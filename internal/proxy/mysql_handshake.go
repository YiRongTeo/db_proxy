package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	capLongPassword     = 1 << 0
	capConnectWithDB    = 1 << 3 // CLIENT_CONNECT_WITH_DB 0x08 (NOT 0x10 = CLIENT_NO_SCHEMA)
	capProtocol41       = 1 << 9
	capTransactions     = 1 << 13
	capSecureConnection = 1 << 15
	capPluginAuth       = 1 << 19
	capPluginAuthData   = 1 << 21

	cmdQuit    = 0x01
	cmdInitDB  = 0x02
	cmdQuery   = 0x03
	cmdPing    = 0x0e
	cmdPrepare = 0x16
	cmdExecute = 0x17
)

var advertisedCaps = capLongPassword | capProtocol41 | capTransactions |
	capSecureConnection | capPluginAuth | capPluginAuthData

// buildHandshakeV10 builds the server's initial handshake payload.
// authData must be exactly 20 bytes (8-byte part1 + 12-byte part2).
func buildHandshakeV10(serverVersion string, connID uint32, authData []byte) ([]byte, error) {
	if len(authData) != 20 {
		return nil, fmt.Errorf("auth data must be 20 bytes, got %d", len(authData))
	}
	p := make([]byte, 0, 128)
	p = append(p, 0x0a) // protocol version 10
	p = append(p, []byte(serverVersion)...)
	p = append(p, 0x00)
	p = binary.LittleEndian.AppendUint32(p, connID)
	p = append(p, authData[:8]...)
	p = append(p, 0x00) // filler
	p = binary.LittleEndian.AppendUint16(p, uint16(advertisedCaps&0xffff))
	p = append(p, 33)                          // charset utf8_general_ci
	p = binary.LittleEndian.AppendUint16(p, 2) // SERVER_STATUS_AUTOCOMMIT
	p = binary.LittleEndian.AppendUint16(p, uint16(advertisedCaps>>16))
	p = append(p, 21)                  // auth plugin data length
	p = append(p, make([]byte, 10)...) // reserved
	p = append(p, authData[8:]...)     // 12-byte part2
	p = append(p, 0x00)
	p = append(p, []byte("mysql_native_password")...)
	p = append(p, 0x00)
	return p, nil
}

func randomAuthData() ([]byte, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	for i := range b {
		if b[i] == 0 {
			b[i] = 1 // avoid NUL bytes inside the scramble
		}
	}
	return b, nil
}

// parseHandshakeResponse extracts username (= token), database, auth response.
// Returns an error if the client does not speak protocol 4.1.
func parseHandshakeResponse(payload []byte) (username, database string, err error) {
	if len(payload) < 32 {
		return "", "", errors.New("handshake response too short")
	}
	caps := binary.LittleEndian.Uint32(payload[0:4])
	if caps&capProtocol41 == 0 {
		return "", "", errors.New("client does not support protocol 4.1")
	}
	pos := 4 + 4 + 1 + 23 // max-packet(4) + charset(1) + reserved(23)
	end := bytes.IndexByte(payload[pos:], 0)
	if end < 0 {
		return "", "", errors.New("username not null-terminated")
	}
	username = string(payload[pos : pos+end])
	pos += end + 1
	if caps&capSecureConnection != 0 {
		if pos >= len(payload) {
			return "", "", errors.New("missing auth response length")
		}
		authLen := int(payload[pos])
		pos++
		if authLen > 0 {
			if pos+authLen > len(payload) {
				return "", "", errors.New("auth response truncated")
			}
			pos += authLen // password ignored — token is the credential
		}
	} else {
		if end := bytes.IndexByte(payload[pos:], 0); end >= 0 {
			pos += end + 1
		}
	}
	if caps&capConnectWithDB != 0 {
		if end := bytes.IndexByte(payload[pos:], 0); end >= 0 {
			database = string(payload[pos : pos+end])
		}
	}
	return username, database, nil
}

func okPacket() []byte {
	return []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00} // OK, autocommit
}

func errPacket(code uint16, sqlState, msg string) []byte {
	p := []byte{0xff, byte(code), byte(code >> 8), '#'}
	p = append(p, []byte(sqlState)...)
	return append(p, []byte(msg)...)
}
