// oracle_auth.go — Task 9.14 Oracle backend auth.
//
// PORTED from github.com/sijms/go-ora/v2 (auth_object.go), Apache-2.0:
//
//	Copyright (c) 2015 Sijms
//
// Adapted: *network.Session -> the proxy's oracleBackendSession framing,
// TCPNego -> oracleTcpNego, OracleError -> plain errors, logging dropped.
// The verification/crypto logic is unchanged. (The ported streaming
// oracleAuthIO reader/writer was removed 2026-09-02: the OCI leg parses
// whole packets via parseOCIChallenge/buildOCIAuth and the JDBC leg uses
// vendored go-ora itself.)
package proxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/sijms/go-ora/v2/network/security"
)

// E infront of the variable means encrypted. Only the fields the live
// OCI leg touches survive: parseOCIChallenge fills the challenge-derived
// fields; computeAuthKeys fills the derived keys. (KeyHash, customHash,
// globalUniqueDBID and usePadding were dropped with the ported streaming
// reader 2026-09-02 — nothing in the byte-parsing path sets them, and the
// OCI verifier always runs unpadded.)
type oracleAuthObject struct {
	EServerSessKey  string
	EClientSessKey  string
	EPassword       string
	ESpeedyKey      string
	ServerSessKey   []byte
	ClientSessKey   []byte
	Salt            string
	pbkdf2ChkSalt   string
	pbkdf2VgenCount int
	pbkdf2SderCount int
	VerifierType    int
	tcpNego         *oracleTcpNego
}

// computeAuthKeys is the verifier-dependent key computation (extracted from
// go-ora's newAuthObject so the OCI challenge path can reuse it).
func (ret *oracleAuthObject) computeAuthKeys(username, password string) error {
	var err error
	var key []byte
	var speedyKey []byte
	padding := false
	if ret.VerifierType == 2361 {
		key, err = getKeyFromUserNameAndPassword(username, password)
		if err != nil {
			return err
		}
	} else if ret.VerifierType == 6949 {

		if ret.tcpNego.ServerCompileTimeCaps[4]&2 == 0 {
			padding = true
		}
		result, err := hex.DecodeString(ret.Salt)
		if err != nil {
			return err
		}
		result = append([]byte(password), result...)
		hash := sha1.New()
		_, err = hash.Write(result)
		if err != nil {
			return err
		}
		key = hash.Sum(nil)           // 20 byte key
		key = append(key, 0, 0, 0, 0) // 24 byte key
	} else if ret.VerifierType == 18453 {
		salt, err := hex.DecodeString(ret.Salt)
		if err != nil {
			return err
		}
		message := append(salt, []byte("AUTH_PBKDF2_SPEEDY_KEY")...)
		speedyKey = generateSpeedyKey(message, []byte(password), ret.pbkdf2VgenCount)

		buffer := append(speedyKey, salt...)
		hash := sha512.New()
		hash.Write(buffer)
		key = hash.Sum(nil)[:32]
	} else {
		return errors.New("unsupported verifier type")
	}
	// get the server session key
	ret.ServerSessKey, err = decryptSessionKey(padding, key, ret.EServerSessKey)
	if err != nil {
		return err
	}

	// note if serverSessKey length is less than the expected length according to verifier generate random one
	// generate new key for client
	ret.ClientSessKey = make([]byte, len(ret.ServerSessKey))
	for {
		_, err = rand.Read(ret.ClientSessKey)
		if err != nil {
			return err
		}
		if !bytes.Equal(ret.ClientSessKey, ret.ServerSessKey) {
			break
		}
	}

	// encrypt the client key
	ret.EClientSessKey, err = encryptSessionKey(padding, key, ret.ClientSessKey)
	if err != nil {
		return err
	}

	// get the hash key form server and client session key
	newKey, err := ret.generatePasswordEncKey()
	if err != nil {
		return err
	}
	if ret.VerifierType == 18453 {
		padding = false
	} else {
		padding = true
	}
	// encrypt the password
	ret.EPassword, err = encryptPassword([]byte(password), newKey, true)
	if err != nil {
		return err
	}
	if ret.VerifierType == 18453 {
		ret.ESpeedyKey, err = encryptPassword(speedyKey, newKey, padding)
		if err != nil {
			return err
		}
	}
	return nil
}

func generateSpeedyKey(buffer, key []byte, turns int) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(append(buffer, 0, 0, 0, 1))
	firstHash := mac.Sum(nil)
	tempHash := make([]byte, len(firstHash))
	copy(tempHash, firstHash)
	for index1 := 2; index1 <= turns; index1++ {
		// mac = hmac.New(sha512.New, []byte("ter1234"))
		mac.Reset()
		mac.Write(tempHash)
		tempHash = mac.Sum(nil)
		for index2 := 0; index2 < 64; index2++ {
			firstHash[index2] = firstHash[index2] ^ tempHash[index2]
		}
	}
	return firstHash
}

func getKeyFromUserNameAndPassword(username string, password string) ([]byte, error) {
	username = strings.ToUpper(username)
	password = strings.ToUpper(password)
	extendString := func(str string) []byte {
		ret := make([]byte, len(str)*2)
		for index, char := range []byte(str) {
			ret[index*2] = 0
			ret[index*2+1] = char
		}
		return ret
	}
	buffer := append(extendString(username), extendString(password)...)
	if len(buffer)%8 > 0 {
		buffer = append(buffer, make([]byte, 8-len(buffer)%8)...)
	}
	key := []byte{1, 35, 69, 103, 137, 171, 205, 239}

	DesEnc := func(input []byte, key []byte) ([]byte, error) {
		ret := make([]byte, 8)
		enc, err := des.NewCipher(key)
		if err != nil {
			return nil, err
		}
		for x := 0; x < len(input)/8; x++ {
			for y := 0; y < 8; y++ {
				ret[y] = uint8(int(ret[y]) ^ int(input[x*8+y]))
			}
			output := make([]byte, 8)
			enc.Encrypt(output, ret)
			copy(ret, output)
		}
		return ret, nil
	}
	key1, err := DesEnc(buffer, key)
	if err != nil {
		return nil, err
	}
	key2, err := DesEnc(buffer, key1)
	if err != nil {
		return nil, err
	}
	// function OSLogonHelper.Method1_bytearray (DecryptSessionKey)
	return append(key2, make([]byte, 8)...), nil
}

// decrypt session key that come from the server
func decryptSessionKey(padding bool, encKey []byte, sessionKey string) ([]byte, error) {
	result, err := hex.DecodeString(sessionKey)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	//if padding {
	//	result = PKCS5Padding(result, blk.BlockSize())
	//}
	enc := cipher.NewCBCDecrypter(blk, make([]byte, 16))
	output := make([]byte, len(result))
	enc.CryptBlocks(output, result)
	cutLen := 0
	if padding {
		num := int(output[len(output)-1])
		if num < enc.BlockSize() {
			apply := true
			for x := len(output) - num; x < len(output); x++ {
				if output[x] != uint8(num) {
					apply = false
					break
				}
			}
			if apply {
				cutLen = int(output[len(output)-1])
			}
		}
	}
	return output[:len(output)-cutLen], nil
}

// encrypt session key that generated from the client
func encryptSessionKey(padding bool, encKey []byte, sessionKey []byte) (string, error) {
	blk, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	enc := cipher.NewCBCEncrypter(blk, make([]byte, 16))
	originalLen := len(sessionKey)
	sessionKey = security.PKCS5Padding(sessionKey, blk.BlockSize())
	//if padding {
	//
	//}
	output := make([]byte, len(sessionKey))
	enc.CryptBlocks(output, sessionKey)
	if !padding {
		return fmt.Sprintf("%X", output[:originalLen]), nil
	}
	return fmt.Sprintf("%X", output), nil

	// cryptoServiceProvider.Mode = CipherMode.CBC;
	// cryptoServiceProvider.KeySize = key.Length * 8;
	// cryptoServiceProvider.BlockSize = O5LogonHelper.d;
	// cryptoServiceProvider.Key = key;
	// cryptoServiceProvider.IV = O5LogonHelper.f;
	// numArray = cryptoServiceProvider.CreateEncryptor().TransformFinalBlock(buffer, 0, buffer.Length);
}

// encrypt user password
func encryptPassword(password, key []byte, padding bool) (string, error) {
	buff1 := make([]byte, 0x10)
	_, err := rand.Read(buff1)
	if err != nil {
		return "", nil
	}
	buffer := append(buff1, password...)
	return encryptSessionKey(padding, key, buffer)
}

// generate encryption key for the password this depends on database verifier type
func (obj *oracleAuthObject) generatePasswordEncKey() ([]byte, error) {
	hash := md5.New()
	key1 := obj.ServerSessKey
	key2 := obj.ClientSessKey
	start := 16

	logonCompatibility := obj.tcpNego.ServerCompileTimeCaps[4]
	if logonCompatibility&32 != 0 {
		var keyBuffer string
		var retKeyLen int
		switch obj.VerifierType {
		case 2361:
			buffer := append(key2[:len(key2)/2], key1[:len(key1)/2]...)
			keyBuffer = fmt.Sprintf("%X", buffer)
			retKeyLen = 16
		case 6949:
			buffer := append(key2[:24], key1[:24]...)
			keyBuffer = fmt.Sprintf("%X", buffer)
			retKeyLen = 24
		case 18453:
			buffer := append(key2, key1...)
			keyBuffer = fmt.Sprintf("%X", buffer)
			retKeyLen = 32
		default:
			return nil, errors.New("unsupported verifier type")
		}
		df2key, err := hex.DecodeString(obj.pbkdf2ChkSalt)
		if err != nil {
			return nil, err
		}
		return generateSpeedyKey(df2key, []byte(keyBuffer), obj.pbkdf2SderCount)[:retKeyLen], nil
	} else {
		switch obj.VerifierType {
		case 2361:
			buffer := make([]byte, 16)
			for x := 0; x < 16; x++ {
				buffer[x] = key1[x+start] ^ key2[x+start]
			}
			_, err := hash.Write(buffer)
			if err != nil {
				return nil, err
			}
			return hash.Sum(nil), nil
		case 6949:
			buffer := make([]byte, 24)
			for x := 0; x < 24; x++ {
				buffer[x] = key1[x+start] ^ key2[x+start]
			}
			_, err := hash.Write(buffer[:16])
			if err != nil {
				return nil, err
			}
			ret := hash.Sum(nil)
			hash.Reset()
			_, err = hash.Write(buffer[16:])
			if err != nil {
				return nil, err
			}
			ret = append(ret, hash.Sum(nil)...)
			return ret[:24], nil
		default:
			return nil, errors.New("unsupported verifier type")
		}
	}
}

// oracleTcpNego carries the two negotiated fields the auth code reads.
type oracleTcpNego struct {
	ServerCharset         uint16
	ServerCompileTimeCaps [8]byte
}
