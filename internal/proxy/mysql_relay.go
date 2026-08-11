package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"zerotrust-proxy/internal/models"
)

// pipeClientToBackend: read client packets, sniff SQL, relay byte-exact.
// br must be the same buffered reader used during protocol detection.
func (p *MySQLProxy) pipeClientToBackend(br *bufio.Reader, backend net.Conn, tok *models.TokenPayload, clientAddr string) {
	for {
		seq, payload, err := readMySQLPacket(br)
		if err != nil {
			return
		}
		if len(payload) > 0 {
			p.sniffCommand(payload[0], payload[1:], tok, clientAddr)
		}
		if err := writeMySQLPacket(backend, seq, payload); err != nil {
			return
		}
	}
}

// pipeBackendToClient: relay backend packets byte-exact (original seq preserved).
func (p *MySQLProxy) pipeBackendToClient(backend, client net.Conn) {
	for {
		seq, payload, err := readMySQLPacket(backend)
		if err != nil {
			return
		}
		if err := writeMySQLPacket(client, seq, payload); err != nil {
			return
		}
	}
}

// trimSniffedSQL strips the NUL terminator that real clients append to
// COM_QUERY/COM_INIT_DB/COM_STMT_PREPARE payloads (plus any whitespace after
// it) from the SNIFFED copy only. The relayed payload bytes are never touched
// — the relay is byte-exact; this affects solely the published event text.
func trimSniffedSQL(body []byte) string {
	s := string(body)
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return strings.TrimRight(s, " 	\r\n")
}

// sniffCommand extracts SQL text from command payloads and publishes a
// QueryEvent to queries:<username> and queries:ticket:<ticket>. Publishing is
// best-effort: failures are logged by the caller of Publish, never fatal.
func (p *MySQLProxy) sniffCommand(cmd byte, body []byte, tok *models.TokenPayload, clientAddr string) {
	var kind, sql string
	switch cmd {
	case cmdQuery:
		kind, sql = "query", trimSniffedSQL(body)
	case cmdInitDB:
		kind, sql = "use", "USE "+trimSniffedSQL(body)
	case cmdPrepare:
		kind, sql = "prepare", trimSniffedSQL(body)
	case cmdExecute:
		kind = "execute"
		if len(body) >= 4 {
			sql = fmt.Sprintf("EXECUTE stmt_id=%d", binary.LittleEndian.Uint32(body))
		} else {
			sql = "EXECUTE stmt_id=?"
		}
	default:
		return
	}
	ev := models.QueryEvent{
		ID:         newEventID(),
		Ts:         time.Now().UTC(),
		Kind:       kind,
		Username:   tok.Username,
		TicketID:   tok.TicketID,
		DBUser:     tok.DBUser,
		DBIP:       tok.DBIP,
		DBPort:     tok.DBPort,
		DBType:     "mysql",
		SQL:        sql,
		ClientAddr: clientAddr,
	}
	raw, _ := json.Marshal(ev)
	ctx := context.Background()
	_ = p.vs.Publish(ctx, "queries:"+tok.Username, raw)
	if tok.TicketID != "" {
		_ = p.vs.Publish(ctx, "queries:ticket:"+tok.TicketID, raw)
	}
}
