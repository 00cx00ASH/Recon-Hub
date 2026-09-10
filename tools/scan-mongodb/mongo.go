package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

var reqID int32

// mongoConn is a live TCP connection to a mongod/mongos.
type mongoConn struct {
	c   net.Conn
	tmo time.Duration
}

func dialMongo(addr string, timeout time.Duration) (*mongoConn, error) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	return &mongoConn{c: c, tmo: timeout}, nil
}

func (m *mongoConn) close() { m.c.Close() }

// runCommand sends `cmd` (with $db) as an OP_MSG and returns the reply document.
func (m *mongoConn) runCommand(cmd []byte) (map[string]any, error) {
	// cmd is a full BSON doc; append $db by re-wrapping is messy — instead we
	// build the doc here with $db included by the caller. So `cmd` already has $db.
	body := make([]byte, 0, len(cmd)+5)
	body = append(body, 0, 0, 0, 0) // flagBits = 0
	body = append(body, 0x00)       // section kind 0
	body = append(body, cmd...)

	id := atomic.AddInt32(&reqID, 1)
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:], uint32(16+len(body)))
	binary.LittleEndian.PutUint32(hdr[4:], uint32(id))
	binary.LittleEndian.PutUint32(hdr[8:], 0)
	binary.LittleEndian.PutUint32(hdr[12:], 2013) // OP_MSG

	m.c.SetDeadline(time.Now().Add(m.tmo))
	if _, err := m.c.Write(append(hdr, body...)); err != nil {
		return nil, err
	}

	rh := make([]byte, 16)
	if _, err := io.ReadFull(m.c, rh); err != nil {
		return nil, err
	}
	total := int(binary.LittleEndian.Uint32(rh))
	opCode := int(binary.LittleEndian.Uint32(rh[12:]))
	if total < 16 || total > 48<<20 {
		return nil, fmt.Errorf("resposta com tamanho suspeito: %d", total)
	}
	rest := make([]byte, total-16)
	if _, err := io.ReadFull(m.c, rest); err != nil {
		return nil, err
	}
	if opCode != 2013 {
		return nil, fmt.Errorf("opcode inesperado na resposta: %d", opCode)
	}
	// rest = flagBits(4) + sections
	if len(rest) < 5 {
		return nil, fmt.Errorf("corpo OP_MSG curto")
	}
	p := 4
	for p < len(rest) {
		kind := rest[p]
		p++
		if kind == 0 {
			doc, _, err := decodeDoc(rest[p:])
			if err != nil {
				return nil, err
			}
			return doc, nil
		}
		// kind 1: document sequence — skip
		if p+4 > len(rest) {
			break
		}
		size := int(binary.LittleEndian.Uint32(rest[p:]))
		p += size
	}
	return nil, fmt.Errorf("nenhuma seção kind-0 na resposta")
}

// cmd builds a command BSON doc with $db appended.
func cmd(db string, first bkv, rest ...bkv) []byte {
	all := append([]bkv{first}, rest...)
	all = append(all, bkv{"$db", db})
	return encodeDoc(all...)
}

// hello runs the handshake command; works pre-auth.
func (m *mongoConn) hello() (map[string]any, error) {
	return m.runCommand(cmd("admin", bkv{"hello", 1}))
}

// listDatabases requires auth unless the server is open.
func (m *mongoConn) listDatabases() (map[string]any, error) {
	return m.runCommand(cmd("admin", bkv{"listDatabases", 1}, bkv{"nameOnly", true}))
}

func (m *mongoConn) listCollections(db string) (map[string]any, error) {
	return m.runCommand(cmd(db, bkv{"listCollections", 1}, bkv{"nameOnly", true}))
}

func (m *mongoConn) findOne(db, coll string) (map[string]any, error) {
	return m.runCommand(cmd(db, bkv{"find", coll}, bkv{"limit", 1}, bkv{"batchSize", 1}))
}

// --- reply helpers ---

func cmdOK(reply map[string]any) bool {
	switch v := reply["ok"].(type) {
	case float64:
		return v == 1
	case int32:
		return v == 1
	case int64:
		return v == 1
	}
	return false
}

func errText(reply map[string]any) string {
	if s, ok := reply["errmsg"].(string); ok {
		return s
	}
	if s, ok := reply["$err"].(string); ok {
		return s
	}
	return ""
}

func isAuthError(reply map[string]any) bool {
	t := strings.ToLower(errText(reply))
	code, _ := reply["code"].(int32)
	return code == 13 || code == 18 || strings.Contains(t, "requires authentication") ||
		strings.Contains(t, "not authorized") || strings.Contains(t, "unauthorized") ||
		strings.Contains(t, "authentication failed")
}

// dbNames pulls database names from a listDatabases reply.
func dbNames(reply map[string]any) []string {
	arr, _ := reply["databases"].([]any)
	var out []string
	for _, e := range arr {
		if d, ok := e.(map[string]any); ok {
			if n, ok := d["name"].(string); ok {
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

// collNames pulls collection names from a listCollections reply cursor.
func collNames(reply map[string]any) []string {
	cur, _ := reply["cursor"].(map[string]any)
	if cur == nil {
		return nil
	}
	batch, _ := cur["firstBatch"].([]any)
	var out []string
	for _, e := range batch {
		if d, ok := e.(map[string]any); ok {
			if n, ok := d["name"].(string); ok {
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

// firstDocKeys returns the field names of the first doc in a find reply.
func firstDocKeys(reply map[string]any) []string {
	cur, _ := reply["cursor"].(map[string]any)
	if cur == nil {
		return nil
	}
	batch, _ := cur["firstBatch"].([]any)
	if len(batch) == 0 {
		return nil
	}
	d, _ := batch[0].(map[string]any)
	var out []string
	for k := range d {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func systemDB(name string) bool {
	return name == "admin" || name == "config" || name == "local"
}
