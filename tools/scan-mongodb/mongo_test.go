package main

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// fakeMongo answers one OP_MSG request with `reply` (a BSON doc) then closes.
func fakeMongo(t *testing.T, reply []byte) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		hdr := make([]byte, 16)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		total := int(binary.LittleEndian.Uint32(hdr))
		rest := make([]byte, total-16)
		io.ReadFull(conn, rest)

		body := []byte{0, 0, 0, 0, 0x00} // flagBits + section kind 0
		body = append(body, reply...)
		out := make([]byte, 16+len(body))
		binary.LittleEndian.PutUint32(out[0:], uint32(len(out)))
		binary.LittleEndian.PutUint32(out[4:], 1)
		binary.LittleEndian.PutUint32(out[8:], binary.LittleEndian.Uint32(hdr[4:])) // responseTo
		binary.LittleEndian.PutUint32(out[12:], 2013)
		copy(out[16:], body)
		conn.Write(out)
	}()
	return ln
}

func TestRunCommandRoundTrip(t *testing.T) {
	reply := encodeDoc(
		bkv{"ok", int64(1)},
		bkv{"ismaster", true},
		bkv{"version", "7.0.5"},
	)
	ln := fakeMongo(t, reply)
	defer ln.Close()

	conn, err := dialMongo(ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.close()

	got, err := conn.hello()
	if err != nil {
		t.Fatal(err)
	}
	if !cmdOK(got) || got["version"] != "7.0.5" || got["ismaster"] != true {
		t.Fatalf("reply = %#v", got)
	}
}

func TestRunCommandAuthError(t *testing.T) {
	reply := encodeDoc(
		bkv{"ok", int64(0)},
		bkv{"errmsg", "command listDatabases requires authentication"},
		bkv{"code", 13},
		bkv{"codeName", "Unauthorized"},
	)
	ln := fakeMongo(t, reply)
	defer ln.Close()

	conn, _ := dialMongo(ln.Addr().String(), 2*time.Second)
	defer conn.close()

	got, err := conn.listDatabases()
	if err != nil {
		t.Fatal(err)
	}
	if cmdOK(got) || !isAuthError(got) {
		t.Fatalf("esperava auth error, got %#v", got)
	}
}

func TestCleanHost(t *testing.T) {
	cases := map[string]string{
		"mongodb://db.example.com:27017/app": "db.example.com",
		"HTTP://10.0.0.5":                    "10.0.0.5",
		"host.local:27018":                   "host.local",
		"  db.example.com.  ":                "db.example.com",
	}
	for in, want := range cases {
		if got := cleanHost(in); got != want {
			t.Errorf("cleanHost(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestParsePorts(t *testing.T) {
	if got := parsePorts("27017, 27018 27019"); len(got) != 3 || got[0] != 27017 || got[2] != 27019 {
		t.Errorf("parsePorts = %v", got)
	}
	if got := parsePorts("nope,-1,99999"); len(got) != 0 {
		t.Errorf("parsePorts inválidas = %v", got)
	}
}
