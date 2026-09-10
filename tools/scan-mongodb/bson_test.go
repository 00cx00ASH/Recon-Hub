package main

import (
	"encoding/binary"
	"math"
	"reflect"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	doc := encodeDoc(
		bkv{"listDatabases", 1},
		bkv{"nameOnly", true},
		bkv{"$db", "admin"},
		bkv{"big", int64(9000000000)},
		bkv{"name", "hello world"},
	)
	m, n, err := decodeDoc(doc)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(doc) {
		t.Errorf("consumiu %d de %d", n, len(doc))
	}
	if m["listDatabases"].(int32) != 1 || m["nameOnly"] != true ||
		m["$db"] != "admin" || m["big"].(int64) != 9000000000 || m["name"] != "hello world" {
		t.Fatalf("round-trip = %#v", m)
	}
}

func TestDecodeNestedAndTypes(t *testing.T) {
	// build: { ok: 1.0, databases: [ {name:"admin"}, {name:"app"} ], flag: false }
	inner1 := encodeDoc(bkv{"name", "admin"})
	inner2 := encodeDoc(bkv{"name", "app"})
	arrBody := append(append([]byte{0x03}, cstr("0")...), inner1...)
	arrBody = append(arrBody, 0x03)
	arrBody = append(arrBody, cstr("1")...)
	arrBody = append(arrBody, inner2...)
	arrBody = append(arrBody, 0x00)
	arr := make([]byte, 4+len(arrBody))
	binary.LittleEndian.PutUint32(arr, uint32(len(arr)))
	copy(arr[4:], arrBody)

	var body []byte
	// double ok=1.0
	body = append(body, 0x01)
	body = append(body, cstr("ok")...)
	var f [8]byte
	binary.LittleEndian.PutUint64(f[:], math.Float64bits(1.0))
	body = append(body, f[:]...)
	// array
	body = append(body, 0x04)
	body = append(body, cstr("databases")...)
	body = append(body, arr...)
	// bool
	body = append(body, 0x08)
	body = append(body, cstr("flag")...)
	body = append(body, 0x00)
	body = append(body, 0x00)

	full := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(full, uint32(len(full)))
	copy(full[4:], body)

	m, _, err := decodeDoc(full)
	if err != nil {
		t.Fatal(err)
	}
	if m["ok"].(float64) != 1.0 || m["flag"] != false {
		t.Fatalf("m = %#v", m)
	}
	dbs, ok := m["databases"].([]any)
	if !ok || len(dbs) != 2 {
		t.Fatalf("databases = %#v", m["databases"])
	}
	if dbs[0].(map[string]any)["name"] != "admin" || dbs[1].(map[string]any)["name"] != "app" {
		t.Fatalf("array elems = %#v", dbs)
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, _, err := decodeDoc([]byte{0x05, 0x00}); err == nil {
		t.Error("buffer curto deveria falhar")
	}
	good := encodeDoc(bkv{"a", 1})
	if _, _, err := decodeDoc(good[:len(good)-2]); err == nil {
		t.Error("doc cortado deveria falhar")
	}
}

func TestReplyHelpers(t *testing.T) {
	ok := map[string]any{"ok": float64(1)}
	if !cmdOK(ok) {
		t.Error("ok:1.0 deveria ser cmdOK")
	}
	if cmdOK(map[string]any{"ok": float64(0)}) {
		t.Error("ok:0 não")
	}
	authErr := map[string]any{"ok": float64(0), "code": int32(13), "errmsg": "command listDatabases requires authentication"}
	if !isAuthError(authErr) {
		t.Error("code 13 deveria ser auth error")
	}
	if isAuthError(map[string]any{"ok": float64(0), "errmsg": "some other failure"}) {
		t.Error("erro genérico não é auth error")
	}

	ldb := map[string]any{"databases": []any{
		map[string]any{"name": "admin"}, map[string]any{"name": "shop"}, map[string]any{"name": "config"},
	}}
	got := dbNames(ldb)
	if !reflect.DeepEqual(got, []string{"admin", "config", "shop"}) {
		t.Errorf("dbNames = %v", got)
	}

	lc := map[string]any{"cursor": map[string]any{"firstBatch": []any{
		map[string]any{"name": "users"}, map[string]any{"name": "orders"},
	}}}
	if !reflect.DeepEqual(collNames(lc), []string{"orders", "users"}) {
		t.Errorf("collNames = %v", collNames(lc))
	}

	fd := map[string]any{"cursor": map[string]any{"firstBatch": []any{
		map[string]any{"_id": "x", "email": "a", "password_hash": "b"},
	}}}
	if !reflect.DeepEqual(firstDocKeys(fd), []string{"_id", "email", "password_hash"}) {
		t.Errorf("firstDocKeys = %v", firstDocKeys(fd))
	}
}

func cstr(s string) []byte { return append([]byte(s), 0x00) }
