package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Minimal BSON: encode command documents, decode replies to Go values.

type bkv struct {
	k string
	v any
}

// encodeDoc encodes an ordered set of key/values into a BSON document.
func encodeDoc(kvs ...bkv) []byte {
	var body []byte
	for _, kv := range kvs {
		body = append(body, encodeElem(kv.k, kv.v)...)
	}
	body = append(body, 0x00) // terminator
	out := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	copy(out[4:], body)
	return out
}

func cstring(s string) []byte { return append([]byte(s), 0x00) }

func encodeElem(key string, v any) []byte {
	switch t := v.(type) {
	case int:
		return encodeInt32(key, int32(t))
	case int32:
		return encodeInt32(key, t)
	case int64:
		b := append([]byte{0x12}, cstring(key)...)
		var n [8]byte
		binary.LittleEndian.PutUint64(n[:], uint64(t))
		return append(b, n[:]...)
	case bool:
		x := byte(0)
		if t {
			x = 1
		}
		return append(append([]byte{0x08}, cstring(key)...), x)
	case string:
		b := append([]byte{0x02}, cstring(key)...)
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(t)+1))
		b = append(b, l[:]...)
		b = append(b, cstring(t)...)
		return b
	case []byte: // raw sub-document
		return append(append([]byte{0x03}, cstring(key)...), t...)
	default:
		// fall back to int32 0
		return encodeInt32(key, 0)
	}
}

func encodeInt32(key string, n int32) []byte {
	b := append([]byte{0x10}, cstring(key)...)
	var x [4]byte
	binary.LittleEndian.PutUint32(x[:], uint32(n))
	return append(b, x[:]...)
}

// --- decode ---

var errShort = errors.New("bson: dados truncados")

// decodeDoc parses a BSON document starting at buf[0].
func decodeDoc(buf []byte) (map[string]any, int, error) {
	if len(buf) < 5 {
		return nil, 0, errShort
	}
	total := int(binary.LittleEndian.Uint32(buf))
	if total < 5 || total > len(buf) {
		return nil, 0, fmt.Errorf("bson: tamanho inválido %d (buf %d)", total, len(buf))
	}
	m := map[string]any{}
	i := 4
	for i < total-1 {
		et := buf[i]
		i++
		key, n, err := readCString(buf[i:])
		if err != nil {
			return nil, 0, err
		}
		i += n
		val, adv, err := decodeValue(et, buf[i:])
		if err != nil {
			return nil, 0, err
		}
		m[key] = val
		i += adv
	}
	return m, total, nil
}

func readCString(b []byte) (string, int, error) {
	for i := 0; i < len(b); i++ {
		if b[i] == 0x00 {
			return string(b[:i]), i + 1, nil
		}
	}
	return "", 0, errShort
}

func decodeValue(et byte, b []byte) (any, int, error) {
	switch et {
	case 0x01: // double
		if len(b) < 8 {
			return nil, 0, errShort
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(b)), 8, nil
	case 0x02, 0x0E: // string / symbol
		if len(b) < 4 {
			return nil, 0, errShort
		}
		l := int(binary.LittleEndian.Uint32(b))
		if l < 1 || 4+l > len(b) {
			return nil, 0, errShort
		}
		return string(b[4 : 4+l-1]), 4 + l, nil
	case 0x03: // document
		sub, n, err := decodeDoc(b)
		return sub, n, err
	case 0x04: // array
		sub, n, err := decodeDoc(b)
		if err != nil {
			return nil, 0, err
		}
		arr := make([]any, 0, len(sub))
		for idx := 0; ; idx++ {
			v, ok := sub[fmt.Sprint(idx)]
			if !ok {
				break
			}
			arr = append(arr, v)
		}
		return arr, n, nil
	case 0x05: // binary
		if len(b) < 5 {
			return nil, 0, errShort
		}
		l := int(binary.LittleEndian.Uint32(b))
		if 5+l > len(b) {
			return nil, 0, errShort
		}
		return fmt.Sprintf("<binary %d bytes>", l), 5 + l, nil
	case 0x07: // ObjectId
		if len(b) < 12 {
			return nil, 0, errShort
		}
		return "ObjectId(" + hexStr(b[:12]) + ")", 12, nil
	case 0x08: // bool
		if len(b) < 1 {
			return nil, 0, errShort
		}
		return b[0] == 1, 1, nil
	case 0x09, 0x11: // datetime / timestamp
		if len(b) < 8 {
			return nil, 0, errShort
		}
		return int64(binary.LittleEndian.Uint64(b)), 8, nil
	case 0x0A, 0x06, 0xFF, 0x7F: // null / undefined / minkey / maxkey
		return nil, 0, nil
	case 0x10: // int32
		if len(b) < 4 {
			return nil, 0, errShort
		}
		return int32(binary.LittleEndian.Uint32(b)), 4, nil
	case 0x12: // int64
		if len(b) < 8 {
			return nil, 0, errShort
		}
		return int64(binary.LittleEndian.Uint64(b)), 8, nil
	case 0x13: // decimal128
		if len(b) < 16 {
			return nil, 0, errShort
		}
		return "<decimal128>", 16, nil
	case 0x0B: // regex: two cstrings
		_, n1, err := readCString(b)
		if err != nil {
			return nil, 0, err
		}
		_, n2, err := readCString(b[n1:])
		if err != nil {
			return nil, 0, err
		}
		return "<regex>", n1 + n2, nil
	default:
		return nil, 0, fmt.Errorf("bson: tipo 0x%02x não suportado", et)
	}
}

const hexdigits = "0123456789abcdef"

func hexStr(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
