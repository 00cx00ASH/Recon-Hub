package main

import (
	"math"
	"strings"
)

// hit is one secret found in a body.
type hit struct {
	Pattern  string
	Severity string
	Value    string
}

// scan runs every pattern over body and returns deduped hits.
func scan(body string, min int) []hit {
	seen := map[string]bool{}
	var out []hit
	for _, p := range patterns {
		for _, m := range p.Re.FindAllStringSubmatch(body, -1) {
			val := m[0]
			if p.Group > 0 && p.Group < len(m) {
				val = m[p.Group]
			}
			val = strings.TrimSpace(val)
			if len(val) < min {
				continue
			}
			if p.Entropy > 0 && shannon(val) < p.Entropy {
				continue
			}
			if looksPlaceholder(val) {
				continue
			}
			key := p.Name + "\x00" + val
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, hit{Pattern: p.Name, Severity: p.Severity, Value: val})
		}
	}
	return out
}

// redact keeps the ends visible so the operator can recognise/grep the value
// without the whole secret ending up in every log line.
func redact(s string) string {
	if len(s) <= 12 {
		return s
	}
	if len(s) <= 40 {
		return s[:6] + "…" + s[len(s)-4:]
	}
	return s[:8] + "…(" + itoa(len(s)) + " chars)…" + s[len(s)-6:]
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

var placeholders = []string{
	"example", "changeme", "your_", "yourapi", "placeholder", "xxxxxxxx", "0000000000",
	"1234567890", "abcdefgh", "test_key", "dummy", "sample", "redacted", "insertkey",
	"<your", "process.env", "${", "{{", "notreal",
}

func looksPlaceholder(v string) bool {
	l := strings.ToLower(v)
	for _, p := range placeholders {
		if strings.Contains(l, p) {
			return true
		}
	}
	// all one repeated char
	if len(v) > 8 {
		allSame := true
		for i := 1; i < len(v); i++ {
			if v[i] != v[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
