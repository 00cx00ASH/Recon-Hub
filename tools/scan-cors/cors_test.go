package main

import (
	"net/http"
	"strings"
	"testing"
)

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func TestRegDomain(t *testing.T) {
	cases := map[string]string{
		"api.example.com":   "example.com",
		"example.com":       "example.com",
		"a.b.example.co.uk": "example.co.uk",
		"localhost":         "localhost",
	}
	for in, want := range cases {
		if got := regDomain(in); got != want {
			t.Errorf("regDomain(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestTestOrigins(t *testing.T) {
	os := testOrigins("api.example.com")
	if len(os) < 8 {
		t.Fatalf("poucas origens: %d", len(os))
	}
	joined := ""
	for _, o := range os {
		joined += o.value + " "
	}
	for _, want := range []string{"null", "https://api.example.com.evil.example", "http://api.example.com", "https://attacker.example.com"} {
		if !strings.Contains(joined, want) {
			t.Errorf("faltou origem %q em %q", want, joined)
		}
	}
}

func TestAnalyze(t *testing.T) {
	host := "api.example.com"
	evil := "https://evil.example"

	// reflexão + credenciais => critical
	if v := analyze(evil, hdr("Access-Control-Allow-Origin", evil, "Access-Control-Allow-Credentials", "true"), host); v.kind != "cors-reflect-credentials" || v.severity != "critical" {
		t.Errorf("reflect+creds → %+v", v)
	}
	// reflexão sem credenciais => medium
	if v := analyze(evil, hdr("Access-Control-Allow-Origin", evil), host); v.kind != "cors-reflect-origin" || v.severity != "medium" {
		t.Errorf("reflect → %+v", v)
	}
	// null + creds => high
	if v := analyze("null", hdr("Access-Control-Allow-Origin", "null", "Access-Control-Allow-Credentials", "true"), host); v.kind != "cors-null-origin" || v.severity != "high" {
		t.Errorf("null+creds → %+v", v)
	}
	// wildcard + creds => high
	if v := analyze(evil, hdr("Access-Control-Allow-Origin", "*", "Access-Control-Allow-Credentials", "true"), host); v.kind != "cors-wildcard-credentials" {
		t.Errorf("*+creds → %+v", v)
	}
	// ACAO fixo do próprio site => nada
	if v := analyze(evil, hdr("Access-Control-Allow-Origin", "https://api.example.com", "Access-Control-Allow-Credentials", "true"), host); v.kind != "" {
		t.Errorf("origem própria não é finding: %+v", v)
	}
	// sem ACAO => nada
	if v := analyze(evil, hdr("Content-Type", "application/json"), host); v.kind != "" {
		t.Errorf("sem ACAO → %+v", v)
	}
}

func TestBaselineWildcard(t *testing.T) {
	if v := baselineWildcard(hdr("Access-Control-Allow-Origin", "*")); v.kind != "cors-wildcard" || v.severity != "low" {
		t.Errorf("* → %+v", v)
	}
	if v := baselineWildcard(hdr("Access-Control-Allow-Origin", "*", "Access-Control-Allow-Credentials", "true")); v.severity != "high" {
		t.Errorf("*+creds baseline → %+v", v)
	}
	if v := baselineWildcard(hdr("Content-Type", "x")); v.kind != "" {
		t.Errorf("sem ACAO → %+v", v)
	}
}
