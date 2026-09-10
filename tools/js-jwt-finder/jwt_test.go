package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mkHS256(claims map[string]any, secret string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pb, _ := json.Marshal(claims)
	p := base64.RawURLEncoding.EncodeToString(pb)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(h + "." + p))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return h + "." + p + "." + sig
}

func mkNone(claims map[string]any) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	pb, _ := json.Marshal(claims)
	return h + "." + base64.RawURLEncoding.EncodeToString(pb) + "."
}

func TestFindJWTs(t *testing.T) {
	tok := mkHS256(map[string]any{"sub": "1"}, "secret")
	text := `var auth = "Bearer ` + tok + `"; // and a non-jwt eyJ.not.valid`
	got := findJWTs(text)
	if len(got) != 1 || got[0] != tok {
		t.Fatalf("findJWTs = %v", got)
	}
}

func TestDecodeJWT(t *testing.T) {
	tok := mkHS256(map[string]any{"role": "admin", "exp": 111}, "x")
	h, p, sig, err := decodeJWT(tok)
	if err != nil {
		t.Fatal(err)
	}
	if h["alg"] != "HS256" || p["role"] != "admin" || len(sig) == 0 {
		t.Errorf("h=%v p=%v sig=%d", h, p, len(sig))
	}
	if _, _, _, err := decodeJWT("a.b"); err == nil {
		t.Error("2 partes deveria falhar")
	}
}

func TestAnalyze(t *testing.T) {
	// alg none
	h, p, _, _ := decodeJWT(mkNone(map[string]any{"sub": "1", "exp": float64(time.Now().Add(time.Hour).Unix())}))
	if !hasKind(analyze(h, p, ""), "jwt-alg-none") {
		t.Error("faltou jwt-alg-none")
	}
	// sem exp + claim sensível
	h2, p2, _, _ := decodeJWT(mkHS256(map[string]any{"email": "a@b.c", "is_admin": true}, "s"))
	is := analyze(h2, p2, "")
	if !hasKind(is, "jwt-no-exp") || !hasKind(is, "jwt-sensitive-claims") || !hasKind(is, "jwt-symmetric") {
		t.Errorf("issues = %+v", is)
	}
	// vida longa
	h3, p3, _, _ := decodeJWT(mkHS256(map[string]any{"exp": float64(time.Now().AddDate(3, 0, 0).Unix())}, "s"))
	if !hasKind(analyze(h3, p3, ""), "jwt-long-lived") {
		t.Error("faltou jwt-long-lived")
	}
	// emissor conhecido
	h4, p4, _, _ := decodeJWT(mkHS256(map[string]any{"iss": "https://xyz.supabase.co/auth/v1", "exp": float64(time.Now().Add(time.Hour).Unix())}, "s"))
	if !hasKind(analyze(h4, p4, ""), "jwt-known-issuer") {
		t.Error("faltou jwt-known-issuer")
	}
}

// TestAnalyzeNestedSensitiveClaims regressão: achado rodando o hub de verdade
// contra o OWASP Juice Shop — o payload real vem como
// {"data":{"password":"<md5>","role":"customer",...},"bid":6,"iat":...}
// (claims sensíveis aninhadas sob "data", não no nível raiz). Antes do fix,
// jwt-sensitive-claims só olhava as chaves de topo e não disparava — um hash
// de senha inteiro passava batido.
func TestAnalyzeNestedSensitiveClaims(t *testing.T) {
	nested := map[string]any{
		"data": map[string]any{
			"id":       25,
			"email":    "testuser@example.com",
			"password": "a226f4f822830025ca5c14731882 36e93",
			"role":     "customer",
		},
		"bid": 6,
	}
	h, p, _, _ := decodeJWT(mkHS256(nested, "s"))
	is := analyze(h, p, "")
	if !hasKind(is, "jwt-sensitive-claims") {
		t.Fatal("faltou jwt-sensitive-claims com claim sensível aninhada sob \"data\"")
	}
	var detail string
	for _, i := range is {
		if i.kind == "jwt-sensitive-claims" {
			detail = i.detail
		}
	}
	if !strings.Contains(detail, "data.password") || !strings.Contains(detail, "data.email") {
		t.Errorf("detail deveria citar o caminho aninhado (data.password, data.email): %q", detail)
	}
}

func TestCrackHS(t *testing.T) {
	tok := mkHS256(map[string]any{"sub": "1"}, "supersecret")
	got, ok := crackHS(tok, mergeSecrets(nil))
	if !ok || got != "supersecret" {
		t.Fatalf("crackHS = %q %v", got, ok)
	}
	// segredo forte -> não quebra
	strong := mkHS256(map[string]any{"sub": "1"}, "9f8c2b1e-not-in-any-list-4a7d")
	if _, ok := crackHS(strong, mergeSecrets(nil)); ok {
		t.Error("não deveria quebrar segredo forte")
	}
	// wordlist extra
	tok2 := mkHS256(map[string]any{"sub": "1"}, "correcthorsebatterystaple")
	if _, ok := crackHS(tok2, mergeSecrets([]string{"nope", "correcthorsebatterystaple"})); !ok {
		t.Error("deveria quebrar via wordlist extra")
	}
}

func TestRedactJWT(t *testing.T) {
	tok := mkHS256(map[string]any{"sub": "1"}, "s")
	r := redactJWT(tok)
	if strings.Contains(r, tok) || !strings.Contains(r, "<payload>") {
		t.Errorf("redact = %q", r)
	}
}

func hasKind(is []issue, k string) bool {
	for _, i := range is {
		if i.kind == k {
			return true
		}
	}
	return false
}
