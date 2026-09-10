package main

import (
	"net/http"
	"testing"
)

func TestApplyAuth(t *testing.T) {
	t.Setenv("RECONHUB_TARGET", "https://x.com")
	t.Setenv("RECONHUB_AUTH_COOKIE", "session=abc")
	req, _ := http.NewRequest(http.MethodGet, "https://x.com/app.js", nil)
	applyAuth(req)
	if req.Header.Get("Cookie") != "session=abc" {
		t.Errorf("Cookie = %q", req.Header.Get("Cookie"))
	}
}

func TestApplyAuthSkipsAWSHost(t *testing.T) {
	// é exatamente o host que aws.go fala (STS/Cognito) — o cookie do alvo
	// não pode ir junto com a assinatura SigV4.
	t.Setenv("RECONHUB_TARGET", "https://x.com")
	t.Setenv("RECONHUB_AUTH_COOKIE", "session=abc")
	req, _ := http.NewRequest(http.MethodGet, "https://cognito-identity.us-east-1.amazonaws.com/", nil)
	applyAuth(req)
	if req.Header.Get("Cookie") != "" {
		t.Error("não deveria vazar o cookie do alvo pra AWS")
	}
}
