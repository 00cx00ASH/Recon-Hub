package main

import (
	"net/http"
	"testing"
)

func TestApplyAuth(t *testing.T) {
	t.Setenv("RECONHUB_TARGET", "https://x.com")
	t.Setenv("RECONHUB_AUTH_COOKIE", "session=abc")
	req, _ := http.NewRequest(http.MethodGet, "https://x.com/perfil?name=42", nil)
	applyAuth(req)
	if req.Header.Get("Cookie") != "session=abc" {
		t.Errorf("Cookie = %q", req.Header.Get("Cookie"))
	}
}

func TestApplyAuthSkipsThirdPartyHost(t *testing.T) {
	t.Setenv("RECONHUB_TARGET", "https://x.com")
	t.Setenv("RECONHUB_AUTH_COOKIE", "session=abc")
	req, _ := http.NewRequest(http.MethodGet, "https://evil.com", nil)
	applyAuth(req)
	if req.Header.Get("Cookie") != "" {
		t.Error("não deveria vazar o cookie do alvo pra outro host")
	}
}
