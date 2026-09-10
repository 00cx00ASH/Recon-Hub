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

func TestApplyAuthSkipsProviderHost(t *testing.T) {
	// é exatamente o tipo de host que validate.go fala (API do provedor de
	// IA) — o cookie do alvo não pode ir junto.
	t.Setenv("RECONHUB_TARGET", "https://x.com")
	t.Setenv("RECONHUB_AUTH_COOKIE", "session=abc")
	req, _ := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/models", nil)
	applyAuth(req)
	if req.Header.Get("Cookie") != "" {
		t.Error("não deveria vazar o cookie do alvo pro provedor")
	}
}
