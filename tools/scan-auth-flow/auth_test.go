package main

import (
	"net/http"
	"testing"
)

func TestApplyAuth(t *testing.T) {
	t.Setenv("RECONHUB_TARGET", "https://idp.test")
	t.Setenv("RECONHUB_AUTH_COOKIE", "session=abc")
	req, _ := http.NewRequest(http.MethodGet, "https://idp.test/oauth2/authorize", nil)
	applyAuth(req)
	if req.Header.Get("Cookie") != "session=abc" {
		t.Errorf("Cookie = %q", req.Header.Get("Cookie"))
	}
}

func TestApplyAuthSkipsOtherHost(t *testing.T) {
	t.Setenv("RECONHUB_TARGET", "https://idp.test")
	t.Setenv("RECONHUB_AUTH_COOKIE", "session=abc")
	req, _ := http.NewRequest(http.MethodGet, "https://attacker.example/callback", nil)
	applyAuth(req)
	if req.Header.Get("Cookie") != "" {
		t.Error("não deveria vazar o cookie do alvo pro host injetado no redirect_uri")
	}
}
