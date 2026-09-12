package main

import (
	"strings"
	"testing"
)

func TestTokenFlowsThroughPayloadAndEval(t *testing.T) {
	tok := randToken()
	p := storedPayload(tok)
	if !strings.Contains(p, "window.__rhxss_"+tok) {
		t.Fatalf("payload deveria setar a propriedade do token: %s", p)
	}
	if !strings.Contains(p, "<img src=x onerror=") {
		t.Fatalf("payload deveria usar o onerror da <img> (dispara sem interação): %s", p)
	}
	if eval := evalExpr(tok); eval != "!!window.__rhxss_"+tok {
		t.Fatalf("evalExpr tem que checar exatamente a propriedade que o payload seta: %s", eval)
	}
}

func TestRandTokenUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		tok := randToken()
		if seen[tok] {
			t.Fatal("token repetido — quebraria a garantia anti-falso-positivo")
		}
		seen[tok] = true
	}
}

func TestViewCookieParamsParse(t *testing.T) {
	params := viewCookieParams("session=abc; csrf=xyz", "https://app.example.com/admin")
	if len(params) != 2 {
		t.Fatalf("esperava 2 cookies, veio %d", len(params))
	}
	if params[0].Name != "session" || params[0].Value != "abc" {
		t.Fatalf("primeiro cookie malparseado: %+v", params[0])
	}
	if params[0].URL != "https://app.example.com/admin" {
		t.Fatal("URL do cookie deveria ser a view_url (pro browser inferir domínio)")
	}
	// entradas vazias/sem '=' são ignoradas
	if got := viewCookieParams("  ; =novalue; ok=1", "https://x.com"); len(got) != 1 {
		t.Fatalf("deveria ignorar entradas inválidas, veio %d", len(got))
	}
}
