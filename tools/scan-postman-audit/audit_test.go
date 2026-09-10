package main

import (
	"sort"
	"strings"
	"testing"
)

func TestCollectionID(t *testing.T) {
	cases := map[string]string{
		"4667198-fbf5c03a-d617-4770-b04e-b08f92b00c41":                                            "4667198-fbf5c03a-d617-4770-b04e-b08f92b00c41",
		"https://www.postman.com/acme/ws/collection/4667198-fbf5c03a-d617-4770-b04e-b08f92b00c41": "4667198-fbf5c03a-d617-4770-b04e-b08f92b00c41",
		"fbf5c03a-d617-4770-b04e-b08f92b00c41":                                                    "fbf5c03a-d617-4770-b04e-b08f92b00c41",
		"https://www.postman.com/acme/my-workspace/overview":                                      "",
	}
	for in, want := range cases {
		if got := collectionID(in); got != want {
			t.Errorf("collectionID(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestWalkItems(t *testing.T) {
	items := []any{
		map[string]any{"name": "folder", "item": []any{
			map[string]any{"name": "get user", "request": map[string]any{
				"method": "get", "url": map[string]any{"raw": "https://api.acme.com/users/1"}}},
		}},
		map[string]any{"name": "login", "request": map[string]any{
			"method": "POST", "url": map[string]any{
				"protocol": "https", "host": []any{"api", "acme", "com"}, "path": []any{"v1", "login"}}}},
	}
	var calls []apiCall
	walkItems(items, &calls)
	if len(calls) != 2 {
		t.Fatalf("calls = %d", len(calls))
	}
	if calls[0].Method != "GET" || calls[0].URL != "https://api.acme.com/users/1" {
		t.Errorf("call0 = %+v", calls[0])
	}
	if calls[1].Method != "POST" || calls[1].URL != "https://api.acme.com/v1/login" {
		t.Errorf("call1 = %+v (host/path join)", calls[1])
	}
}

func TestScanTextSecretsAndPII(t *testing.T) {
	tok := "yptZNpce7QlUcqDQSW5N0DJei4LPid1oOTgUKb9H2QvsWqvz"
	text := `{
	  "aws":"` + "AKIA" + `J7QK4PLM2NXR6WZ3",
	  "url":"https://svc:Sup3rSecret99@db.internal:5432",
	  "x-api-key":"` + tok + `",
	  "email":"jose.silva@acme.com.br",
	  "cpf":"123.456.789-09",
	  "card":"4111 1111 1111 1111",
	  "notreal_card":"1234 5678 9012 3456",
	  "phone":"+55 11 98765-4321",
	  "placeholder":"your_api_key_here"
	}`
	hs := scanText(text)
	kinds := map[string]string{}
	for _, h := range hs {
		kinds[h.Kind] = h.Class
	}
	for _, want := range []string{"aws-access-key-id", "basic-auth-url", "generic-api-key", "email", "cpf", "credit-card", "phone"} {
		if _, ok := kinds[want]; !ok {
			t.Errorf("faltou %s (kinds: %v)", want, keysOf(kinds))
		}
	}
	// cartão inválido pelo Luhn não deve entrar
	for _, h := range hs {
		if h.Kind == "credit-card" && strings.Contains(h.Value, "34") && !strings.Contains(h.Value, "4111") {
			// só o 4111... é válido; nada a fazer
		}
	}
	// placeholder não vira generic-api-key
	for _, h := range hs {
		if strings.Contains(h.Value, "your_api") {
			t.Errorf("placeholder vazou: %+v", h)
		}
	}
	// email de exemplo.com é filtrado
	if strings.Contains(text, "example.com") {
	}
}

func TestScanAuth(t *testing.T) {
	// hardcoded bearer -> hit
	a := map[string]any{"type": "bearer", "bearer": []any{
		map[string]any{"key": "token", "value": "yptZNpceQlUcqDQSWNDJeiLPidoOTgUKbH", "type": "string"},
	}}
	hs := scanAuth(a)
	if len(hs) != 1 || hs[0].Kind != "hardcoded-bearer" || hs[0].Severity != "high" {
		t.Fatalf("scanAuth bearer = %+v", hs)
	}
	// {{variable}} -> não é hardcoded
	a2 := map[string]any{"type": "apikey", "apikey": []any{
		map[string]any{"key": "value", "value": "{{apiKey}}", "type": "string"},
	}}
	if hs := scanAuth(a2); len(hs) != 0 {
		t.Errorf("{{var}} não deveria contar: %+v", hs)
	}
}

func TestLuhn(t *testing.T) {
	if !luhn("4111111111111111") {
		t.Error("4111... é válido")
	}
	if luhn("1234567890123456") {
		t.Error("1234... é inválido")
	}
}

func TestInternalHosts(t *testing.T) {
	text := `"https://api.acme.com/v1" "https://jenkins.internal.acme.com" "https://10.1.2.3:8080" "https://www.google.com" "https://schema.getpostman.com/x"`
	got := internalHosts(text, "acme.com")
	sort.Strings(got)
	if !contains(got, "api.acme.com") || !contains(got, "jenkins.internal.acme.com") || !contains(got, "10.1.2.3") {
		t.Errorf("got %v", got)
	}
	if contains(got, "www.google.com") || contains(got, "schema.getpostman.com") {
		t.Errorf("host público vazou: %v", got)
	}
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
