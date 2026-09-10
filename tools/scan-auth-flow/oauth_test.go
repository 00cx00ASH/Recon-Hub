package main

import "testing"

func TestRedirectsToCanary(t *testing.T) {
	cases := []struct {
		loc, canary string
		want        bool
	}{
		{"https://example.com/callback", "example.com", true},
		{"https://sub.example.com/x", "example.com", true},
		{"https://notexample.com/x", "example.com", false},
		{"https://app.client.test/callback", "example.com", false},
		{"", "example.com", false},
	}
	for _, c := range cases {
		if got := redirectsToCanary(c.loc, c.canary); got != c.want {
			t.Errorf("redirectsToCanary(%q, %q) = %v, want %v", c.loc, c.canary, got, c.want)
		}
	}
}

func TestWithRedirectURIPreservesOtherParams(t *testing.T) {
	u := withRedirectURI("https://idp.test/authorize?scope=openid&state=abc", "cid123", "https://example.com")
	if u == "" {
		t.Fatal("withRedirectURI retornou vazio")
	}
	for _, want := range []string{"scope=openid", "state=abc", "client_id=cid123", "response_type=code"} {
		if !contains(u, want) {
			t.Errorf("esperava %q na URL final: %s", want, u)
		}
	}
}

func TestWithRedirectURIKeepsExistingResponseType(t *testing.T) {
	u := withRedirectURI("https://idp.test/authorize?response_type=token", "cid", "https://example.com")
	if !contains(u, "response_type=token") {
		t.Fatalf("não deveria sobrescrever response_type já presente: %s", u)
	}
}

func TestExtractAuthorizationEndpoint(t *testing.T) {
	body := `{"issuer":"https://idp.test","authorization_endpoint":"https://idp.test/oauth2/authorize","token_endpoint":"https://idp.test/oauth2/token"}`
	if got := extractAuthorizationEndpoint(body); got != "https://idp.test/oauth2/authorize" {
		t.Errorf("got %q", got)
	}
	if got := extractAuthorizationEndpoint("não é json de OIDC"); got != "" {
		t.Errorf("esperava vazio pra corpo sem o campo, veio %q", got)
	}
}

func TestRedirectURIBypassesNonEmpty(t *testing.T) {
	got := redirectURIBypasses("example.com", "app.acme.com")
	if len(got) < 5 {
		t.Fatalf("lista de bypass suspeitosamente curta: %d", len(got))
	}
	for _, p := range got {
		if p.Label == "" || p.Value == "" {
			t.Fatalf("payload incompleto: %+v", p)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
