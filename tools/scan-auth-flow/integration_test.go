package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeIdP simula um authorization_endpoint. Quando strict=false, aceita
// QUALQUER redirect_uri (bug clássico) e redireciona pra lá com um código
// fake. Quando strict=true, só redireciona se redirect_uri bater
// exatamente com a URL registrada.
func fakeIdP(t *testing.T, strict bool, registered string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"authorization_endpoint":"` + "http://" + r.Host + "/oauth2/authorize" + `"}`))
			return
		}
		if r.URL.Path == "/oauth2/authorize" {
			ru := r.URL.Query().Get("redirect_uri")
			if strict && ru != registered {
				w.WriteHeader(400)
				w.Write([]byte("invalid redirect_uri"))
				return
			}
			w.Header().Set("Location", ru+"?code=fake-auth-code")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(404)
	}))
}

func TestEndToEndDetectsOpenRedirectURIBypass(t *testing.T) {
	srv := fakeIdP(t, false, "https://app.legit.test/callback")
	defer srv.Close()

	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	authURL := discoverAuthorizeEndpoint(client, srv.URL)
	if authURL == "" {
		t.Fatal("deveria ter descoberto o authorization_endpoint via well-known")
	}

	payloads := redirectURIBypasses("example.com", "app.legit.test")
	confirmed := false
	for _, p := range payloads {
		u := withRedirectURI(authURL, "cid123", p.Value)
		status, headers := getHeaders(client, u)
		if status >= 300 && status < 400 && redirectsToCanary(headers.Get("Location"), "example.com") {
			confirmed = true
			break
		}
	}
	if !confirmed {
		t.Fatal("deveria ter confirmado pelo menos 1 bypass contra um IdP que aceita qualquer redirect_uri")
	}
}

func TestEndToEndNoFalsePositiveOnStrictIdP(t *testing.T) {
	srv := fakeIdP(t, true, "https://app.legit.test/callback")
	defer srv.Close()

	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	authURL := discoverAuthorizeEndpoint(client, srv.URL)
	payloads := redirectURIBypasses("example.com", "app.legit.test")
	for _, p := range payloads {
		u := withRedirectURI(authURL, "cid123", p.Value)
		status, headers := getHeaders(client, u)
		if status >= 300 && status < 400 && redirectsToCanary(headers.Get("Location"), "example.com") {
			t.Fatalf("falso positivo: IdP estrito não deveria confirmar bypass com o payload %q (%s)", p.Value, p.Label)
		}
	}
}
