package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEndToEndAgainstFakeVulnerableApp simula um app que, quando o parâmetro
// "webhook_url" aponta pra um host com "169.254.169.254", devolve o corpo
// (fingindo que buscou o recurso) — e confirma que probe()+confirm() batem
// nesse caso e não em nenhum outro parâmetro/alvo.
func TestEndToEndAgainstFakeVulnerableApp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wh := r.URL.Query().Get("webhook_url")
		if strings.Contains(wh, "169.254.169.254") && strings.Contains(wh, "meta-data") {
			io.WriteString(w, "ami-id\ninstance-id\nlocal-hostname\nsecurity-credentials/\n")
			return
		}
		io.WriteString(w, "<html>página normal</html>")
	}))
	defer srv.Close()

	client := &http.Client{}
	u := withParam(srv.URL+"?other=1", "webhook_url", "http://169.254.169.254/latest/meta-data/")
	status, body := doProbe(client, u)
	if status != 200 {
		t.Fatalf("status = %d", status)
	}
	tg := ssrfTargets()[0] // aws-metadata
	if !tg.confirm(body) {
		t.Fatalf("deveria confirmar SSRF contra o app fake vulnerável; corpo: %q", body)
	}

	// parâmetro errado (não o vulnerável) não deve confirmar nada
	u2 := withParam(srv.URL+"?other=1", "outro_param", "http://169.254.169.254/latest/meta-data/")
	_, body2 := doProbe(client, u2)
	if tg.confirm(body2) {
		t.Fatal("não deveria confirmar quando o parâmetro testado não é o vulnerável")
	}
}
