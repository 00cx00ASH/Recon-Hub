package main

import (
	"strings"
	"testing"
)

// TestParseCrtshBody usa o formato real de resposta do crt.sh (?output=json):
// um array de linhas de certificado, cada uma com name_value podendo trazer
// vários SANs separados por \n. Antes do refactor que separou fetch de
// parse, isso só era exercitado batendo na rede — impossível de validar num
// ambiente sem acesso a crt.sh (ex: este sandbox, que bloqueia o domínio por
// política de rede).
func TestParseCrtshBody(t *testing.T) {
	body := []byte(`[
		{
			"issuer_ca_id": 16418,
			"issuer_name": "C=US, O=Let's Encrypt, CN=R3",
			"common_name": "www.example.com",
			"name_value": "www.example.com",
			"id": 1234567890,
			"entry_timestamp": "2024-01-01T00:00:00",
			"not_before": "2024-01-01T00:00:00",
			"not_after": "2024-04-01T00:00:00",
			"serial_number": "abc123"
		},
		{
			"common_name": "api.example.com",
			"name_value": "api.example.com\nwww.api.example.com\n*.internal.example.com"
		}
	]`)
	rows, err := parseCrtshBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, quer 2", len(rows))
	}
	if rows[0].NameValue != "www.example.com" || rows[0].CommonName != "www.example.com" {
		t.Errorf("row0 = %+v", rows[0])
	}
	if rows[1].NameValue != "api.example.com\nwww.api.example.com\n*.internal.example.com" {
		t.Errorf("row1.NameValue multi-SAN não preservado: %q", rows[1].NameValue)
	}

	// o pipeline real (main) faz strings.Split(NameValue+"\n"+CommonName, "\n")
	// e normalizeHost em cada linha — confirma que os 3 SANs do row1 + o apex
	// do common_name viram 4 hosts distintos, todos dentro do escopo.
	set := map[string]struct{}{}
	for _, r := range rows {
		for _, raw := range strings.Split(r.NameValue+"\n"+r.CommonName, "\n") {
			if h := normalizeHost(raw, "example.com", false); h != "" {
				set[h] = struct{}{}
			}
		}
	}
	for _, want := range []string{"www.example.com", "api.example.com", "www.api.example.com"} {
		if _, ok := set[want]; !ok {
			t.Errorf("faltou %q no set final: %v", want, set)
		}
	}
	if _, ok := set["*.internal.example.com"]; ok {
		t.Error("wildcard sem -wildcards não deveria sobreviver ao normalizeHost")
	}
}

func TestParseCrtshBodyInvalidJSON(t *testing.T) {
	if _, err := parseCrtshBody([]byte("not json")); err == nil {
		t.Error("esperava erro pra JSON inválido")
	}
}

// TestParseCertspotterBody usa o formato real da API do certspotter
// (?expand=dns_names): array de issuances, cada um com dns_names.
func TestParseCertspotterBody(t *testing.T) {
	body := []byte(`[
		{
			"id": "111",
			"tbs_sha256": "aaa",
			"cert_sha256": "bbb",
			"dns_names": ["example.com", "www.example.com"],
			"not_before": "2024-01-01T00:00:00Z",
			"not_after": "2024-04-01T00:00:00Z"
		},
		{
			"id": "222",
			"dns_names": ["api.example.com"]
		}
	]`)
	names, err := parseCertspotterBody(body)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "www.example.com", "api.example.com"}
	if len(names) != len(want) {
		t.Fatalf("names = %v, quer %v", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("names[%d] = %q, quer %q", i, names[i], w)
		}
	}
}

func TestParseCertspotterBodyInvalidJSON(t *testing.T) {
	if _, err := parseCertspotterBody([]byte("<html>rate limited</html>")); err == nil {
		t.Error("esperava erro pra JSON inválido")
	}
}

func TestNormalizeHost(t *testing.T) {
	dom := "exemplo.com"
	cases := map[string]string{
		"api.exemplo.com":         "api.exemplo.com",
		"  API.Exemplo.com. ":     "api.exemplo.com",
		"exemplo.com":             "exemplo.com",
		"a.b.exemplo.com":         "a.b.exemplo.com",
		"*.exemplo.com":           "", // wildcard sem -wildcards
		"outro.com":               "", // fora do escopo
		"exemplo.com.br":          "", // sufixo parecido mas não é
		"admin@exemplo.com":       "", // e-mail no CT
		"foo bar.exemplo.com":     "", // espaço
		"under_score.exemplo.com": "", // char inválido p/ DNS
	}
	for in, want := range cases {
		if got := normalizeHost(in, dom, false); got != want {
			t.Errorf("normalizeHost(%q) = %q, quer %q", in, got, want)
		}
	}
	if got := normalizeHost("*.exemplo.com", dom, true); got != "exemplo.com" {
		t.Errorf("wildcard com flag: %q", got)
	}
}

func TestCleanHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://Sub.Exemplo.com/x": "sub.exemplo.com",
		"exemplo.com:443":           "exemplo.com",
		"*.exemplo.com.":            "exemplo.com",
	} {
		if got := cleanHost(in); got != want {
			t.Errorf("cleanHost(%q) = %q, quer %q", in, got, want)
		}
	}
}
