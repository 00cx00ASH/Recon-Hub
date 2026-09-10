package main

import "testing"

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
