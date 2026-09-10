package main

import "testing"

func TestWithParam(t *testing.T) {
	got := withParam("https://app.example.com/import?other=1", "url", "http://169.254.169.254/")
	if got == "" {
		t.Fatal("withParam retornou vazio")
	}
	if !contains(got, "url=") {
		t.Fatalf("esperava o parâmetro url= na URL final: %s", got)
	}
	if !contains(got, "other=1") {
		t.Fatalf("não deveria descartar os outros parâmetros existentes: %s", got)
	}
}

func TestLooksDifferent(t *testing.T) {
	cases := []struct {
		name     string
		baseline string
		status   int
		bodyLen  int
		want     bool
	}{
		{"status igual e corpo parecido", "status=200 bytes=100", 200, 120, false},
		{"status diferente", "status=0 bytes=0", 200, 50, true},
		{"corpo bem maior", "status=200 bytes=50", 200, 400, true},
		{"requisição do alvo falhou", "status=200 bytes=50", 0, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := looksDifferent(c.baseline, c.status, c.bodyLen); got != c.want {
				t.Errorf("looksDifferent(%q, %d, %d) = %v, want %v", c.baseline, c.status, c.bodyLen, got, c.want)
			}
		})
	}
}

func TestNormURL(t *testing.T) {
	if got := normURL("app.example.com"); got != "https://app.example.com" {
		t.Errorf("normURL sem esquema: got %q", got)
	}
	if got := normURL("http://app.example.com"); got != "http://app.example.com" {
		t.Errorf("normURL preservando http://: got %q", got)
	}
	if got := normURL("  "); got != "" {
		t.Errorf("normURL de string vazia deveria ser vazio, veio %q", got)
	}
}

func TestParamNamesIncludesBuiltins(t *testing.T) {
	got := paramNames("meu_param_custom")
	if got[0] != "meu_param_custom" {
		t.Fatalf("param extra deveria vir primeiro: %v", got[:3])
	}
	found := false
	for _, p := range got {
		if p == "webhook_url" {
			found = true
		}
	}
	if !found {
		t.Fatal("lista embutida não foi incluída")
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
