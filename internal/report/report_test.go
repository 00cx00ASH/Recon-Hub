package report

import (
	"strings"
	"testing"
	"time"
)

func sampleItems() []Item {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return []Item{
		{Type: "cors-reflect-credentials", Severity: "critical", Title: "x", Asset: "https://api.acme.com/me",
			Evidence: "Origin: https://evil.example → ACAO: \"https://evil.example\" · ACAC: \"true\"", Tool: "scan-cors",
			Count: 1, FirstAt: now, LastAt: now, Meta: map[string]any{"sent_origin": "https://evil.example"}},
		{Type: "subdomain-takeover", Severity: "high", Title: "y", Asset: "abandoned.acme.com",
			Evidence: "CNAME para foo.s3.amazonaws.com — NoSuchBucket", Tool: "scan-subdomain-takeover",
			Count: 2, FirstAt: now, LastAt: now, Meta: map[string]any{"claim_target": "foo"}},
		{Type: "recon-crtsh-note", Severity: "info", Title: "z", Asset: "a.acme.com", Tool: "recon-crtsh"},
		{Type: "some-brand-new-thing", Severity: "medium", Title: "Weird thing found", Asset: "https://acme.com/weird",
			Evidence: "got a 200 with odd header", Tool: "scan-fuzz"},
	}
}

func TestBuildOrderingAndSkip(t *testing.T) {
	r := Build("acme", "", sampleItems(), false)
	if r.Total != 3 {
		t.Fatalf("Total = %d (info sem template deveria sair), sections: %+v", r.Total, r.Sections)
	}
	if r.Skipped() != 1 {
		t.Errorf("Skipped = %d, quer 1", r.Skipped())
	}
	// mais severo primeiro
	if r.Sections[0].Severity != "critical" || r.Sections[1].Severity != "high" || r.Sections[2].Severity != "medium" {
		t.Errorf("ordem de severidade errada: %v %v %v", r.Sections[0].Severity, r.Sections[1].Severity, r.Sections[2].Severity)
	}
	if r.Sections[0].ID != "F-01" || r.Sections[2].ID != "F-03" {
		t.Errorf("ids = %v", []string{r.Sections[0].ID, r.Sections[2].ID})
	}
	if r.Counts["critical"] != 1 || r.Counts["high"] != 1 || r.Counts["medium"] != 1 {
		t.Errorf("counts = %v", r.Counts)
	}
}

func TestBuildTemplatedVsFallback(t *testing.T) {
	r := Build("acme", "", sampleItems(), false)
	cors := r.Sections[0]
	if !cors.Templated || cors.CWE != "CWE-942" || cors.Impact == "" || cors.Remediation == "" {
		t.Errorf("cors deveria ser templated com CWE/impact/remediation: %+v", cors)
	}
	if len(cors.Repro) < 2 {
		t.Errorf("cors repro curto: %v", cors.Repro)
	}
	var fb *Section
	for i := range r.Sections {
		if r.Sections[i].Type == "some-brand-new-thing" {
			fb = &r.Sections[i]
		}
	}
	if fb == nil || fb.Templated {
		t.Fatalf("esperava seção fallback não-templated")
	}
	if fb.Name != "Weird thing found" || !strings.Contains(fb.Description, "Sem template") {
		t.Errorf("fallback = %+v", *fb)
	}
}

func TestIncludeInfo(t *testing.T) {
	r := Build("acme", "", sampleItems(), true)
	if r.Total != 4 || r.Skipped() != 0 {
		t.Errorf("com include_info: total=%d skipped=%d", r.Total, r.Skipped())
	}
}

func TestMarkdown(t *testing.T) {
	md := Build("acme", "", sampleItems(), false).Markdown()
	for _, want := range []string{
		"# Relatório de recon — acme",
		"## Resumo",
		"1 critical, 1 high, 1 medium",
		"## F-01 — CORS: reflexão de origem com credenciais",
		"### Passos para reproduzir",
		"### Impacto",
		"### Correção",
		"### Referências",
		"CWE-942",
		"Sem template dedicado", // fallback nota
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown sem %q", want)
		}
	}
}

func TestHTML(t *testing.T) {
	h := Build("acme", "", sampleItems(), false).HTML()
	if !strings.HasPrefix(h, "<!doctype html>") || !strings.Contains(h, "</html>") {
		t.Fatal("HTML mal formado")
	}
	for _, want := range []string{
		"<title>Relatório de recon — acme</title>",
		`<span class="sev critical">CRITICAL</span>`,
		"<h3>Passos para reproduzir</h3>",
		"<code>", // repro inline code
		"CWE-350",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("html sem %q", want)
		}
	}
	// XSS: o nome fallback vem de dados; garante escape
	items := []Item{{Type: "x", Severity: "low", Title: "<script>alert(1)</script>", Asset: "a", Tool: "t"}}
	h2 := Build("", "", items, false).HTML()
	if strings.Contains(h2, "<script>alert(1)</script>") {
		t.Error("HTML não escapou o título")
	}
}

func TestLookup(t *testing.T) {
	// todos os tipos cors reais têm template exato
	for _, ty := range []string{"cors-reflect-credentials", "cors-reflect-origin", "cors-null-origin", "cors-wildcard", "cors-wildcard-credentials"} {
		if tp, ok := lookup(ty); !ok || tp.CWE == "" {
			t.Errorf("%s deveria ter template exato", ty)
		}
	}
	// prefixo conservador que ainda faz sentido
	if tp, ok := lookup("ai-key-invalid-variant"); !ok || tp.CWE == "" {
		t.Error("prefixo ai-key-")
	}
	// tipos jwt distintos NÃO caem num template genérico errado
	if _, ok := lookup("jwt-symmetric"); ok {
		t.Error("jwt-symmetric não deveria ter template (é contexto/info)")
	}
	if _, ok := lookup("totally-unknown-xyz"); ok {
		t.Error("desconhecido não deveria casar")
	}
}
