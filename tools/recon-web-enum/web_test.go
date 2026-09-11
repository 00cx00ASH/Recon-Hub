package main

import (
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
)

func TestApplyAuth(t *testing.T) {
	t.Setenv("RECONHUB_TARGET", "https://x.com")
	t.Setenv("RECONHUB_AUTH_COOKIE", "session=abc123")
	t.Setenv("RECONHUB_AUTH_BEARER", "tok-xyz")
	t.Setenv("RECONHUB_AUTH_HEADERS", `{"X-Api-Key":"k1"}`)
	req, _ := http.NewRequest(http.MethodGet, "https://x.com", nil)
	applyAuth(req)
	if req.Header.Get("Cookie") != "session=abc123" {
		t.Errorf("Cookie = %q", req.Header.Get("Cookie"))
	}
	if req.Header.Get("Authorization") != "Bearer tok-xyz" {
		t.Errorf("Authorization = %q", req.Header.Get("Authorization"))
	}
	if req.Header.Get("X-Api-Key") != "k1" {
		t.Errorf("X-Api-Key = %q", req.Header.Get("X-Api-Key"))
	}
}

func TestApplyAuthSkipsThirdPartyHost(t *testing.T) {
	// achado no design: js-bucket-scanner/js-firebase-enum/js-gtm-osint
	// reusam a mesma função de fetch pra chamadas a terceiros (S3, Firebase,
	// CDN do Google) — o cookie/token do ALVO não pode vazar pra lá.
	t.Setenv("RECONHUB_TARGET", "https://x.com")
	t.Setenv("RECONHUB_AUTH_COOKIE", "session=abc123")
	req, _ := http.NewRequest(http.MethodGet, "https://storage.googleapis.com/bucket", nil)
	applyAuth(req)
	if req.Header.Get("Cookie") != "" {
		t.Errorf("não deveria enviar o cookie do alvo pra um host diferente: %q", req.Header.Get("Cookie"))
	}
}

func TestSameHostAsTargetIgnoresPort(t *testing.T) {
	t.Setenv("RECONHUB_TARGET", "https://x.com:8443/app")
	if !sameHostAsTarget("x.com:9000") {
		t.Error("mesmo host, porta diferente ainda deveria bater (ignora porta)")
	}
	if sameHostAsTarget("evil.com") {
		t.Error("host diferente não deveria bater")
	}
}

func TestSameHostAsTargetNoTargetSetAllows(t *testing.T) {
	os.Unsetenv("RECONHUB_TARGET")
	if !sameHostAsTarget("qualquer.com") {
		t.Error("sem RECONHUB_TARGET não deveria bloquear")
	}
}

func TestApplyAuthNoEnvIsNoop(t *testing.T) {
	os.Unsetenv("RECONHUB_AUTH_COOKIE")
	os.Unsetenv("RECONHUB_AUTH_BEARER")
	os.Unsetenv("RECONHUB_AUTH_HEADERS")
	req, _ := http.NewRequest(http.MethodGet, "https://x.com", nil)
	applyAuth(req)
	if req.Header.Get("Cookie") != "" || req.Header.Get("Authorization") != "" {
		t.Errorf("sem env, não deveria setar nada: %v", req.Header)
	}
}

func TestSameSite(t *testing.T) {
	if !sameSite("https://blog.example.com/x", "www.example.com") {
		t.Error("subdomínios do mesmo site")
	}
	if sameSite("https://evil.com/x", "www.example.com") {
		t.Error("host diferente")
	}
	if !sameSite("https://www.example.com/y", "example.com") {
		t.Error("www vs apex")
	}
}

func TestPageLinks(t *testing.T) {
	html := `
	<a href="/about">about</a>
	<a href="https://www.example.com/contact">contact</a>
	<a href="https://other.com/x">external</a>
	<a href="mailto:a@b.com">mail</a>
	<a href="#top">frag</a>
	<script src="/static/app.js"></script>
	`
	got := pageLinks(html, "https://www.example.com/", "www.example.com")
	sort.Strings(got)
	want := []string{
		"https://www.example.com/about",
		"https://www.example.com/contact",
		"https://www.example.com/static/app.js",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

// TestIsHTMLRejectsJS regressão: um bundle JS que contém uma string de
// template tipo `href="{{href}}"` (ex: a lib de cookie-consent embute HTML
// como texto) não pode virar "link descoberto" — só body de resposta HTML
// deveria ir pro pageLinks/extractForms. Achado rodando o hub de verdade
// contra o OWASP Juice Shop: o crawler seguia scripts.js e "descobria"
// http://alvo/{{href}} como se fosse uma página real.
func TestIsHTMLRejectsJS(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/javascript; charset=utf-8")
	if isHTML(h) {
		t.Error("Content-Type application/javascript não deveria contar como HTML")
	}
	h2 := http.Header{}
	h2.Set("Content-Type", "text/html; charset=utf-8")
	if !isHTML(h2) {
		t.Error("text/html deveria contar como HTML")
	}
	h3 := http.Header{} // sem Content-Type — mantém compatibilidade (assume HTML)
	if !isHTML(h3) {
		t.Error("sem Content-Type deveria manter o comportamento anterior (assume HTML)")
	}
}

func TestExtractForms(t *testing.T) {
	html := `
	<form action="/login" method="POST">
	  <input name="user" type="text">
	  <input name="pass" type="password">
	</form>
	<form><input name="q"></form>
	`
	fs := extractForms(html, "https://x.com/page")
	if len(fs) != 2 {
		t.Fatalf("forms = %d", len(fs))
	}
	if fs[0].Action != "https://x.com/login" || fs[0].Method != "POST" || !fs[0].Password {
		t.Errorf("form0 = %+v", fs[0])
	}
	if len(fs[0].Inputs) != 2 || fs[0].Inputs[0] != "user" {
		t.Errorf("form0 inputs = %v", fs[0].Inputs)
	}
	if fs[1].Method != "GET" || fs[1].Password {
		t.Errorf("form1 = %+v", fs[1])
	}
}

func TestFingerprint(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.25")
	h.Set("X-Powered-By", "PHP/8.2")
	h.Add("Set-Cookie", "PHPSESSID=abc; path=/")
	h.Set("CF-RAY", "abc123-GRU")
	body := `<html><head><meta name="generator" content="WordPress 6.4"></head><body>wp-content/themes</body></html>`
	got := fingerprint(h, body)
	joined := strings.Join(got, " | ")
	for _, want := range []string{"nginx/1.25", "PHP/8.2", "PHP (PHPSESSID)", "Cloudflare", "WordPress", "Generator: WordPress 6.4"} {
		if !strings.Contains(joined, want) {
			t.Errorf("faltou %q em %q", want, joined)
		}
	}
}

func TestBaselineSoft(t *testing.T) {
	b := baseline{status: 200, size: 1000}
	if !b.isSoft(200, 1050) {
		t.Error("200 com tamanho parecido = soft-404")
	}
	if b.isSoft(200, 5000) {
		t.Error("200 com tamanho bem diferente != soft-404")
	}
	if b.isSoft(404, 300) {
		t.Error("baseline 200, probe 404 real -> não é soft")
	}
	b2 := baseline{status: 404, size: 200}
	if !b2.isSoft(404, 999) {
		t.Error("baseline não-200: mesmo status = soft (independe do tamanho)")
	}
	if b2.isSoft(200, 200) {
		t.Error("status diferente do baseline != soft")
	}
}

func TestProbeVerdict(t *testing.T) {
	base := baseline{status: 404, size: 150}
	// admin 403 -> existe mas protegido: conta como hit (pra visibilidade),
	// mas NÃO confirmado — não é achado reportável isoladamente.
	if ok, confirmed, _ := probeVerdict("admin", 403, 500, "text/html", "forbidden", base); !ok || confirmed {
		t.Error("admin 403 deveria contar como hit, mas não confirmado")
	}
	// admin 200 real -> confirmado
	if ok, confirmed, _ := probeVerdict("admin", 200, 4000, "text/html", "<html>login</html>", base); !ok || !confirmed {
		t.Error("admin 200 fora do baseline deveria contar e ser confirmado")
	}
	// soft-404
	if ok, _, _ := probeVerdict("admin", 404, 150, "text/html", "not found", base); ok {
		t.Error("soft-404 não deveria contar")
	}
	// sensitive file that's just an SPA html page
	if ok, _, _ := probeVerdict("sensitive-file", 200, 3000, "text/html", "<html><body>app</body></html>", base); ok {
		t.Error("SPA html não é o arquivo sensível")
	}
	// .git/config real content
	if ok, confirmed, _ := probeVerdict("sensitive-file", 200, 120, "text/plain", "[core]\n\trepositoryformatversion = 0", base); !ok || !confirmed {
		t.Error("conteúdo real de .git/config deveria contar e ser confirmado")
	}
}
