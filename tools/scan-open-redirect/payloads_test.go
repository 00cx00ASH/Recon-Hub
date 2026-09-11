package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://example.com/x":                "example.com",
		"//example.com/x":                      "example.com",
		"/\\example.com":                       "example.com",
		"\\/\\/example.com":                    "example.com",
		"https://user:pass@example.com/y":      "example.com",
		"https://whitelisted.test@example.com": "example.com",
		"https://example.com:8443/z":           "example.com",
		"https://example.com.evil.com/":        "example.com.evil.com",
		"http://EXAMPLE.COM":                   "example.com",
		"/relative/only":                       "",
		"":                                     "",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestSameHost(t *testing.T) {
	yes := [][2]string{{"example.com", "example.com"}, {"a.example.com", "example.com"}}
	no := [][2]string{
		{"example.com.evil.com", "example.com"},
		{"notexample.com", "example.com"},
		{"", "example.com"},
		{"example.com", ""},
	}
	for _, c := range yes {
		if !sameHost(c[0], c[1]) {
			t.Errorf("sameHost(%q,%q) = false, quer true", c[0], c[1])
		}
	}
	for _, c := range no {
		if sameHost(c[0], c[1]) {
			t.Errorf("sameHost(%q,%q) = true, quer false", c[0], c[1])
		}
	}
}

func TestRedirectsToCanary(t *testing.T) {
	if !redirectsToCanary("https://example.com/landing", "example.com") {
		t.Error("Location absoluto pro canary deveria bater")
	}
	if !redirectsToCanary("//example.com/", "example.com") {
		t.Error("Location protocol-relative pro canary deveria bater")
	}
	if redirectsToCanary("/local/path", "example.com") {
		t.Error("Location relativo NÃO deveria bater")
	}
	if redirectsToCanary("https://real-site.com/?u=https://example.com", "example.com") {
		t.Error("canary só no query NÃO deveria bater")
	}
	if redirectsToCanary("https://example.com.attacker.com/", "example.com") {
		t.Error("sufixo de domínio NÃO deveria bater")
	}
}

func TestBodyRedirectsToCanary(t *testing.T) {
	meta := `<html><head><meta http-equiv="refresh" content="0; url=https://example.com/next"></head></html>`
	if ok, m := bodyRedirectsToCanary(meta, "example.com"); !ok || m != "meta refresh" {
		t.Errorf("meta refresh: ok=%v m=%q", ok, m)
	}
	js := `<script>window.location.replace("https://example.com/go")</script>`
	if ok, m := bodyRedirectsToCanary(js, "example.com"); !ok || m != "location JS" {
		t.Errorf("location JS: ok=%v m=%q", ok, m)
	}
	benign := `<a href="https://example.com/docs">docs</a>`
	if ok, _ := bodyRedirectsToCanary(benign, "example.com"); ok {
		t.Error("link comum pro canary NÃO deveria bater")
	}
}

func TestParamNames(t *testing.T) {
	got := paramNames("foo, bar\nfoo", []string{"bar", "baz"})
	want := []string{"foo", "bar", "baz"}
	if len(got) != len(want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, quer %v", got, want)
		}
	}
}

func TestBuildPayloads(t *testing.T) {
	ps := buildPayloads("example.com", "victim.com")
	if len(ps) < 10 {
		t.Fatalf("poucos payloads: %d", len(ps))
	}
	var hasUserinfo bool
	for _, p := range ps {
		if p.value == "https://victim.com@example.com" {
			hasUserinfo = true
		}
	}
	if !hasUserinfo {
		t.Error("faltou o payload userinfo com o host alvo")
	}
	var hasBackslashAt bool
	for _, p := range ps {
		if p.value == "https://example.com\\@victim.com" {
			hasBackslashAt = true
		}
	}
	if !hasBackslashAt {
		t.Error("faltou o payload de confusão de parser (backslash antes do @)")
	}
}

// integração: servidor que reflete o param `next` no Location.
func TestProbeConfirmsServerRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.WriteHeader(200)
			return
		}
		http.Redirect(w, r, next, http.StatusFound)
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	u := withParam(srv.URL, "next", "https://example.com/pwn")
	sev, ftype, _, _ := probe(client, u, "example.com")
	if sev != "high" || ftype != "open-redirect" {
		t.Fatalf("sev=%q ftype=%q, quer high/open-redirect", sev, ftype)
	}

	// controle: redireciona pra si mesmo → sem hit
	u2 := withParam(srv.URL, "next", "/dashboard")
	if sev2, _, _, _ := probe(client, u2, "example.com"); sev2 != "" {
		t.Fatalf("redirect interno não deveria virar finding (sev=%q)", sev2)
	}
}
