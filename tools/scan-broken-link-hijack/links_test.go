package main

import "testing"

func TestExtractRefs(t *testing.T) {
	html := `
	<a href="https://github.com/acme/tools">tools</a>
	<a href="/relative">rel</a>
	<a href="#frag">frag</a>
	<a href="mailto:x@y.com">mail</a>
	<script src="https://cdn.jsdelivr.net/npm/leftpad@1/index.js"></script>
	<img src="https://img.example.com/logo.png">
	<iframe src="//player.example.com/x"></iframe>
	`
	refs := extractRefs(html, "https://blog.example.com/post")
	got := map[string]string{}
	for _, r := range refs {
		got[r.URL] = r.Where
	}
	if got["https://github.com/acme/tools"] != "a" {
		t.Errorf("faltou o link do github: %v", got)
	}
	if got["https://blog.example.com/relative"] != "a" {
		t.Errorf("link relativo não resolvido: %v", got)
	}
	if _, ok := got["https://img.example.com/logo.png"]; !ok {
		t.Errorf("faltou o img: %v", got)
	}
	if got["https://player.example.com/x"] != "iframe" {
		t.Errorf("iframe protocol-relative não resolvido: %v", got)
	}
	if _, bad := got["#frag"]; bad {
		t.Error("fragmento não devia entrar")
	}
}

func TestClassifyRef(t *testing.T) {
	cases := []struct {
		url      string
		wantOK   bool
		platform string
		probe    string
		target   string
	}{
		{"https://github.com/someuser", true, "GitHub user/org", "github-user", "someuser"},
		{"https://github.com/someuser/somerepo", true, "GitHub repo", "github-repo", "someuser/somerepo"},
		{"https://github.com/about", false, "", "", ""},
		{"https://acme.github.io/docs", true, "GitHub Pages", "github-user", "acme"},
		{"https://www.npmjs.com/package/@scope/thing", true, "npm package", "npm", "@scope/thing"},
		{"https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js", true, "npm package (CDN)", "npm", "lodash"},
		{"https://mybucket.s3.amazonaws.com/x.js", true, "S3 bucket", "s3", "mybucket"},
		{"https://s3.amazonaws.com/otherbucket/y", true, "S3 bucket", "s3", "otherbucket"},
		{"https://foo.herokuapp.com/", true, "CNAME herokuapp.com", "fingerprint", "foo.herokuapp.com"},
		{"https://twitter.com/somehandle", true, "social (twitter.com)", "social", "somehandle"},
		{"https://twitter.com/home", false, "", "", ""},
		{"https://example.com/normal/link", false, "", "", ""},
	}
	for _, c := range cases {
		k, ok := classifyRef(c.url)
		if ok != c.wantOK {
			t.Errorf("%s: ok=%v, quer %v", c.url, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if k.platform != c.platform || k.probe != c.probe || k.target != c.target {
			t.Errorf("%s: %+v, quer platform=%q probe=%q target=%q", c.url, k, c.platform, c.probe, c.target)
		}
	}
}

func TestDecide(t *testing.T) {
	gh := hijackKind{platform: "GitHub user/org", probe: "github-user", sev: "high", target: "ghost"}

	if v, hit := decide(gh, probeResult{resolves: false}); !hit || v.kind != "dangling-dns" {
		t.Errorf("host que não resolve → %+v", v)
	}
	if v, hit := decide(gh, probeResult{resolves: true, status: 404}); !hit || v.kind != "broken-link-hijack" || v.severity != "high" {
		t.Errorf("gh 404 → %+v hit=%v", v, hit)
	}
	if _, hit := decide(gh, probeResult{resolves: true, status: 200}); hit {
		t.Error("gh 200 não é hijack")
	}

	s3 := hijackKind{platform: "S3 bucket", probe: "s3", sev: "high", target: "b"}
	if v, hit := decide(s3, probeResult{resolves: true, status: 404, body: "<Error><Code>NoSuchBucket</Code></Error>"}); !hit || v.severity != "high" {
		t.Errorf("s3 NoSuchBucket → %+v", v)
	}
	if _, hit := decide(s3, probeResult{resolves: true, status: 403, body: "<Code>AllAccessDisabled</Code>"}); hit {
		t.Error("s3 AllAccessDisabled não é hijack")
	}

	fp := hijackKind{platform: "CNAME herokuapp.com", probe: "fingerprint", sev: "high", target: "x.herokuapp.com", marker: "no such app"}
	if _, hit := decide(fp, probeResult{resolves: true, status: 404, body: "<h1>No such app</h1>"}); !hit {
		t.Error("fingerprint marker deveria bater (case-insensitive)")
	}
	if _, hit := decide(fp, probeResult{resolves: true, status: 200, body: "welcome to the app"}); hit {
		t.Error("sem marker não é hijack")
	}
}

func TestRegistrableGuess(t *testing.T) {
	cases := map[string]string{
		"blog.example.com":    "example.com",
		"example.com":         "example.com",
		"a.b.c.example.co.uk": "example.co.uk",
		"shop.acme.com.br":    "acme.com.br",
		"localhost":           "localhost",
	}
	for in, want := range cases {
		if got := registrableGuess(in); got != want {
			t.Errorf("registrableGuess(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestGenericExternal(t *testing.T) {
	k, ok := genericExternal("https://some-partner-site.example/path")
	if !ok || k.probe != "dns-only" || k.target != "some-partner-site.example" {
		t.Errorf("genericExternal → %+v ok=%v", k, ok)
	}
	if _, ok := genericExternal("https://93.184.216.34/x"); ok {
		t.Error("IP não deveria virar candidato dns-only")
	}
	// dns-only só vira finding se não resolver
	if _, hit := decide(k, probeResult{resolves: true, status: 200}); hit {
		t.Error("dns-only que resolve não é finding")
	}
	if v, hit := decide(k, probeResult{resolves: false}); !hit || v.kind != "dangling-dns" {
		t.Errorf("dns-only que não resolve → %+v", v)
	}
}

func TestNpmFromCDN(t *testing.T) {
	cases := map[string]string{
		"lodash@4.17.21/lodash.min.js": "", // unpkg path handled with host
	}
	_ = cases
	if got := npmFromCDN("unpkg.com", "react@18/umd/react.js"); got != "react" {
		t.Errorf("unpkg react → %q", got)
	}
	if got := npmFromCDN("cdn.jsdelivr.net", "npm/@babel/core@7/lib/index.js"); got != "@babel/core" {
		t.Errorf("jsdelivr scoped → %q", got)
	}
	if got := npmFromCDN("cdn.jsdelivr.net", "gh/user/repo/file.js"); got != "" {
		t.Errorf("jsdelivr gh (não-npm) → %q, quer vazio", got)
	}
}
