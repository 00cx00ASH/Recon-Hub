package main

import (
	"net/http"
	"testing"
)

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func TestReadCache(t *testing.T) {
	cases := []struct {
		name   string
		h      http.Header
		backed bool
	}{
		{"x-cache hit", hdr("X-Cache", "HIT"), true},
		{"cf hit", hdr("CF-Cache-Status", "HIT"), true},
		{"cf dynamic", hdr("CF-Cache-Status", "DYNAMIC"), true},
		{"age", hdr("Age", "42"), true},
		{"cc public", hdr("Cache-Control", "public, max-age=600"), true},
		{"cc s-maxage", hdr("Cache-Control", "s-maxage=60"), true},
		{"cc no-store", hdr("Cache-Control", "no-store"), false},
		{"cc private", hdr("Cache-Control", "private, max-age=0"), false},
		{"nada", hdr("Content-Type", "text/html"), false},
		{"via varnish", hdr("Via", "1.1 varnish"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := readCache(c.h); got.backed != c.backed {
				t.Errorf("readCache = %+v, quer backed=%v", got, c.backed)
			}
		})
	}
}

func TestReflections(t *testing.T) {
	canary := "cachepoison-abc.example.com"
	h := hdr("Location", "https://"+canary+"/next", "Content-Type", "text/html")
	body := `<link rel=canonical href="https://` + canary + `/">`
	got := reflections(canary, body, h)
	if len(got) != 2 {
		t.Fatalf("reflections = %v", got)
	}
	var inBody, inHdr bool
	for _, g := range got {
		if g == "corpo" {
			inBody = true
		}
		if g == "header Location" {
			inHdr = true
		}
	}
	if !inBody || !inHdr {
		t.Errorf("faltou corpo/header: %v", got)
	}
	if len(reflections(canary, "sem nada", hdr("X", "y"))) != 0 {
		t.Error("sem reflexo deveria ser vazio")
	}
}

func TestClassify(t *testing.T) {
	refl := []string{"corpo"}
	if v := classify(nil, cacheView{}, false); v.kind != "" {
		t.Errorf("sem reflexo -> vazio, got %+v", v)
	}
	if v := classify(refl, cacheView{backed: true, reason: "Age: 5"}, true); v.kind != "cache-poisoning" || v.severity != "high" {
		t.Errorf("persistido -> %+v", v)
	}
	if v := classify(refl, cacheView{backed: true, reason: "X-Cache: HIT"}, false); v.kind != "cache-poisoning-likely" || v.severity != "medium" {
		t.Errorf("cacheável sem persistência -> %+v", v)
	}
	if v := classify(refl, cacheView{backed: false}, false); v.kind != "header-reflection" || v.severity != "low" {
		t.Errorf("só reflexo -> %+v", v)
	}
}

func TestBustExtra(t *testing.T) {
	got := bust("https://x.com/p?a=1", "CB123")
	if got != "https://x.com/p?a=1&cb=CB123" {
		t.Errorf("bust = %q", got)
	}
	got2 := bustExtra("https://x.com/p", "CB", "utm_content", "canary.example.com")
	if got2 != "https://x.com/p?cb=CB&utm_content=canary.example.com" {
		t.Errorf("bustExtra = %q", got2)
	}
}

func TestDefaultProbesShape(t *testing.T) {
	ps := defaultProbes()
	if len(ps) < 10 {
		t.Fatalf("poucos probes: %d", len(ps))
	}
	for _, p := range ps {
		if p.header == "" && p.param == "" {
			t.Errorf("probe sem header nem param: %+v", p)
		}
		if p.value == nil || p.value("canary.example.com") == "" {
			t.Errorf("probe %s sem value", p.label())
		}
	}
}
