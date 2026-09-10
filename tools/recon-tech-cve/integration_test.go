package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanOneEndToEndAgainstFakeOldApache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Write([]byte(`<html><head><meta name="generator" content="WordPress 4.7.1" /></head></html>`))
	}))
	defer srv.Close()

	client := srv.Client()
	dets, matches := scanOne(client, srv.URL)

	if len(dets) < 2 {
		t.Fatalf("esperava detectar apache + wordpress, veio %+v", dets)
	}
	if len(matches) < 2 {
		t.Fatalf("esperava candidatos a CVE pra apache 2.4.41 e wordpress 4.7.1, veio %d: %+v", len(matches), matches)
	}
	products := map[string]bool{}
	for _, m := range matches {
		products[m.Det.Product] = true
	}
	if !products["apache"] || !products["wordpress"] {
		t.Fatalf("esperava match em apache e wordpress, veio %v", products)
	}
}

func TestScanOneEndToEndAgainstFakeUpToDateApp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Write([]byte(`<html><body>app moderno sem generator meta</body></html>`))
	}))
	defer srv.Close()

	client := srv.Client()
	dets, matches := scanOne(client, srv.URL)
	if len(dets) != 1 || dets[0].Product != "nginx" {
		t.Fatalf("esperava só nginx detectado, veio %+v", dets)
	}
	if len(matches) != 0 {
		t.Fatalf("nginx 1.25.3 é bem mais novo que a entrada da tabela (1.21.0) — não deveria dar match: %+v", matches)
	}
}
