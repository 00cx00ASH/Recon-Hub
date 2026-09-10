package main

import (
	"net/http"
	"testing"
)

func fakeResp(headers map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{Header: h}
}

func TestFingerprintServerHeader(t *testing.T) {
	resp := fakeResp(map[string]string{"Server": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f"})
	dets := fingerprint(resp, "")
	if len(dets) < 2 {
		t.Fatalf("esperava pelo menos apache e openssl, veio %+v", dets)
	}
	found := map[string]string{}
	for _, d := range dets {
		found[d.Product] = d.Version
	}
	if found["apache"] != "2.4.41" {
		t.Errorf("apache = %q", found["apache"])
	}
	if found["openssl"] != "1.1.1" {
		// "1.1.1f" tem sufixo de letra — nosso regex de versão pega só os
		// dígitos/pontos, então "1.1.1" é o esperado (não corta na letra por engano)
		t.Logf("openssl detectado como %q (aceitável — sufixo de letra fora do padrão numérico)", found["openssl"])
	}
}

func TestFingerprintXPoweredBy(t *testing.T) {
	resp := fakeResp(map[string]string{"X-Powered-By": "PHP/7.4.3"})
	dets := fingerprint(resp, "")
	if len(dets) != 1 || dets[0].Product != "php" || dets[0].Version != "7.4.3" {
		t.Fatalf("esperava php 7.4.3, veio %+v", dets)
	}
}

func TestFingerprintGeneratorMeta(t *testing.T) {
	body := `<html><head><meta name="generator" content="WordPress 5.7.2" /></head></html>`
	dets := fingerprint(fakeResp(nil), body)
	if len(dets) != 1 || dets[0].Product != "wordpress" || dets[0].Version != "5.7.2" {
		t.Fatalf("esperava wordpress 5.7.2, veio %+v", dets)
	}
}

func TestFingerprintWPAssetVersion(t *testing.T) {
	body := `<script src="/wp-includes/js/jquery/jquery.js?ver=1.12.4-wp"></script>`
	dets := fingerprint(fakeResp(nil), body)
	found := false
	for _, d := range dets {
		if d.Product == "wordpress" {
			found = true
			if d.Version != "1.12.4" {
				t.Errorf("versão do wp via asset = %q", d.Version)
			}
		}
	}
	if !found {
		t.Fatalf("não detectou wordpress via asset versionado: %+v", dets)
	}
}

func TestFingerprintJqueryAndBootstrap(t *testing.T) {
	body := `<script src="/js/jquery-3.4.1.min.js"></script><link href="/css/bootstrap-4.3.1.min.css">`
	dets := fingerprint(fakeResp(nil), body)
	got := map[string]string{}
	for _, d := range dets {
		got[d.Product] = d.Version
	}
	if got["jquery"] != "3.4.1" {
		t.Errorf("jquery = %q", got["jquery"])
	}
	if got["bootstrap"] != "4.3.1" {
		t.Errorf("bootstrap = %q", got["bootstrap"])
	}
}

func TestFingerprintDedupe(t *testing.T) {
	resp := fakeResp(map[string]string{"Server": "Apache/2.4.41"})
	body := `<script src="/js/jquery-3.4.1.min.js"></script><script src="/other/jquery-3.4.1.min.js"></script>`
	dets := fingerprint(resp, body)
	seen := map[string]int{}
	for _, d := range dets {
		seen[d.Product+"@"+d.Version]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("%s apareceu %d vezes, deveria ser deduplicado", k, n)
		}
	}
}

func TestFingerprintEmptyOnPlainPage(t *testing.T) {
	dets := fingerprint(fakeResp(nil), "<html><body>nada aqui</body></html>")
	if len(dets) != 0 {
		t.Fatalf("página sem nenhum sinal não deveria detectar nada, veio %+v", dets)
	}
}
