package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBypassTechniquesCount(t *testing.T) {
	got := bypassTechniques("https://x.com", "/admin")
	if len(got) != 9 {
		t.Fatalf("esperava 9 técnicas, veio %d", len(got))
	}
	headerBased := 0
	for _, tq := range got {
		if tq.headerBased {
			headerBased++
		}
	}
	if headerBased != 5 {
		t.Fatalf("esperava 5 técnicas baseadas em header (X-Original-URL/X-Rewrite-URL/X-Forwarded-For/X-Forwarded-Host/X-Custom-IP-Authorization), veio %d", headerBased)
	}
}

func TestUpperFirstSegment(t *testing.T) {
	cases := map[string]string{
		"admin":      "Admin",
		"admin/":     "Admin/",
		"a/b/config": "a/b/Config",
		"":           "",
		"a/":         "A/",
	}
	for in, want := range cases {
		if got := upperFirstSegment(in); got != want {
			t.Errorf("upperFirstSegment(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestSameShape(t *testing.T) {
	if !sameShape(200, 1000, 200, 1050) {
		t.Error("mesma status, diferença pequena de tamanho -> deveria ser a mesma forma")
	}
	if sameShape(200, 1000, 200, 1500) {
		t.Error("diferença grande de tamanho -> não deveria ser a mesma forma")
	}
	if sameShape(200, 1000, 403, 1000) {
		t.Error("status diferente nunca é a mesma forma")
	}
}

const genericNotFound = "generic 404 page with some padding text to look realistic"

// adminBlockedServer simula um site real: "/admin" e "/admin/" EXATOS ficam
// atrás de 403; qualquer outro path (incluindo as variações de path-shape
// que as técnicas testam — barra dupla, case alternada, ponto final) cai no
// 404 genérico do site. extra, quando não-nil, decide uma resposta especial
// baseada no request (usado só pelo teste que confirma o bypass de verdade).
func adminBlockedServer(t *testing.T, extra func(*http.Request) (body string, ok bool)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if extra != nil {
			if body, ok := extra(r); ok {
				w.Write([]byte(body))
				return
			}
		}
		switch r.URL.Path {
		case "/admin", "/admin/":
			w.WriteHeader(403)
			w.Write([]byte("forbidden"))
		default:
			w.WriteHeader(404)
			w.Write([]byte(genericNotFound))
		}
	}))
}

// TestTryBypassDetectsHeaderTrick é o cenário real que motivou o comentário
// em bypassTechniques: um app que confia em X-Original-URL pra decidir a
// rota (comum atrás de um reverse proxy que só filtra pelo path da
// requisição, não pelo header) — a raiz "/" sozinha devolve o 404 genérico,
// mas com X-Original-URL: /admin o backend serve o painel de verdade.
func TestTryBypassDetectsHeaderTrick(t *testing.T) {
	srv := adminBlockedServer(t, func(r *http.Request) (string, bool) {
		if r.Header.Get("X-Original-URL") == "/admin" {
			return strings.Repeat("PAINEL ADMIN SECRETO conteudo aqui ", 5), true
		}
		return "", false
	})
	defer srv.Close()
	client = &http.Client{Timeout: 3 * time.Second}

	base := baseline{status: 404, size: len(genericNotFound)}
	ok, technique, note := tryBypass(srv.URL, "/admin", base)
	if !ok || technique != "X-Original-URL" {
		t.Fatalf("esperava bypass confirmado via X-Original-URL, veio ok=%v technique=%q note=%q", ok, technique, note)
	}
}

// TestTryBypassNoFalsePositiveWhenNothingChanges prova que as variações de
// path (barra dupla, case alternada, ponto final) caindo no MESMO 404
// genérico do site — o comportamento real de um site que não trata essas
// variações de propósito nenhum — não confirmam bypass nenhum. E as 5
// técnicas de header, contra um servidor que não olha pra nenhum header
// extra, também não.
func TestTryBypassNoFalsePositiveWhenNothingChanges(t *testing.T) {
	srv := adminBlockedServer(t, nil)
	defer srv.Close()
	client = &http.Client{Timeout: 3 * time.Second}

	base := baseline{status: 404, size: len(genericNotFound)}
	ok, technique, _ := tryBypass(srv.URL, "/admin", base)
	if ok {
		t.Fatalf("nenhuma técnica deveria mudar o comportamento do servidor — não esperava bypass (veio technique=%q)", technique)
	}
}
