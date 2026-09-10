package main

import (
	"strings"
	"testing"
)

func TestClteBodyMatchesContentLength(t *testing.T) {
	// o payload canônico exige que os 4 primeiros bytes do corpo sejam
	// exatamente "1\r\nA" — se isso quebrar, o teste de timing perde o
	// sentido (o servidor não vai interpretar como esperado).
	if clteBody[:4] != "1\r\nA" {
		t.Fatalf("clteBody[:4] = %q, want %q", clteBody[:4], "1\r\nA")
	}
}

func TestTeclBodyMatchesContentLength(t *testing.T) {
	if len(teclBody) != 6 {
		t.Fatalf("teclBody tem %d bytes, want 6 (precisa bater com Content-Length: 6)", len(teclBody))
	}
	if !strings.HasPrefix(teclBody, "0\r\n\r\n") {
		t.Fatalf("teclBody = %q, want prefixo do terminador chunked 0\\r\\n\\r\\n", teclBody)
	}
}

func TestCraftRequestWellFormed(t *testing.T) {
	req := craftRequest("example.com", "/x", "4", "chunked", clteBody, true)
	if !strings.HasPrefix(req, "POST /x HTTP/1.1\r\n") {
		t.Fatalf("linha de requisição errada: %q", req[:30])
	}
	if !strings.Contains(req, "Host: example.com\r\n") {
		t.Fatal("falta o header Host")
	}
	if !strings.Contains(req, "Content-Length: 4\r\n") {
		t.Fatal("falta Content-Length correto")
	}
	if !strings.Contains(req, "Transfer-Encoding: chunked\r\n") {
		t.Fatal("falta Transfer-Encoding")
	}
	if !strings.HasSuffix(req, clteBody) {
		t.Fatal("corpo não é o esperado no final da requisição")
	}
	headEnd := strings.Index(req, "\r\n\r\n")
	if headEnd < 0 {
		t.Fatal("falta a linha em branco separando headers do corpo")
	}
}

func TestBaselineRequestHasNoTransferEncoding(t *testing.T) {
	req := baselineRequest("example.com", "/")
	if strings.Contains(req, "Transfer-Encoding") {
		t.Fatal("baseline não deveria ter Transfer-Encoding — é o controle 'normal'")
	}
	if !strings.Contains(req, "Connection: close\r\n") {
		t.Fatal("baseline deveria fechar a conexão (não reaproveitada)")
	}
}

func TestClteAndTeclRequestsKeepAlive(t *testing.T) {
	for _, req := range []string{clteRequest("x.com", "/"), teclRequest("x.com", "/")} {
		if !strings.Contains(req, "Connection: keep-alive\r\n") {
			t.Fatalf("probe deveria manter a conexão aberta (é o que expõe o hang): %q", req[:80])
		}
	}
}
