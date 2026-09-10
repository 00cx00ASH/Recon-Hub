package main

import (
	"net/http"
	"testing"
)

func TestApplyAuth(t *testing.T) {
	t.Setenv("RECONHUB_TARGET", "https://x.com")
	t.Setenv("RECONHUB_AUTH_COOKIE", "session=abc")
	req, _ := http.NewRequest(http.MethodGet, "https://x.com/import?url=http://169.254.169.254/", nil)
	applyAuth(req)
	if req.Header.Get("Cookie") != "session=abc" {
		t.Errorf("Cookie = %q", req.Header.Get("Cookie"))
	}
}

func TestApplyAuthSkipsInjectedInternalTarget(t *testing.T) {
	// o próprio ponto da ferramenta é fazer o ALVO buscar 169.254.169.254 —
	// a requisição HTTP que o scan-ssrf faz é sempre pro alvo (x.com), nunca
	// diretamente pro host interno, então isso é só a checagem padrão de
	// mesmo-host de qualquer forma; mantém a rede de segurança consistente
	// com as outras ferramentas caso o cliente algum dia siga redirect.
	t.Setenv("RECONHUB_TARGET", "https://x.com")
	t.Setenv("RECONHUB_AUTH_COOKIE", "session=abc")
	req, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	applyAuth(req)
	if req.Header.Get("Cookie") != "" {
		t.Error("não deveria vazar o cookie do alvo pro serviço de metadata")
	}
}
