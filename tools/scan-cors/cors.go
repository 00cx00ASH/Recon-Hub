package main

import (
	"net/http"
	"strings"
)

// origin is one CORS test case.
type origin struct {
	value string
	label string // como o filtro é burlado
}

// testOrigins builds the attacker origins to try against a target host.
func testOrigins(host string) []origin {
	host = strings.ToLower(strings.TrimPrefix(host, "www."))
	reg := regDomain(host)
	os := []origin{
		{"https://evil.example", "origem totalmente estranha"},
		{"null", "origem null (sandbox/iframe/redirect)"},
		{"https://" + host + ".evil.example", "sufixo — <alvo>.evil.example"},
		{"https://evil" + host, "prefixo colado — evil<alvo>"},
		{"https://" + strings.TrimSuffix(host, "."+reg) + "-evil." + reg, "hífen no subdomínio"},
		{"https://not-" + host, "prefixo not-"},
		{"http://" + host, "downgrade pra http"},
		{"https://sub.random-" + reg, "subdomínio arbitrário do domínio registrável"},
	}
	if reg != host {
		os = append(os, origin{"https://attacker." + reg, "qualquer subdomínio (attacker.<reg>)"})
	}
	return os
}

// verdict from a single Origin probe.
type verdict struct {
	kind     string
	severity string
	note     string
}

// analyze inspects the CORS response headers for a probe sent with sentOrigin.
func analyze(sentOrigin string, h http.Header, targetHost string) verdict {
	acao := strings.TrimSpace(h.Get("Access-Control-Allow-Origin"))
	acac := strings.EqualFold(strings.TrimSpace(h.Get("Access-Control-Allow-Credentials")), "true")
	if acao == "" {
		return verdict{}
	}
	reflected := strings.EqualFold(acao, sentOrigin)
	isNull := strings.EqualFold(acao, "null")
	isStar := acao == "*"

	switch {
	case reflected && sentOrigin != "null" && acac:
		return verdict{"cors-reflect-credentials", "critical",
			"a resposta reflete a origem do atacante em ACAO E manda Access-Control-Allow-Credentials: true — leitura autenticada cross-origin"}
	case isNull && acac:
		return verdict{"cors-null-origin", "high",
			"ACAO: null + credentials: true — qualquer página consegue origem 'null' (sandbox iframe, redirect) e lê dados autenticados"}
	case reflected && sentOrigin != "null":
		return verdict{"cors-reflect-origin", "medium",
			"a resposta reflete a origem do atacante em ACAO (sem credentials) — vaza dados que não dependem de cookie/sessão"}
	case isNull:
		return verdict{"cors-null-origin", "medium",
			"ACAO: null aceito (sem credentials)"}
	case isStar && acac:
		return verdict{"cors-wildcard-credentials", "high",
			"ACAO: * junto com credentials: true — inválido pelo spec, mas alguns clientes/servidores honram"}
	}
	return verdict{}
}

// baselineWildcard classifies the no-Origin / benign response.
func baselineWildcard(h http.Header) verdict {
	acao := strings.TrimSpace(h.Get("Access-Control-Allow-Origin"))
	acac := strings.EqualFold(strings.TrimSpace(h.Get("Access-Control-Allow-Credentials")), "true")
	if acao == "*" {
		if acac {
			return verdict{"cors-wildcard-credentials", "high", "ACAO: * com credentials: true no baseline"}
		}
		return verdict{"cors-wildcard", "low", "ACAO: * — leitura cross-origin liberada (ok pra API pública; problema se servir dados privados)"}
	}
	return verdict{}
}

// regDomain: last two labels (or three for co.uk-style).
func regDomain(host string) string {
	l := strings.Split(strings.Trim(host, "."), ".")
	if len(l) <= 2 {
		return host
	}
	second := map[string]bool{"co": true, "com": true, "org": true, "net": true, "gov": true, "edu": true, "ac": true}
	if second[l[len(l)-2]] && len(l) >= 3 {
		return strings.Join(l[len(l)-3:], ".")
	}
	return strings.Join(l[len(l)-2:], ".")
}
