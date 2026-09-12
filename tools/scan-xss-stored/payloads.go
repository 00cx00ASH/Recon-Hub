package main

import (
	"crypto/rand"
	"encoding/hex"
)

// randToken gera um token único por candidato — o nome da propriedade JS que o
// payload seta (window.__rhxss_<token>) muda a cada run, pra nunca confundir
// com uma propriedade pré-existente por coincidência (mesmo princípio
// anti-falso-positivo do scan-xss-dom/scan-ssrf/scan-ssti).
func randToken() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// storedPayload é o valor submetido no fluxo de escrita. Quebra atributo (aspa
// simples E dupla) e tag, e o onerror de uma <img> com src inválido dispara sem
// interação — só o navegador tentando carregar a imagem. Idêntico em espírito
// ao domPayload do scan-xss-dom: se window[prop] virar true ao ABRIR A PÁGINA
// DE LEITURA (depois de ter submetido noutra requisição), o valor foi
// PERSISTIDO e executado como código — prova de stored XSS, não reflexo.
func storedPayload(token string) string {
	return `'"><img src=x onerror=window.__rhxss_` + token + `=true>`
}

// evalExpr é avaliada na página de leitura depois da navegação — !! garante
// bool (propriedade nunca setada = undefined = false, nunca erro).
func evalExpr(token string) string {
	return `!!window.__rhxss_` + token
}
