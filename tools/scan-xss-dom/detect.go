package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// randToken gera um token único por candidato — o nome da propriedade JS
// que o payload seta (window.__rhxss_<token>) muda a cada requisição, pra
// nunca confundir com uma propriedade que já existisse na página por
// coincidência (o mesmo princípio anti-falso-positivo usado no scan-ssrf/
// scan-ssti deste hub: nunca chave num valor fixo previsível).
func randToken() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// domPayload é o vetor clássico de DOM XSS: quebra atributo (aspa simples
// E dupla, cobre os dois casos mais comuns) e tag, e o onerror de uma <img>
// com src inválido dispara SEM precisar de clique nem de interação alguma
// — só o navegador tentando (e falhando) carregar a imagem. Isso é o que
// permite confirmar execução real sem heurística: se window[prop] virar
// true, o navegador EXECUTOU o que veio da URL como código, não só
// refletiu como texto.
func domPayload(token string) string {
	return `'"><img src=x onerror=window.__rhxss_` + token + `=true>`
}

// evalExpr é a expressão avaliada no contexto da página depois da
// navegação — !! pra sempre devolver um bool mesmo se a propriedade nunca
// foi setada (undefined vira false, nunca erro).
func evalExpr(token string) string {
	return `!!window.__rhxss_` + token
}

// withHash devolve base com o payload como fragmento — o motivo real de
// existir uma ferramenta com navegador de verdade: o fragmento NUNCA chega
// no servidor (fica só no navegador), então scan-xss (requisição HTTP
// crua) é estruturalmente incapaz de ver isso — só um navegador
// executando o JS da página revela um app que lê location.hash e insere
// sem sanitizar. Remove um fragmento pré-existente antes de anexar o
// nosso, senão o navegador veria os dois concatenados.
func withHash(base, payload string) string {
	if i := strings.IndexByte(base, '#'); i >= 0 {
		base = base[:i]
	}
	return base + "#" + payload
}

// withQueryParam devolve base com key=payload anexado ao valor existente
// (ou como valor único, se key não existia) — mesmo padrão de
// scan-xss/scan-sqli/scan-ssti. Cobre o caso em que a resposta HTTP
// inicial escapa certo (scan-xss não acharia nada), mas o JS do lado do
// CLIENTE relê location.search/URLSearchParams e insere sem sanitizar —
// só executar o JS revela isso.
func withQueryParam(base, key, payload string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(key, q.Get(key)+payload)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func fmtEvidence(vec, detail string) string {
	return fmt.Sprintf("vetor=%s (%s) — window[prop] virou true depois da navegação: o navegador EXECUTOU o payload como código (onerror da <img> disparou), não só refletiu como texto", vec, detail)
}
