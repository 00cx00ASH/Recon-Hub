package main

import (
	"net/url"
	"regexp"
	"strings"
)

// canary é um host inofensivo e reservado (IANA example.com). Se a resposta
// redireciona pra ele, o parâmetro é um open redirect confirmado — navegar
// pra lá não causa dano.
const defaultCanary = "example.com"

type payloadEntry struct {
	label string // como o payload burla o filtro
	value string // valor injetado no parâmetro
}

// buildPayloads gera os valores de teste para um canary + host alvo.
// targetHost entra nos truques de "host confuso" (whitelisted@canary, sufixo).
func buildPayloads(canary, targetHost string) []payloadEntry {
	if targetHost == "" {
		targetHost = "whitelisted.test"
	}
	tmpl := []struct{ label, raw string }{
		{"absoluto https", "https://" + canary},
		{"absoluto http", "http://" + canary},
		{"sem esquema (//)", "//" + canary},
		{"barra faltando (https:/)", "https:/" + canary},
		{"backslash (/\\)", "/\\" + canary},
		{"backslash duplo", "\\/\\/" + canary},
		{"quatro barras", "////" + canary},
		{"barra + ponto-ponto", "//" + canary + "/%2e%2e"},
		{"encoded //", "%2F%2F" + canary},
		{"tab antes da url", "%09https://" + canary},
		{"newline antes da url", "%0Ahttps://" + canary},
		{"userinfo (@)", "https://" + targetHost + "@" + canary},
		// diferente do userinfo comum acima: aqui o CANARY vem primeiro e o
		// targetHost (parece confiável) depois do "\@" — reproduz uma técnica
		// real de bypass de validação de origem (visto em relatório público
		// contra o wlc/Weblate): parsers que tratam "\" como parte do userinfo
		// (ex: net/url do Go, urllib.parse do Python) resolvem o host pro que
		// vem DEPOIS do "\@" (o alvo, "confiável"), mas outra biblioteca no
		// mesmo processo (ex: urllib3) trata "\" como separador de path e
		// resolve pro que vem ANTES (o canary) — um validador que checa com
		// um parser e requisita/redireciona com outro pode aprovar isso.
		{"backslash antes do @ (confusão de parser)", "https://" + canary + "\\@" + targetHost},
		{"fragmento depois do host", "https://" + canary + "#." + targetHost},
		{"query depois do host", "https://" + canary + "?." + targetHost},
		{"backslash depois do host", "https://" + canary + "\\." + targetHost},
		{"sufixo confuso", "https://" + canary + "/." + targetHost},
		{"whitespace + //", " //" + canary},
		{"carriage return antes da url", "%0Dhttps://" + canary},
		// double-encoded: um filtro que só decodifica uma vez e checa por
		// "//"/"://" cru nunca bate nisso (o valor bruto do parâmetro é só
		// "%252F%252F..."), mas o servidor que decodifica duas vezes (comum
		// quando um proxy/gateway já decodifica uma camada antes de repassar
		// pro app) resolve pro "//" real e redireciona do mesmo jeito.
		{"double-encoded //", "%252F%252F" + canary},
		// múltiplos @: um parser ingênuo que extrai "host" olhando só o
		// PRIMEIRO "@" (em vez do último, como RFC 3986/navegadores fazem)
		// vê targetHost logo no início e aprova — mas o navegador resolve
		// userinfo até o ÚLTIMO "@", host real é o que vem depois dele.
		{"múltiplos @ (parser pega o 1º, navegador pega o último)", "https://" + targetHost + "@" + targetHost + "@" + canary},
		// barra unicode fullwidth (U+FF0F) — alguns proxies/CDNs normalizam
		// esse caractere pra "/" ASCII antes de repassar a URL adiante, mas
		// um filtro de string que só reconhece "/" ASCII nunca vê "//" no
		// valor bruto do parâmetro.
		{"barra unicode fullwidth (／)", "／／" + canary},
	}
	out := make([]payloadEntry, 0, len(tmpl))
	for _, t := range tmpl {
		out = append(out, payloadEntry{t.label, t.raw})
	}
	return out
}

// hostOf extrai o host de uma URL possivelmente meia-boca (backslash,
// protocol-relative, credenciais, porta). "" se não der pra determinar.
func hostOf(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, "\\", "/")
	// desfaz encodings comuns que servidores já normalizam na resposta
	s = strings.ReplaceAll(s, "%252f", "/") // double-encoded primeiro — vira %2f decodificando uma vez a mais
	s = strings.ReplaceAll(s, "%252F", "/")
	s = strings.ReplaceAll(s, "%2f", "/")
	s = strings.ReplaceAll(s, "%2F", "/")
	s = strings.ReplaceAll(s, "／", "/") // barra unicode fullwidth
	if s == "" {
		return ""
	}
	// navegadores colapsam "////host" e "///host" em "//host"
	if strings.HasPrefix(s, "//") {
		s = "//" + strings.TrimLeft(s, "/")
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	h := u.Host
	if h == "" {
		// pode ser "example.com/x" sem esquema nem "//"
		if u.Scheme == "" && !strings.HasPrefix(s, "/") {
			h = strings.SplitN(s, "/", 2)[0]
		}
	}
	if at := strings.LastIndex(h, "@"); at >= 0 {
		h = h[at+1:]
	}
	if c := strings.IndexByte(h, ':'); c >= 0 {
		h = h[:c]
	}
	return strings.ToLower(strings.Trim(h, "."))
}

// redirectsToCanary: o Location de uma resposta 3xx aponta pro canary?
func redirectsToCanary(location, canary string) bool {
	if location == "" {
		return false
	}
	return sameHost(hostOf(location), canary)
}

var (
	metaRefreshRe = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']?refresh["']?[^>]*?url=([^"'>\s;]+)`)
	jsLocationRe  = regexp.MustCompile(`(?i)(?:(?:window|top|self|document)\.)?location(?:\.(?:href|replace|assign))?\s*(?:=|\()\s*["']([^"']+)["']`)
)

// bodyRedirectsToCanary: redirect client-side (meta refresh ou location JS)
// pro canary. Devolve o mecanismo achado.
func bodyRedirectsToCanary(body, canary string) (bool, string) {
	if m := metaRefreshRe.FindStringSubmatch(body); m != nil {
		if sameHost(hostOf(m[1]), canary) {
			return true, "meta refresh"
		}
	}
	for _, m := range jsLocationRe.FindAllStringSubmatch(body, -1) {
		if sameHost(hostOf(m[1]), canary) {
			return true, "location JS"
		}
	}
	return false, ""
}

// sameHost: host == canary ou subdomínio direto do canary.
func sameHost(host, canary string) bool {
	host = strings.ToLower(strings.Trim(host, "."))
	canary = strings.ToLower(strings.Trim(canary, "."))
	if host == "" || canary == "" {
		return false
	}
	return host == canary || strings.HasSuffix(host, "."+canary)
}

// paramNames junta os nomes vindos do param `params` (csv) com a wordlist.
func paramNames(csv string, wordlist []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, p := range strings.FieldsFunc(csv, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}) {
		add(p)
	}
	for _, p := range wordlist {
		add(p)
	}
	return out
}
