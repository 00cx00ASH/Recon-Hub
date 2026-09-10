package main

import (
	"net/url"
	"regexp"
	"strings"
)

const defaultCanary = "example.com"

// wellKnownPaths — descoberta de configuração OIDC. Quando existe, é a
// fonte mais confiável do authorization_endpoint real (não precisa
// adivinhar caminho).
var wellKnownPaths = []string{
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
}

// authorizePaths — chutes comuns quando não há well-known (ou ele não
// respondeu). Servem só pra achar ALGO que pareça um endpoint de
// autorização; sem um client_id válido, o teste de bypass de redirect_uri
// não roda de verdade (ver main.go).
var authorizePaths = []string{
	"/oauth/authorize", "/oauth2/authorize", "/oauth2/auth", "/connect/authorize",
	"/authorize", "/auth/authorize", "/sso/authorize", "/idp/authorize",
}

// samlPaths — descoberta de metadata SAML. Isso é só um inventário
// (asset), não uma checagem de vulnerabilidade — validar assinatura XML,
// XSW etc. exige manipulação de XML assinado que essa ferramenta
// deliberadamente não tenta automatizar (risco alto de falso positivo/
// negativo sem uma libSAML de verdade).
var samlPaths = []string{
	"/saml/metadata", "/simplesaml/module.php/saml/sp/metadata.php",
	"/simplesaml/saml2/idp/metadata.php", "/adfs/ls/idpinitiatedsignon",
	"/auth/realms/master/protocol/saml/descriptor", "/sso/saml/metadata",
	"/saml2/metadata", "/Shibboleth.sso/Metadata",
}

type bypassPayload struct {
	Label string
	Value string
}

// redirectURIBypasses gera as variações de redirect_uri testadas contra o
// authorization_endpoint. clientDomain é o host do próprio alvo (o domínio
// "legítimo" que uma validação por sufixo/prefixo mal feita pode confundir
// com o canary).
func redirectURIBypasses(canary, clientDomain string) []bypassPayload {
	if clientDomain == "" {
		clientDomain = "client.test"
	}
	tmpl := []struct{ label, raw string }{
		{"host totalmente diferente (sem validação nenhuma)", "https://" + canary},
		{"subdomínio do canary com o domínio do client no meio", "https://" + clientDomain + "." + canary},
		{"canary como subdomínio aparente do client", "https://" + canary + "." + clientDomain + ".evil-proxy.test"},
		{"userinfo (@) antes do canary", "https://" + clientDomain + "@" + canary},
		{"path parecido com o domínio do client", "https://" + canary + "/" + clientDomain},
		{"fragmento depois do canary", "https://" + canary + "#" + clientDomain},
		{"query depois do canary", "https://" + canary + "?" + clientDomain},
		{"downgrade http", "http://" + clientDomain},
		{"barra dupla depois do domínio do client", "https://" + clientDomain + "//" + canary},
		{"ponto final no host do client (bypass de igualdade exata)", "https://" + clientDomain + "."},
	}
	out := make([]bypassPayload, 0, len(tmpl))
	for _, t := range tmpl {
		out = append(out, bypassPayload{t.label, t.raw})
	}
	return out
}

// redirectsToCanary confirma o bypass pelo mesmo critério do
// scan-open-redirect: o Location da resposta aponta de fato pro canary (ou
// subdomínio dele) — nunca só "não deu erro".
func redirectsToCanary(location, canary string) bool {
	if location == "" {
		return false
	}
	h := hostOf(location)
	h = strings.ToLower(strings.Trim(h, "."))
	c := strings.ToLower(strings.Trim(canary, "."))
	return h == c || strings.HasSuffix(h, "."+c)
}

func hostOf(raw string) string {
	s := strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	h := u.Host
	if at := strings.LastIndex(h, "@"); at >= 0 {
		h = h[at+1:]
	}
	if c := strings.IndexByte(h, ':'); c >= 0 {
		h = h[:c]
	}
	return h
}

// withRedirectURI substitui (ou adiciona) redirect_uri e client_id na URL
// de autorização, preservando os demais parâmetros que já estavam lá
// (response_type, scope, state…, caso o operador já tenha passado a URL
// completa copiada do fluxo real).
func withRedirectURI(authorizeURL, clientID, redirectURI string) string {
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	q.Set("redirect_uri", redirectURI)
	if q.Get("response_type") == "" {
		q.Set("response_type", "code")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

var oidcAuthEndpointRe = regexp.MustCompile(`"authorization_endpoint"\s*:\s*"([^"]+)"`)

// extractAuthorizationEndpoint lê o campo authorization_endpoint de um
// corpo de /.well-known/openid-configuration sem precisar de um decoder
// JSON completo com struct — o documento tem dezenas de campos que não
// interessam, só esse.
func extractAuthorizationEndpoint(body string) string {
	if m := oidcAuthEndpointRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}
