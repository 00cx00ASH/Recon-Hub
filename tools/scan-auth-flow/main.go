// scan-auth-flow — SSO/OAuth: descobre o authorization_endpoint (via
// /.well-known ou caminhos comuns), testa bypass de validação de
// redirect_uri (confirmado só pelo destino real da resposta, nunca por
// inferência), e inventaria endpoints de metadata SAML encontrados (sem
// tentar validar assinatura XML — isso fica pra ferramenta especializada).
// Contrato NDJSON do recon-hub no stdout.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type payload struct {
	Target string         `json:"target"`
	Params map[string]any `json:"params"`
	JobID  string         `json:"job_id"`
}

type ev struct {
	Type        string         `json:"type"`
	Level       string         `json:"level,omitempty"`
	Msg         string         `json:"msg,omitempty"`
	Kind        string         `json:"kind,omitempty"`
	Value       string         `json:"value,omitempty"`
	Severity    string         `json:"severity,omitempty"`
	FindingType string         `json:"finding_type,omitempty"`
	Title       string         `json:"title,omitempty"`
	Asset       string         `json:"asset,omitempty"`
	Evidence    string         `json:"evidence,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`
	OK          bool           `json:"ok,omitempty"`
}

var (
	mu     sync.Mutex
	out    = bufio.NewWriter(os.Stdout)
	pretty bool
)

func emit(e ev) {
	mu.Lock()
	defer mu.Unlock()
	if pretty {
		switch e.Type {
		case "finding":
			fmt.Fprintf(out, "[%s] %s\n        %s\n", strings.ToUpper(e.Severity), e.Title, e.Evidence)
		case "done":
			fmt.Fprintln(out, "done: "+e.Msg)
		case "error":
			fmt.Fprintln(out, "erro: "+e.Msg)
		default:
			lv := e.Level
			if lv == "" {
				lv = "info"
			}
			fmt.Fprintf(out, "[%s] %s\n", lv, e.Msg)
		}
	} else {
		b, _ := json.Marshal(e)
		out.Write(b)
		out.WriteByte('\n')
	}
	out.Flush()
}

func main() {
	var (
		flagTarget   = flag.String("target", "", "URL base do site (ex https://app.exemplo.com)")
		flagAuthURL  = flag.String("authorize-url", "", "authorization_endpoint já conhecido (pula a descoberta)")
		flagClientID = flag.String("client-id", "", "client_id válido — sem ele o teste de redirect_uri não roda de verdade")
		flagCanary   = flag.String("canary", "", "host canary (default example.com)")
		flagTOms     = flag.Int("timeout-ms", 0, "timeout por requisição (0 = param/10000)")
		flagPretty   = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 10000)) * time.Millisecond
	canary := firstNonEmpty(*flagCanary, strParam(pl.Params, "canary"), os.Getenv("RECONHUB_PARAM_CANARY"), defaultCanary)
	clientID := firstNonEmpty(*flagClientID, strParam(pl.Params, "client_id"), os.Getenv("RECONHUB_PARAM_CLIENT_ID"))
	authorizeURL := firstNonEmpty(*flagAuthURL, strParam(pl.Params, "authorize_url"), os.Getenv("RECONHUB_PARAM_AUTHORIZE_URL"))

	base := normURL(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	if base == "" {
		emit(ev{Type: "error", Msg: "informe target (URL base do site)"})
		os.Exit(2)
	}
	bu, err := url.Parse(base)
	if err != nil {
		emit(ev{Type: "error", Msg: "target inválido: " + base})
		os.Exit(2)
	}

	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	root := bu.Scheme + "://" + bu.Host

	// 1) descoberta do authorization_endpoint, se não veio pronto
	if authorizeURL == "" {
		authorizeURL = discoverAuthorizeEndpoint(client, root)
	}
	if authorizeURL != "" {
		emit(ev{Type: "asset", Kind: "endpoint", Value: authorizeURL})
		emit(ev{Type: "log", Level: "info", Msg: "authorization_endpoint: " + authorizeURL})
	} else {
		emit(ev{Type: "log", Level: "info", Msg: "nenhum authorization_endpoint achado (nem /.well-known, nem os caminhos comuns) — informe params.authorize_url se souber qual é"})
	}

	// 2) teste de bypass de redirect_uri — só roda com endpoint + client_id
	if authorizeURL != "" && clientID != "" {
		testRedirectURIBypass(client, authorizeURL, clientID, canary, bu.Host)
	} else if authorizeURL != "" {
		emit(ev{Type: "log", Level: "warn", Msg: "sem client_id — pulando o teste de bypass de redirect_uri (a maioria dos provedores rejeita antes mesmo de olhar o redirect_uri sem um client_id válido). Pegue um na URL de login do app (?client_id=...) e rode de novo com params.client_id"})
	}

	// 3) inventário de metadata SAML (informativo, sem checagem de vulnerabilidade)
	discoverSAML(client, root)

	emit(ev{Type: "done", OK: true, Msg: "concluído"})
}

func discoverAuthorizeEndpoint(client *http.Client, root string) string {
	for _, p := range wellKnownPaths {
		status, body := get(client, root+p)
		if status == 200 {
			if ep := extractAuthorizationEndpoint(body); ep != "" {
				return ep
			}
		}
	}
	for _, p := range authorizePaths {
		status, _ := get(client, root+p)
		if status == 200 || status == 302 || status == 400 {
			// 400 conta: muitos servers respondem 400 "invalid_client" pra
			// GET sem parâmetros — isso já confirma que o caminho existe.
			return root + p
		}
	}
	return ""
}

func testRedirectURIBypass(client *http.Client, authorizeURL, clientID, canary, clientHost string) {
	payloads := redirectURIBypasses(canary, clientHost)
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("testando %d variação(ões) de redirect_uri contra %s", len(payloads), authorizeURL)})
	for _, p := range payloads {
		u := withRedirectURI(authorizeURL, clientID, p.Value)
		if u == "" {
			continue
		}
		status, headers := getHeaders(client, u)
		if status < 300 || status >= 400 {
			continue
		}
		loc := headers.Get("Location")
		if !redirectsToCanary(loc, canary) {
			continue
		}
		emit(ev{
			Type: "finding", Severity: "critical", FindingType: "oauth-redirect-uri-bypass",
			Title:    "Bypass de validação de redirect_uri no authorization_endpoint",
			Asset:    authorizeURL,
			Evidence: fmt.Sprintf("redirect_uri=%q (%s) — o servidor respondeu %d redirecionando pra %s, o canary. client_id=%s. Isso permite roubar o código de autorização (ou token) de qualquer usuário que clicar num link malicioso — teste com uma conta de teste pra confirmar o impacto completo antes de reportar.", p.Value, p.Label, status, loc, clientID),
			Meta:     map[string]any{"redirect_uri": p.Value, "bypass": p.Label, "client_id": clientID, "location": loc},
		})
		return // 1 bypass confirmado já basta — não precisa continuar testando os outros
	}
	emit(ev{Type: "log", Level: "info", Msg: "nenhum bypass de redirect_uri confirmado nas variações testadas"})
}

func discoverSAML(client *http.Client, root string) {
	for _, p := range samlPaths {
		status, body := get(client, root+p)
		if status != 200 || !looksLikeSAMLMetadata(body) {
			continue
		}
		emit(ev{Type: "asset", Kind: "endpoint", Value: root + p})
		emit(ev{
			Type: "finding", Severity: "info", FindingType: "saml-metadata-exposed",
			Title:    "Metadata SAML exposta em " + p,
			Asset:    root + p,
			Evidence: "Documento com EntityDescriptor/SSODescriptor real (não é uma página de erro genérica). Não é vulnerabilidade por si só — é o ponto de partida pra testar XML Signature Wrapping, replay de asserção e downgrade de binding manualmente ou com uma ferramenta especializada em SAML.",
		})
	}
}

func get(client *http.Client, u string) (status int, body string) {
	status, h, body := getFull(client, u)
	_ = h
	return status, body
}

func getHeaders(client *http.Client, u string) (status int, headers http.Header) {
	status, headers, _ = getFull(client, u)
	return status, headers
}

func getFull(client *http.Client, u string) (status int, headers http.Header, body string) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, ""
	}
	req.Header.Set("User-Agent", "recon-hub/scan-auth-flow")
	applyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return resp.StatusCode, resp.Header, string(b)
}

// applyAuth attaches the operator's shared auth context for this program —
// set once via PUT /api/programs/{name}/auth (internal/project.Auth),
// injected by the engine as env vars — to a request, but ONLY when it's
// going to the same host as the job's own target. Sending it to the
// target's own authorize endpoint is exactly what a real account-takeover
// proof needs (an already-authenticated session completing the flow); the
// host check still stops it from ever reaching the injected redirect_uri
// (we never follow that redirect) or any unrelated third party.
func applyAuth(req *http.Request) {
	if !sameHostAsTarget(req.URL.Host) {
		return
	}
	if v := os.Getenv("RECONHUB_AUTH_COOKIE"); v != "" {
		req.Header.Set("Cookie", v)
	}
	if v := os.Getenv("RECONHUB_AUTH_BEARER"); v != "" {
		req.Header.Set("Authorization", "Bearer "+v)
	}
	if v := os.Getenv("RECONHUB_AUTH_HEADERS"); v != "" {
		var extra map[string]string
		if json.Unmarshal([]byte(v), &extra) == nil {
			for k, val := range extra {
				req.Header.Set(k, val)
			}
		}
	}
}

func sameHostAsTarget(host string) bool {
	t := strings.TrimSpace(os.Getenv("RECONHUB_TARGET"))
	if t == "" {
		return true
	}
	th := t
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		th = u.Host
	}
	strip := func(h string) string {
		if i := strings.LastIndexByte(h, ':'); i >= 0 {
			h = h[:i]
		}
		return strings.ToLower(h)
	}
	return strip(host) == strip(th)
}

// --- helpers ---

func readPayload() payload {
	var p payload
	fi, err := os.Stdin.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) != 0 {
		return p
	}
	b, _ := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if s := strings.TrimSpace(string(b)); s != "" {
		_ = json.Unmarshal([]byte(s), &p)
	}
	return p
}

func normURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	if _, err := url.Parse(s); err != nil {
		return ""
	}
	return s
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

func strParam(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func intParam(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}

func pick(vs ...int) int {
	for _, v := range vs {
		if v > 0 {
			return v
		}
	}
	if len(vs) > 0 {
		return vs[len(vs)-1]
	}
	return 0
}
