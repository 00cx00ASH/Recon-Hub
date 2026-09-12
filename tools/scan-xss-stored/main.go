// scan-xss-stored — XSS armazenado (stored/persistent) confirmado por
// EXECUÇÃO real, em duas fases:
//
//  1. SUBMETE um payload único num fluxo de escrita (form/API) — uma
//     requisição HTTP comum (usa http.Client + proxy.go).
//  2. ABRE a página de LEITURA num navegador de verdade (chromedp/CDP, o
//     mesmo mecanismo do scan-xss-dom) e checa se o payload EXECUTOU lá:
//     o onerror de uma <img> seta window.__rhxss_<token>=true. Se virar
//     true numa navegação SEPARATE (depois do submit, possivelmente em
//     outra sessão), o valor foi PERSISTIDO e executado como código — é o
//     que diferencia stored de reflected, e nenhum scanner de requisição
//     crua consegue ver.
//
// PoC-only: confirma por execução, nunca por heurística de texto; o payload
// seta uma flag inofensiva (nunca exfiltra nem age). A fase de leitura é
// browser-driven (proxy só no allocator local, nunca no sidecar remoto — mesma
// exceção do scan-xss-dom); a fase de submit respeita proxy/rate-limit.
//
// Contrato NDJSON do recon-hub no stdout.
package main

import (
	"bufio"
	"bytes"
	"context"
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
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
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
	out    = bufio.NewWriter(os.Stdout)
	pretty bool
)

func emit(e ev) {
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
		flagSubmitURL = flag.String("submit-url", "", "URL do endpoint de ESCRITA onde o payload é submetido (form/API)")
		flagMethod    = flag.String("submit-method", "", "método do submit (POST/PUT/PATCH) — default POST")
		flagField     = flag.String("submit-field", "", "nome do campo que carrega o payload (ex: comment, bio, name)")
		flagBody      = flag.String("submit-body", "", "corpo JSON base com os outros campos (ex: {\"author\":\"teste\"}) — o campo do payload é somado")
		flagCType     = flag.String("submit-content-type", "", "Content-Type do submit: application/json (default) ou application/x-www-form-urlencoded")
		flagViewURL   = flag.String("view-url", "", "URL da página de LEITURA onde o payload deve aparecer/executar")
		flagCookie    = flag.String("cookie", "", "Cookie da sessão que SUBMETE")
		flagBearer    = flag.String("bearer", "", "Bearer token da sessão que submete")
		flagVCookie   = flag.String("view-cookie", "", "Cookie da sessão que VISUALIZA (default: a de submit) — stored XSS costuma executar numa sessão diferente (ex: admin)")
		flagVBearer   = flag.String("view-bearer", "", "Bearer da sessão que visualiza (default: a de submit)")
		flagChromeURL = flag.String("chrome-url", "", "endpoint CDP remoto (ws://.. ou http://..) — default RECONHUB_CHROME_URL ou navegador local")
		flagChromePth = flag.String("chrome-path", "", "caminho do Chrome/Chromium local")
		flagSettleMs  = flag.Int("settle-ms", 0, "espera após navegar na página de leitura, pro JS assíncrono rodar (0 = param/1200)")
		flagTOms      = flag.Int("timeout-ms", 0, "timeout por requisição/navegação (0 = param/15000)")
		flagPretty    = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 15000)) * time.Millisecond
	settle := time.Duration(pick(*flagSettleMs, intParam(pl.Params, "settle_ms"), 1200)) * time.Millisecond

	submitURL := normURL(firstNonEmpty(*flagSubmitURL, strParam(pl.Params, "submit_url"), pl.Target, os.Getenv("RECONHUB_TARGET")))
	viewURL := normURL(firstNonEmpty(*flagViewURL, strParam(pl.Params, "view_url")))
	field := firstNonEmpty(*flagField, strParam(pl.Params, "submit_field"))
	if submitURL == "" || viewURL == "" || field == "" {
		emit(ev{Type: "error", Msg: "informe submit_url (onde o payload é escrito), view_url (onde ele deve aparecer) e submit_field (o campo que carrega o payload)"})
		os.Exit(2)
	}
	method := strings.ToUpper(firstNonEmpty(*flagMethod, strParam(pl.Params, "submit_method"), "POST"))
	ct := firstNonEmpty(*flagCType, strParam(pl.Params, "submit_content_type"), "application/json")
	cookie := firstNonEmpty(*flagCookie, strParam(pl.Params, "cookie"), os.Getenv("RECONHUB_PARAM_COOKIE"), os.Getenv("RECONHUB_AUTH_COOKIE"))
	bearer := firstNonEmpty(*flagBearer, strParam(pl.Params, "bearer"), os.Getenv("RECONHUB_PARAM_BEARER"), os.Getenv("RECONHUB_AUTH_BEARER"))
	viewCookie := firstNonEmpty(*flagVCookie, strParam(pl.Params, "view_cookie"), cookie)
	viewBearer := firstNonEmpty(*flagVBearer, strParam(pl.Params, "view_bearer"), bearer)

	base := map[string]any{}
	if raw := firstNonEmpty(*flagBody, strParam(pl.Params, "submit_body")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &base); err != nil {
			emit(ev{Type: "error", Msg: "submit_body precisa ser um objeto JSON válido: " + err.Error()})
			os.Exit(2)
		}
	}

	token := randToken()
	p := storedPayload(token)

	// --- fase 1: submeter o payload ---
	status, err := submit(submitURL, method, ct, cookie, bearer, base, field, p, timeout)
	if err != nil {
		emit(ev{Type: "error", Msg: "submit falhou: " + err.Error()})
		os.Exit(1)
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("payload submetido em %s (campo %s, status %d); abrindo a página de leitura no navegador", submitURL, field, status)})
	if status >= 400 {
		emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf("submit retornou %d — pode não ter persistido; checando a página de leitura mesmo assim", status)})
	}

	// --- fase 2: abrir a página de leitura e confirmar execução ---
	allocCtx, allocCancel, mode := buildAllocator(
		firstNonEmpty(*flagChromeURL, strParam(pl.Params, "chrome_url"), os.Getenv("RECONHUB_CHROME_URL")),
		firstNonEmpty(*flagChromePth, strParam(pl.Params, "chrome_path"), os.Getenv("RECONHUB_CHROME_PATH")))
	defer allocCancel()
	emit(ev{Type: "log", Level: "info", Msg: "navegador: " + mode})

	emit(ev{Type: "asset", Kind: "url", Value: viewURL})
	executed, err := confirmOnView(allocCtx, viewURL, token, viewCookie, viewBearer, timeout, settle)
	if err != nil {
		emit(ev{Type: "error", Msg: "navegação na página de leitura falhou: " + err.Error()})
		os.Exit(1)
	}

	if executed {
		emit(ev{
			Type: "finding", Severity: "high", FindingType: "stored-xss",
			Title:    "Stored XSS: payload submetido em " + hostOf(submitURL) + " executa na página de leitura " + hostOf(viewURL),
			Asset:    viewURL,
			Evidence: fmt.Sprintf("submeti um payload único no campo `%s` de %s (%s) e, numa navegação SEPARADA até %s num navegador de verdade, o onerror da <img> injetada DISPAROU (window.__rhxss_%s virou true). O valor foi PERSISTIDO e executado como código numa página/sessão diferente da que submeteu — stored XSS, não reflexo. A flag é inofensiva; a ferramenta não exfiltra nem age além de provar a execução.", field, submitURL, method, viewURL, token),
			Meta: map[string]any{
				"submit_url": submitURL, "submit_field": field, "submit_method": method,
				"view_url": viewURL, "submit_status": status,
				"cross_session": viewCookie != cookie || viewBearer != bearer,
			},
		})
		emit(ev{Type: "done", OK: true, Msg: "1 stored XSS confirmado"})
		return
	}
	emit(ev{Type: "log", Level: "info", Msg: "o payload não executou na página de leitura — não armazenado, escapado, ou a página de leitura não é onde ele aparece"})
	emit(ev{Type: "done", OK: true, Msg: "0 stored XSS confirmado"})
}

// submit faz a requisição de escrita com o payload no campo dado e devolve o
// status. JSON (default) ou form-urlencoded conforme o Content-Type.
func submit(u, method, ct, cookie, bearer string, base map[string]any, field, pld string, timeout time.Duration) (int, error) {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
	}
	applyProxy(transport, timeout)
	client := &http.Client{
		Timeout:   timeout,
		Transport: withBlockRotation(transport, func(msg string) { emit(ev{Type: "log", Level: "info", Msg: msg}) }),
	}

	var body io.Reader
	if strings.Contains(ct, "form-urlencoded") {
		vals := url.Values{}
		for k, v := range base {
			vals.Set(k, fmt.Sprint(v))
		}
		vals.Set(field, pld)
		body = strings.NewReader(vals.Encode())
	} else {
		m := cloneMap(base)
		m[field] = pld
		b, _ := json.Marshal(m)
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "recon-hub/scan-xss-stored")
	req.Header.Set("Content-Type", ct)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, nil
}

// confirmOnView abre uma aba isolada, aplica a sessão de visualização (cookie/
// bearer — stored XSS costuma executar numa sessão diferente da que submeteu),
// navega até viewURL, espera o JS assíncrono e avalia se o payload executou.
func confirmOnView(allocCtx context.Context, viewURL, token, cookie, bearer string, navTimeout, settle time.Duration) (bool, error) {
	tabCtx, cancel := chromedp.NewContext(allocCtx, chromedp.WithErrorf(func(string, ...any) {}))
	defer cancel()
	tabCtx, cancelTO := context.WithTimeout(tabCtx, navTimeout)
	defer cancelTO()

	actions := []chromedp.Action{network.Enable()}
	if hdrs := viewHeaders(bearer); len(hdrs) > 0 {
		actions = append(actions, network.SetExtraHTTPHeaders(hdrs))
	}
	if cks := viewCookieParams(cookie, viewURL); len(cks) > 0 {
		actions = append(actions, network.SetCookies(cks))
	}
	var result bool
	actions = append(actions,
		chromedp.Navigate(viewURL),
		chromedp.Sleep(settle),
		chromedp.Evaluate(evalExpr(token), &result),
	)
	err := chromedp.Run(tabCtx, actions...)
	return result, err
}

func viewHeaders(bearer string) network.Headers {
	if bearer == "" {
		return nil
	}
	return network.Headers{"Authorization": "Bearer " + bearer}
}

func viewCookieParams(raw, viewURL string) []*network.CookieParam {
	var params []*network.CookieParam
	for _, part := range strings.Split(raw, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 || kv[0] == "" {
			continue
		}
		params = append(params, &network.CookieParam{Name: strings.TrimSpace(kv[0]), Value: kv[1], URL: viewURL})
	}
	return params
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil {
		return strings.ToLower(p.Host)
	}
	return ""
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

func cloneMap(m map[string]any) map[string]any {
	c := make(map[string]any, len(m)+1)
	for k, v := range m {
		c[k] = v
	}
	return c
}
