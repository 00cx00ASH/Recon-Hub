// scan-idor — compara a resposta do MESMO endpoint pedida com DUAS sessões
// diferentes (as próprias contas de teste do operador) pra confirmar IDOR
// horizontal: a sessão A consegue ler o recurso que pertence à sessão B (ou
// vice-versa)? Confirma comparando a resposta "cruzada" contra o baseline
// legítimo do dono de verdade (mesmo status 2xx + tamanho de corpo dentro da
// tolerância) — nunca lê nem guarda o corpo da resposta, só status+tamanho,
// então não há PII de um usuário real armazenada no finding. Contrato
// NDJSON do recon-hub no stdout.
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
		flagTarget  = flag.String("target", "", "URL do recurso da sessão A (ex: .../orders/1001)")
		flagURLB    = flag.String("url-b", "", "URL do MESMO endpoint pro recurso da sessão B (ex: .../orders/1002)")
		flagCookieA = flag.String("cookie-a", "", "Cookie da sessão A")
		flagBearerA = flag.String("bearer-a", "", "Bearer token da sessão A")
		flagCookieB = flag.String("cookie-b", "", "Cookie da sessão B")
		flagBearerB = flag.String("bearer-b", "", "Bearer token da sessão B")
		flagTol     = flag.Int("tolerance-pct", 0, "tolerância de diferença de tamanho de corpo, em % (0 = param/15)")
		flagTOms    = flag.Int("timeout-ms", 0, "timeout por requisição (0 = param/10000)")
		flagPretty  = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 10000)) * time.Millisecond
	tolerance := pick(*flagTol, intParam(pl.Params, "tolerance_pct"), 15)

	urlA := normURL(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	urlB := normURL(firstNonEmpty(*flagURLB, strParam(pl.Params, "url_b"), os.Getenv("RECONHUB_PARAM_URL_B")))
	if urlA == "" || urlB == "" {
		emit(ev{Type: "error", Msg: "informe target (recurso da sessão A) e params.url_b (o MESMO endpoint pro recurso da sessão B)"})
		os.Exit(2)
	}
	// url_b nunca passa pelo enforcement de escopo do servidor (só o
	// target/RECONHUB_TARGET passa) — sem essa trava, um url_b apontando pra
	// outro host contornaria o escopo do programa. IDOR é sempre "mesmo
	// endpoint, ID diferente", então mesmo host é sempre esperado de verdade.
	if hostOf(urlA) != hostOf(urlB) {
		emit(ev{Type: "error", Msg: fmt.Sprintf(
			"target e url_b precisam ser do MESMO host (%s ≠ %s) — scan-idor testa o mesmo endpoint com dois IDs, não hosts diferentes",
			hostOf(urlA), hostOf(urlB))})
		os.Exit(2)
	}

	cookieA := firstNonEmpty(*flagCookieA, strParam(pl.Params, "cookie_a"), os.Getenv("RECONHUB_PARAM_COOKIE_A"))
	bearerA := firstNonEmpty(*flagBearerA, strParam(pl.Params, "bearer_a"), os.Getenv("RECONHUB_PARAM_BEARER_A"))
	cookieB := firstNonEmpty(*flagCookieB, strParam(pl.Params, "cookie_b"), os.Getenv("RECONHUB_PARAM_COOKIE_B"))
	bearerB := firstNonEmpty(*flagBearerB, strParam(pl.Params, "bearer_b"), os.Getenv("RECONHUB_PARAM_BEARER_B"))
	if cookieA == "" && bearerA == "" {
		emit(ev{Type: "error", Msg: "informe cookie_a ou bearer_a — a sessão A precisa de alguma credencial"})
		os.Exit(2)
	}
	if cookieB == "" && bearerB == "" {
		emit(ev{Type: "error", Msg: "informe cookie_b ou bearer_b — a sessão B precisa de alguma credencial"})
		os.Exit(2)
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	emit(ev{Type: "asset", Kind: "url", Value: urlA})
	emit(ev{Type: "asset", Kind: "url", Value: urlB})
	emit(ev{Type: "log", Level: "info", Msg: "4 requisições: baseline de cada sessão no próprio recurso, e cruzada no recurso da outra"})

	baselineA, err := fetch(client, urlA, cookieA, bearerA)
	if err != nil {
		emit(ev{Type: "error", Msg: "sessão A não conseguiu nem ler o próprio recurso (" + urlA + "): " + err.Error()})
		os.Exit(1)
	}
	baselineB, err := fetch(client, urlB, cookieB, bearerB)
	if err != nil {
		emit(ev{Type: "error", Msg: "sessão B não conseguiu nem ler o próprio recurso (" + urlB + "): " + err.Error()})
		os.Exit(1)
	}
	if baselineA.status < 200 || baselineA.status > 299 {
		emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf("sessão A recebeu status %d no PRÓPRIO recurso — credencial pode estar inválida/expirada", baselineA.status)})
	}
	if baselineB.status < 200 || baselineB.status > 299 {
		emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf("sessão B recebeu status %d no PRÓPRIO recurso — credencial pode estar inválida/expirada", baselineB.status)})
	}

	hits := 0
	crossA, err := fetch(client, urlB, cookieA, bearerA)
	if err == nil {
		if ok, delta := classifyCross(crossA, baselineB, tolerance); ok {
			hits++
			emit(ev{
				Type: "finding", Severity: "high", FindingType: "idor-horizontal",
				Title:    "IDOR: sessão A lê o recurso da sessão B (" + hostOf(urlB) + ")",
				Asset:    urlB,
				Evidence: fmt.Sprintf("sessão A pediu %s (recurso de B) e recebeu status %d, %d bytes — muito parecido com o baseline legítimo de B (status %d, %d bytes; diferença %.1f%%)", urlB, crossA.status, crossA.length, baselineB.status, baselineB.length, delta),
				Meta: map[string]any{
					"cross_status": crossA.status, "cross_length": crossA.length,
					"owner_baseline_status": baselineB.status, "owner_baseline_length": baselineB.length,
					"delta_pct": delta,
				},
			})
		}
	} else {
		emit(ev{Type: "log", Level: "warn", Msg: "requisição cruzada A→B falhou: " + err.Error()})
	}

	crossB, err := fetch(client, urlA, cookieB, bearerB)
	if err == nil {
		if ok, delta := classifyCross(crossB, baselineA, tolerance); ok {
			hits++
			emit(ev{
				Type: "finding", Severity: "high", FindingType: "idor-horizontal",
				Title:    "IDOR: sessão B lê o recurso da sessão A (" + hostOf(urlA) + ")",
				Asset:    urlA,
				Evidence: fmt.Sprintf("sessão B pediu %s (recurso de A) e recebeu status %d, %d bytes — muito parecido com o baseline legítimo de A (status %d, %d bytes; diferença %.1f%%)", urlA, crossB.status, crossB.length, baselineA.status, baselineA.length, delta),
				Meta: map[string]any{
					"cross_status": crossB.status, "cross_length": crossB.length,
					"owner_baseline_status": baselineA.status, "owner_baseline_length": baselineA.length,
					"delta_pct": delta,
				},
			})
		}
	} else {
		emit(ev{Type: "log", Level: "warn", Msg: "requisição cruzada B→A falhou: " + err.Error()})
	}

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("4 requisições, %d IDOR confirmado(s)", hits)})
}

// fetch faz o GET com a credencial dada (cookie tem prioridade se as duas
// vierem preenchidas) e devolve só status+tamanho — nunca o corpo, pra não
// guardar dado real de um usuário no processo/nos eventos.
func fetch(c *http.Client, u, cookie, bearer string) (probe, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return probe{}, err
	}
	req.Header.Set("User-Agent", "recon-hub/scan-idor")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		return probe{}, err
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<20))
	return probe{status: resp.StatusCode, length: int(n)}, nil
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
