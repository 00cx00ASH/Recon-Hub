// scan-privesc — broken function level authorization (access control
// vertical): um endpoint que deveria exigir privilégio ALTO (função de admin)
// responde igual pra uma sessão de MENOR privilégio — ou até anônima? Usa as
// próprias contas de teste do operador (uma baixa, uma alta) e confirma
// comparando a resposta da sessão baixa/anônima contra o baseline LEGÍTIMO da
// sessão alta no mesmo endpoint (mesmo status 2xx + tamanho dentro da
// tolerância). Nunca lê nem guarda o corpo, só status+tamanho — sem dado real
// da função admin no finding. Diferente do scan-idor (horizontal, mesmo nível
// lendo recurso de outro); aqui é um nível de baixo alcançando função de cima.
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
		flagTarget     = flag.String("target", "", "URL da função que deveria exigir privilégio ALTO (ex: .../admin/users)")
		flagCookieLow  = flag.String("cookie-low", "", "Cookie da sessão de MENOR privilégio")
		flagBearerLow  = flag.String("bearer-low", "", "Bearer token da sessão de MENOR privilégio")
		flagCookieHigh = flag.String("cookie-high", "", "Cookie da sessão de MAIOR privilégio (admin) — o baseline")
		flagBearerHigh = flag.String("bearer-high", "", "Bearer token da sessão de MAIOR privilégio (admin)")
		flagAnon       = flag.Bool("test-anon", false, "também testar acesso ANÔNIMO (sem credencial) à função")
		flagTol        = flag.Int("tolerance-pct", 0, "tolerância de diferença de tamanho de corpo, em % (0 = param/15)")
		flagTOms       = flag.Int("timeout-ms", 0, "timeout por requisição (0 = param/10000)")
		flagPretty     = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 10000)) * time.Millisecond
	tolerance := pick(*flagTol, intParam(pl.Params, "tolerance_pct"), 15)
	testAnon := *flagAnon || boolParam(pl.Params, "test_anon")

	target := normURL(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	if target == "" {
		emit(ev{Type: "error", Msg: "informe target — a URL da função administrativa a testar"})
		os.Exit(2)
	}

	cookieLow := firstNonEmpty(*flagCookieLow, strParam(pl.Params, "cookie_low"), os.Getenv("RECONHUB_PARAM_COOKIE_LOW"))
	bearerLow := firstNonEmpty(*flagBearerLow, strParam(pl.Params, "bearer_low"), os.Getenv("RECONHUB_PARAM_BEARER_LOW"))
	cookieHigh := firstNonEmpty(*flagCookieHigh, strParam(pl.Params, "cookie_high"), os.Getenv("RECONHUB_PARAM_COOKIE_HIGH"))
	bearerHigh := firstNonEmpty(*flagBearerHigh, strParam(pl.Params, "bearer_high"), os.Getenv("RECONHUB_PARAM_BEARER_HIGH"))
	if cookieHigh == "" && bearerHigh == "" {
		emit(ev{Type: "error", Msg: "informe cookie_high ou bearer_high — a sessão alta (admin) é o baseline que prova que a função existe e retorna conteúdo real"})
		os.Exit(2)
	}
	if cookieLow == "" && bearerLow == "" && !testAnon {
		emit(ev{Type: "error", Msg: "informe cookie_low/bearer_low (sessão de menor privilégio) e/ou test_anon=true — sem um alvo de menor privilégio não há o que escalar"})
		os.Exit(2)
	}

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

	emit(ev{Type: "asset", Kind: "url", Value: target})

	// baseline: a sessão ALTA tem que conseguir a função — senão não dá pra
	// provar escalada nenhuma (não há "conteúdo admin" de referência).
	baselineHigh, err := fetch(client, target, cookieHigh, bearerHigh)
	if err != nil {
		emit(ev{Type: "error", Msg: "sessão alta não conseguiu acessar a função (" + target + "): " + err.Error()})
		os.Exit(1)
	}
	if baselineHigh.status < 200 || baselineHigh.status > 299 {
		emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf("sessão alta recebeu status %d em %s — credencial admin pode estar inválida, ou a URL não é uma função que a própria admin acessa; sem um baseline 2xx não dá pra confirmar escalada", baselineHigh.status, target)})
		emit(ev{Type: "done", OK: true, Msg: "baseline alto não-2xx — nada a confirmar"})
		return
	}

	hits := 0
	// escalada da sessão BAIXA: recebeu a mesma função que a admin?
	if cookieLow != "" || bearerLow != "" {
		low, err := fetch(client, target, cookieLow, bearerLow)
		if err != nil {
			emit(ev{Type: "log", Level: "warn", Msg: "requisição da sessão baixa falhou: " + err.Error()})
		} else if ok, delta := classifyPrivesc(low, baselineHigh, tolerance); ok {
			hits++
			emit(ev{
				Type: "finding", Severity: "high", FindingType: "access-control-vertical",
				Title:    "Broken function level auth: sessão de menor privilégio acessa função admin (" + hostOf(target) + ")",
				Asset:    target,
				Evidence: fmt.Sprintf("a sessão BAIXA pediu %s e recebeu status %d, %d bytes — estruturalmente igual ao baseline legítimo da sessão ALTA (status %d, %d bytes; diferença %.1f%%). O controle de acesso por função não separou os níveis.", target, low.status, low.length, baselineHigh.status, baselineHigh.length, delta),
				Meta: map[string]any{
					"low_status": low.status, "low_length": low.length,
					"high_baseline_status": baselineHigh.status, "high_baseline_length": baselineHigh.length,
					"delta_pct": delta, "actor": "low-privilege-session",
				},
			})
		} else {
			emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("sessão baixa recebeu status %d em %s — controle de acesso parece funcionar (não bate com o baseline admin)", low.status, target)})
		}
	}

	// acesso ANÔNIMO (sem credencial) à função é pior ainda — critical.
	if testAnon {
		anon, err := fetch(client, target, "", "")
		if err != nil {
			emit(ev{Type: "log", Level: "warn", Msg: "requisição anônima falhou: " + err.Error()})
		} else if ok, delta := classifyPrivesc(anon, baselineHigh, tolerance); ok {
			hits++
			emit(ev{
				Type: "finding", Severity: "critical", FindingType: "access-control-vertical",
				Title:    "Função admin acessível SEM autenticação (" + hostOf(target) + ")",
				Asset:    target,
				Evidence: fmt.Sprintf("uma requisição SEM credencial nenhuma a %s recebeu status %d, %d bytes — igual ao baseline da sessão admin (status %d, %d bytes; diferença %.1f%%). A função administrativa não exige autenticação.", target, anon.status, anon.length, baselineHigh.status, baselineHigh.length, delta),
				Meta: map[string]any{
					"anon_status": anon.status, "anon_length": anon.length,
					"high_baseline_status": baselineHigh.status, "high_baseline_length": baselineHigh.length,
					"delta_pct": delta, "actor": "anonymous",
				},
			})
		} else {
			emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("acesso anônimo recebeu status %d — exige autenticação (ok)", anon.status)})
		}
	}

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d escalada(s) de privilégio vertical confirmada(s)", hits)})
}

// fetch faz o GET com a credencial dada (cookie tem prioridade se as duas
// vierem) e devolve só status+tamanho — nunca o corpo, pra não guardar dado
// real da função admin no processo/nos eventos.
func fetch(c *http.Client, u, cookie, bearer string) (probe, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return probe{}, err
	}
	req.Header.Set("User-Agent", "recon-hub/scan-privesc")
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

func boolParam(m map[string]any, k string) bool {
	switch v := m[k].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	}
	return false
}

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
