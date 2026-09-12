// scan-bruteforce-check — confirma AUSÊNCIA de rate limiting/lockout num
// endpoint de login (ou OTP) enviando um número pequeno e travado de
// tentativas com credencial errada contra uma conta de TESTE descartável do
// próprio operador. Nunca é uma força bruta de verdade: número de tentativas
// tem teto rígido, intervalo mínimo entre elas é garantido, e o scan para no
// primeiro sinal de proteção (429, Retry-After, CAPTCHA/lockout na resposta,
// mudança de status/tamanho, ou aumento de latência). Contrato NDJSON do
// recon-hub no stdout.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
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

// hardMaxAttempts is a non-negotiable ceiling — even if params/flags ask for
// more, this tool never sends more than this many wrong-credential requests
// in one run. It exists to test for the ABSENCE of a protection, not to
// actually exhaust one; a real attacker's brute force runs into the
// thousands, this stays a two-digit PoC.
const hardMaxAttempts = 10

// minDelayMs is the floor on the interval between attempts, regardless of
// what's requested — keeps this from ever looking like (or behaving like) a
// flood against the target.
const minDelayMs = 150

func main() {
	var (
		flagTarget      = flag.String("target", "", "URL do endpoint de login/OTP (POST)")
		flagUsername    = flag.String("username", "", "usuário/e-mail da conta de TESTE descartável (nunca a conta principal do operador)")
		flagUsernameF   = flag.String("username-field", "", "nome do campo de usuário no body (default: username)")
		flagPasswordF   = flag.String("password-field", "", "nome do campo de senha/código no body (default: password)")
		flagContentType = flag.String("content-type", "", "json ou form (default: json)")
		flagExtraFields = flag.String("extra-fields", "", `JSON com campos estáticos extras do body, ex: {"grant_type":"password"}`)
		flagAttempts    = flag.Int("attempts", 0, "quantas tentativas de senha errada enviar (0 = param/5, teto rígido 10)")
		flagDelayMs     = flag.Int("delay-ms", 0, "intervalo entre tentativas em ms (0 = param/400, piso 150)")
		flagLenTolPct   = flag.Float64("length-tolerance-pct", 0, "tolerância de variação de tamanho do corpo, em %% (0 = 25)")
		flagLatencyMult = flag.Float64("latency-mult", 0, "quantas vezes a latência da 1ª tentativa conta como escalada (0 = 3)")
		flagTOms        = flag.Int("timeout-ms", 0, "timeout por requisição (0 = param/10000)")
		flagPretty      = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 10000)) * time.Millisecond
	delayMs := pick(*flagDelayMs, intParam(pl.Params, "delay_ms"), 400)
	if delayMs < minDelayMs {
		delayMs = minDelayMs
	}
	attempts := pick(*flagAttempts, intParam(pl.Params, "attempts"), 5)
	if attempts > hardMaxAttempts {
		attempts = hardMaxAttempts
	}
	if attempts < 2 {
		attempts = 2 // menos de 2 tentativas não dá pra observar nem status estável, nem drift
	}
	lengthTolPct := *flagLenTolPct
	if lengthTolPct <= 0 {
		lengthTolPct = pickF(floatParam(pl.Params, "length_tolerance_pct"), 25)
	}
	latencyMult := *flagLatencyMult
	if latencyMult <= 0 {
		latencyMult = pickF(floatParam(pl.Params, "latency_mult"), 3)
	}

	target := normURL(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	username := firstNonEmpty(*flagUsername, strParam(pl.Params, "username"), os.Getenv("RECONHUB_PARAM_USERNAME"))
	usernameField := firstNonEmpty(*flagUsernameF, strParam(pl.Params, "username_field"), os.Getenv("RECONHUB_PARAM_USERNAME_FIELD"), "username")
	passwordField := firstNonEmpty(*flagPasswordF, strParam(pl.Params, "password_field"), os.Getenv("RECONHUB_PARAM_PASSWORD_FIELD"), "password")
	contentType := strings.ToLower(firstNonEmpty(*flagContentType, strParam(pl.Params, "content_type"), os.Getenv("RECONHUB_PARAM_CONTENT_TYPE"), "json"))
	extraFieldsRaw := firstNonEmpty(*flagExtraFields, strParam(pl.Params, "extra_fields"), os.Getenv("RECONHUB_PARAM_EXTRA_FIELDS"))

	if target == "" {
		emit(ev{Type: "error", Msg: "informe target (URL do endpoint de login/OTP)"})
		os.Exit(2)
	}
	if username == "" {
		emit(ev{Type: "error", Msg: "informe params.username — a conta de TESTE descartável usada pra tentar as senhas erradas (NUNCA use a conta principal do operador: se o endpoint tiver lockout de verdade, essa conta pode ficar bloqueada)"})
		os.Exit(2)
	}
	extraFields := map[string]string{}
	if extraFieldsRaw != "" {
		if err := json.Unmarshal([]byte(extraFieldsRaw), &extraFields); err != nil {
			emit(ev{Type: "error", Msg: "params.extra_fields não é um JSON válido de string->string: " + err.Error()})
			os.Exit(2)
		}
	}
	if contentType != "json" && contentType != "form" {
		emit(ev{Type: "error", Msg: "params.content_type precisa ser 'json' ou 'form', veio: " + contentType})
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

	emit(ev{Type: "asset", Kind: "endpoint", Value: target})
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("até %d tentativas de credencial errada contra %s (conta de teste %q), intervalo de %dms — para no 1º sinal de proteção", attempts, target, username, delayMs)})

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var results []attemptResult
	var v verdict
	for i := 1; i <= attempts; i++ {
		if i > 1 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
		wrongPassword := fmt.Sprintf("wrong-%d-%d", i, rng.Intn(1_000_000))
		r, err := attempt(client, target, usernameField, passwordField, username, wrongPassword, contentType, extraFields, i)
		if err != nil {
			emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf("tentativa %d falhou (rede): %s — parando", i, err.Error())})
			break
		}
		results = append(results, r)
		emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("tentativa %d: status %d, %d bytes, %dms", i, r.status, r.length, r.latencyMs)})
		v = classifyAttempts(results, lengthTolPct, latencyMult)
		if v.blocked {
			emit(ev{Type: "log", Level: "info", Msg: "proteção detectada — parando o scan: " + v.reason})
			break
		}
	}

	if len(results) == 0 {
		emit(ev{Type: "error", Msg: "nenhuma tentativa completou (falha de rede/conexão) — nada pra concluir"})
		os.Exit(1)
	}

	if !v.blocked {
		emit(ev{
			Type: "finding", Severity: "medium", FindingType: "missing-rate-limiting",
			Title:    "Sem rate limiting/lockout perceptível em " + target,
			Asset:    target,
			Evidence: fmt.Sprintf("%d tentativas seguidas de credencial errada (conta de teste %q) receberam tratamento idêntico (status %d em todas, tamanho de corpo estável, sem CAPTCHA/429/Retry-After/mensagem de bloqueio, sem aumento de latência) — nenhum sinal de proteção contra força bruta apareceu no intervalo testado.", len(results), username, results[0].status),
			Meta: map[string]any{
				"attempts": len(results), "status": results[0].status,
				"length": results[0].length, "delay_ms": delayMs,
			},
		})
	}

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d tentativa(s), bloqueio detectado: %v", len(results), v.blocked)})
}

// attempt sends one wrong-credential POST and returns only derived signals
// (status/length/latency/keyword) — the response body itself is scanned for
// block keywords in-process and then discarded, never stored or emitted.
func attempt(c *http.Client, target, usernameField, passwordField, username, wrongPassword, contentType string, extraFields map[string]string, idx int) (attemptResult, error) {
	body, ct, err := buildBody(usernameField, passwordField, username, wrongPassword, contentType, extraFields)
	if err != nil {
		return attemptResult{}, err
	}
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return attemptResult{}, err
	}
	req.Header.Set("User-Agent", "recon-hub/scan-bruteforce-check")
	req.Header.Set("Content-Type", ct)

	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return attemptResult{}, err
	}
	defer resp.Body.Close()
	latency := time.Since(start).Milliseconds()

	limited := io.LimitReader(resp.Body, 64<<10)
	raw, _ := io.ReadAll(limited)
	n, _ := io.Copy(io.Discard, resp.Body) // drena o resto sem guardar

	return attemptResult{
		idx:          idx,
		status:       resp.StatusCode,
		length:       len(raw) + int(n),
		latencyMs:    latency,
		retryAfter:   resp.Header.Get("Retry-After") != "",
		blockKeyword: findBlockKeyword(strings.ToLower(string(raw))),
	}, nil
}

func buildBody(usernameField, passwordField, username, password, contentType string, extraFields map[string]string) (body []byte, ct string, err error) {
	switch contentType {
	case "form":
		v := url.Values{}
		v.Set(usernameField, username)
		v.Set(passwordField, password)
		for k, val := range extraFields {
			v.Set(k, val)
		}
		return []byte(v.Encode()), "application/x-www-form-urlencoded", nil
	default: // json
		m := map[string]any{usernameField: username, passwordField: password}
		for k, val := range extraFields {
			m[k] = val
		}
		b, err := json.Marshal(m)
		return b, "application/json", err
	}
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

func floatParam(m map[string]any, k string) float64 {
	switch v := m[k].(type) {
	case float64:
		return v
	case string:
		n, _ := strconv.ParseFloat(v, 64)
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

func pickF(vs ...float64) float64 {
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
