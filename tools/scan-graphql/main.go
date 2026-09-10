// scan-graphql — acha endpoints GraphQL, testa introspection, enumera
// queries/mutations/subscriptions, marca campos sensíveis e mutations
// perigosas, e checa misconfigs (GET habilitado/CSRF, batching, sugestão de
// campos, vazamento de stack trace). Contrato NDJSON do recon-hub no stdout.
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
	client *http.Client
	finds  int
)

func emit(e ev) {
	mu.Lock()
	defer mu.Unlock()
	if e.Type == "finding" {
		finds++
	}
	if pretty {
		switch e.Type {
		case "finding":
			fmt.Fprintf(out, "[%s] %s\n        %s\n", strings.ToUpper(e.Severity), e.Title, e.Evidence)
		case "asset":
			fmt.Fprintln(out, "  ["+e.Kind+"] "+e.Value)
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
		flagTarget = flag.String("target", "", "URL base ou endpoint GraphQL")
		flagURLs   = flag.String("urls", "", "várias URLs por vírgula/linha")
		flagURLsF  = flag.String("urls-file", "", "arquivo, uma URL por linha")
		flagNoDisc = flag.Bool("no-discover", false, "não tentar os caminhos comuns (usar o Alvo como está)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/12000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 12000)) * time.Millisecond
	discover := !*flagNoDisc && !boolParam(pl.Params, "no_discover")

	client = &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	var bases []string
	seen := map[string]bool{}
	add := func(s string) {
		if u := normURL(s); u != "" && !seen[u] {
			seen[u] = true
			bases = append(bases, u)
		}
	}
	add(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	for _, s := range splitList(firstNonEmpty(*flagURLs, strParam(pl.Params, "urls"), os.Getenv("RECONHUB_PARAM_URLS"))) {
		add(s)
	}
	if f := firstNonEmpty(*flagURLsF, strParam(pl.Params, "urls_file"), os.Getenv("RECONHUB_PARAM_URLS_FILE")); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			for _, s := range splitList(string(b)) {
				add(s)
			}
		}
	}
	if len(bases) == 0 {
		emit(ev{Type: "error", Msg: "informe target ou params.urls"})
		os.Exit(2)
	}

	found := 0
	for _, base := range bases {
		candidates := []string{base}
		if discover {
			candidates = endpointGuesses(base)
		}
		hitThisBase := false
		tried := map[string]bool{}
		for _, ep := range candidates {
			if tried[ep] {
				continue
			}
			tried[ep] = true
			body, ct, status, err := post(ep, probeQuery)
			if err != nil {
				continue
			}
			if !looksGraphQL(status, ct, body) {
				continue
			}
			hitThisBase = true
			found++
			emit(ev{Type: "asset", Kind: "endpoint", Value: ep})
			emit(ev{Type: "finding", Severity: "info", FindingType: "graphql-endpoint",
				Title:    "endpoint GraphQL: " + ep,
				Asset:    ep,
				Evidence: fmt.Sprintf("responde a query{__typename} (status %d, %s)", status, ct)})
			auditEndpoint(ep)
			if discover {
				break // um endpoint por base já basta
			}
		}
		if !hitThisBase {
			emit(ev{Type: "log", Level: "info", Msg: "nenhum endpoint GraphQL em " + base})
		}
	}

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d endpoint(s) GraphQL, %d finding(s)", found, finds)})
}

func auditEndpoint(ep string) {
	// 1. introspection
	body, _, status, err := post(ep, introspectionQuery)
	if err == nil {
		if s, ok := parseIntrospection(body); ok {
			emit(ev{Type: "finding", Severity: "medium", FindingType: "graphql-introspection-enabled",
				Title: "introspection habilitada: " + ep,
				Asset: ep,
				Evidence: fmt.Sprintf("__schema retornou %d tipos · %d queries · %d mutations · %d subscriptions — o schema inteiro está exposto",
					s.Types, len(s.Queries), len(s.Mutations), len(s.Subscriptions)),
				Meta: map[string]any{
					"types": s.Types, "queries": s.Queries, "mutations": s.Mutations,
					"subscriptions": s.Subscriptions, "query_type": s.QueryType, "mutation_type": s.MutationType,
				}})

			if sens := flagFields(append(append([]string{}, s.Queries...), s.Mutations...), sensitiveNeedles); len(sens) > 0 {
				emit(ev{Type: "finding", Severity: "medium", FindingType: "graphql-sensitive-field",
					Title:    fmt.Sprintf("%d campo(s) de nome sensível no schema: %s", len(sens), hostOf(ep)),
					Asset:    ep,
					Evidence: "revise a autorização de: " + strings.Join(trimList(sens, 20), ", "),
					Meta:     map[string]any{"fields": sens}})
			}
			if dang := flagFields(s.Mutations, dangerousMutationNeedles); len(dang) > 0 {
				emit(ev{Type: "finding", Severity: "medium", FindingType: "graphql-dangerous-mutation",
					Title:    fmt.Sprintf("%d mutation(s) potencialmente perigosa(s): %s", len(dang), hostOf(ep)),
					Asset:    ep,
					Evidence: "confira quem pode chamar: " + strings.Join(trimList(dang, 20), ", "),
					Meta:     map[string]any{"mutations": dang}})
			}
		}
	} else {
		_ = status
	}

	// 2. GET habilitado (vetor de CSRF)
	if gb, _, gs, gerr := get(ep + "?query=%7B__typename%7D"); gerr == nil && checkGetEnabled(gs, gb) {
		emit(ev{Type: "finding", Severity: "low", FindingType: "graphql-get-enabled",
			Title:    "GraphQL aceita queries por GET: " + ep,
			Asset:    ep,
			Evidence: "GET " + ep + "?query={__typename} funciona — habilita CSRF em mutations se não houver token; também facilita cache poisoning"})
	}

	// 3. batching
	if bb, _, bs, berr := post(ep, `[{"query":"{__typename}"},{"query":"{__typename}"}]`); berr == nil && checkBatching(bs, bb) {
		emit(ev{Type: "finding", Severity: "low", FindingType: "graphql-batching-enabled",
			Title:    "batching de queries habilitado: " + ep,
			Asset:    ep,
			Evidence: "o servidor processa um array de operações numa requisição — pode ser usado pra brute force / bypass de rate limit / DoS"})
	}

	// 4. sugestão de campos + vazamento de erro (mesmo com introspection off)
	eb, _, _, eerr := post(ep, `{"query":"query{thisFieldDoesNotExist___xyz}"}`)
	if eerr == nil {
		if checkFieldSuggestions(eb) {
			emit(ev{Type: "finding", Severity: "low", FindingType: "graphql-field-suggestions",
				Title:    "sugestão de campos ativa: " + ep,
				Asset:    ep,
				Evidence: `o erro traz "Did you mean ..." — dá pra reconstruir o schema campo a campo mesmo com introspection desligada`})
		}
		if leak, marker := checkErrorLeak(eb); leak {
			emit(ev{Type: "finding", Severity: "medium", FindingType: "graphql-error-leak",
				Title:    "vazamento em mensagem de erro: " + ep,
				Asset:    ep,
				Evidence: "a resposta de erro contém rastro de implementação (" + marker + ")"})
		}
	}
}

// --- http ---

func post(u, body string) (string, string, int, error) {
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(body))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "recon-hub/scan-graphql")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	resp.Body.Close()
	return string(b), resp.Header.Get("Content-Type"), resp.StatusCode, nil
}

func get(u string) (string, string, int, error) {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "recon-hub/scan-graphql")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	return string(b), resp.Header.Get("Content-Type"), resp.StatusCode, nil
}

// --- helpers ---

func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return u
	}
	return p.Host
}

func trimList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], "…")
}

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
	return s
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
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
