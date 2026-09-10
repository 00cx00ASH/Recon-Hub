// js-supabase-probe — acha a URL + a anon key do Supabase no HTML/JS de uma
// página e testa, só com leitura, a API PostgREST: lista as tabelas expostas
// (documento raiz OpenAPI) e checa quais permitem leitura anônima (RLS
// ausente/fraca). Decodifica o JWT pra mostrar role/exp e alerta se for uma
// service_role key no cliente. Contrato NDJSON do recon-hub no stdout.
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
	"regexp"
	"sort"
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
		flagTarget = flag.String("target", "", "URL da página")
		flagURLs   = flag.String("urls", "", "várias URLs por vírgula/linha")
		flagURLsF  = flag.String("urls-file", "", "arquivo, uma URL por linha")
		flagURL    = flag.String("supabase-url", "", "https://<ref>.supabase.co (pula a extração)")
		flagKey    = flag.String("anon-key", "", "anon/service key (JWT)")
		flagMaxT   = flag.Int("max-tables", 0, "teto de tabelas a testar (0 = param/40)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/12000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 12000)) * time.Millisecond
	maxTables := pick(*flagMaxT, intParam(pl.Params, "max_tables"), 40)
	client = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	direct := creds{
		URL: strings.TrimRight(firstNonEmpty(*flagURL, strParam(pl.Params, "supabase_url"), os.Getenv("RECONHUB_PARAM_SUPABASE_URL")), "/"),
		Key: firstNonEmpty(*flagKey, strParam(pl.Params, "anon_key"), os.Getenv("RECONHUB_PARAM_ANON_KEY")),
	}
	if m := reSupaURL.FindStringSubmatch(direct.URL); m != nil {
		direct.Ref = m[1]
	}

	type found struct {
		c      creds
		origin string
	}
	var configs []found
	if !direct.empty() {
		configs = append(configs, found{direct, "parâmetros"})
	}

	var pages []string
	seen := map[string]bool{}
	add := func(s string) {
		if u := normURL(s); u != "" && !seen[u] {
			seen[u] = true
			pages = append(pages, u)
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
	if direct.empty() && len(pages) == 0 {
		emit(ev{Type: "error", Msg: "informe target (URL) ou params.supabase_url + anon_key"})
		os.Exit(2)
	}

	for _, p := range pages {
		emit(ev{Type: "log", Level: "info", Msg: "lendo " + p})
		c := harvest(p)
		if c.empty() {
			emit(ev{Type: "log", Level: "info", Msg: "  sem Supabase em " + p})
			continue
		}
		configs = append(configs, found{c, p})
	}
	if len(configs) == 0 {
		emit(ev{Type: "done", OK: true, Msg: "nenhuma credencial Supabase encontrada"})
		return
	}

	tested := map[string]bool{}
	for _, cfg := range configs {
		if tested[cfg.c.URL+"\x00"+cfg.c.Key] {
			continue
		}
		tested[cfg.c.URL+"\x00"+cfg.c.Key] = true
		probe(cfg.c, cfg.origin, maxTables)
	}
	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d projeto(s), %d finding(s)", len(configs), finds)})
}

func probe(c creds, origin string, maxTables int) {
	role := keyRole(c.Key)
	claims, _ := decodeJWT(c.Key)
	exp := ""
	if v, ok := claims["exp"].(float64); ok {
		exp = time.Unix(int64(v), 0).UTC().Format("2006-01-02")
	}
	emit(ev{Type: "asset", Kind: "endpoint", Value: c.URL})
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("Supabase %s (ref=%s) role=%s exp=%s — origem %s", c.URL, c.Ref, orDash(role), orDash(exp), origin)})

	sev, ft := "info", "supabase-key-exposed"
	note := "anon key do Supabase embutida no cliente (esperado) — habilita as sondagens abaixo"
	if role == "service_role" {
		sev, ft = "critical", "supabase-service-role-key-exposed"
		note = "SERVICE_ROLE key no cliente — ignora TODA a RLS, acesso total de leitura e escrita ao banco"
	}
	emit(ev{Type: "finding", Severity: sev, FindingType: ft,
		Title:    "credencial Supabase exposta: " + orDash(c.Ref),
		Asset:    c.URL,
		Evidence: fmt.Sprintf("role=%s, exp=%s, origem=%s. %s", orDash(role), orDash(exp), origin, note),
		Meta:     map[string]any{"url": c.URL, "ref": c.Ref, "role": role, "exp": exp, "origin": origin}})

	// documento raiz do PostgREST -> lista de tabelas
	root, st, _ := apiGET(c, "/rest/v1/?apikey="+url.QueryEscape(c.Key))
	tables := parseOpenAPITables(root)
	if st != 200 && len(tables) == 0 {
		emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf("/rest/v1/ respondeu %d — sem lista de tabelas", st)})
	} else {
		emit(ev{Type: "finding", Severity: "info", FindingType: "supabase-rest-enumerable",
			Title:    fmt.Sprintf("PostgREST expõe %d tabela(s)/view(s): %s", len(tables), c.Ref),
			Asset:    c.URL,
			Evidence: "o documento raiz OpenAPI lista: " + strings.Join(trimList(tables, 40), ", "),
			Meta:     map[string]any{"url": c.URL, "tables": tables}})
	}

	if len(tables) > maxTables {
		tables = tables[:maxTables]
	}
	var openRead, rls int
	var openTables []string
	for _, tbl := range tables {
		body, status, _ := apiGET(c, "/rest/v1/"+url.PathEscape(tbl)+"?select=*&limit=1&apikey="+url.QueryEscape(c.Key))
		v := classifyTable(status, body)
		switch v.kind {
		case "anon-read":
			openRead++
			openTables = append(openTables, tbl)
			emit(ev{Type: "asset", Kind: "endpoint", Value: c.URL + "/rest/v1/" + tbl})
			emit(ev{Type: "finding", Severity: "high", FindingType: "supabase-anon-table-read",
				Title: fmt.Sprintf("tabela '%s' com leitura anônima: %s", tbl, c.Ref),
				Asset: c.URL + "/rest/v1/" + tbl,
				Evidence: fmt.Sprintf("GET /rest/v1/%s (limit 1) → %d, %d linha(s); colunas: %s. %s",
					tbl, status, v.rows, strings.Join(trimList(v.cols, 20), ", "), v.note),
				Meta: map[string]any{"table": tbl, "columns": v.cols, "http_status": status}})
		case "anon-read-empty":
			openRead++
			emit(ev{Type: "finding", Severity: "medium", FindingType: "supabase-anon-table-read",
				Title:    fmt.Sprintf("tabela '%s' acessível anonimamente (vazia): %s", tbl, c.Ref),
				Asset:    c.URL + "/rest/v1/" + tbl,
				Evidence: fmt.Sprintf("GET /rest/v1/%s → %d, []. %s", tbl, status, v.note)})
		case "rls-enforced":
			rls++
		}
	}
	if rls > 0 {
		emit(ev{Type: "finding", Severity: "info", FindingType: "supabase-rls-enforced",
			Title:    fmt.Sprintf("%d/%d tabela(s) com RLS bloqueando leitura anônima: %s", rls, len(tables), c.Ref),
			Asset:    c.URL,
			Evidence: "as demais tabelas responderam permission denied / código 42501 (configuração correta)"})
	}

	// auth: signups habilitados?
	if body, st, _ := apiGET(c, "/auth/v1/settings?apikey="+url.QueryEscape(c.Key)); st == 200 {
		var s struct {
			DisableSignup     bool                       `json:"disable_signup"`
			External          map[string]json.RawMessage `json:"external"`
			MailerAutoconfirm bool                       `json:"mailer_autoconfirm"`
		}
		if json.Unmarshal([]byte(body), &s) == nil && !s.DisableSignup {
			var providers []string
			for k := range s.External {
				providers = append(providers, k)
			}
			sort.Strings(providers)
			emit(ev{Type: "finding", Severity: "low", FindingType: "supabase-signup-enabled",
				Title: "cadastro de usuários habilitado: " + c.Ref,
				Asset: c.URL,
				Evidence: fmt.Sprintf("/auth/v1/settings: disable_signup=false, autoconfirm=%v, provedores: %s",
					s.MailerAutoconfirm, strings.Join(orNone(providers), ", ")),
				Meta: map[string]any{"autoconfirm": s.MailerAutoconfirm, "providers": providers}})
		}
	}

	msg := fmt.Sprintf("%s: %d tabela(s) com leitura anônima, %d com RLS", c.Ref, openRead, rls)
	if len(openTables) > 0 {
		msg += " — abertas: " + strings.Join(trimList(openTables, 20), ", ")
	}
	emit(ev{Type: "log", Level: "info", Msg: msg})
}

func apiGET(c creds, path string) (string, int, error) {
	req, err := http.NewRequest(http.MethodGet, c.URL+path, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "recon-hub/js-supabase-probe")
	req.Header.Set("apikey", c.Key)
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return string(b), resp.StatusCode, nil
}

func harvest(pageURL string) creds {
	body, err := fetch(pageURL)
	if err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: "  " + pageURL + ": " + err.Error()})
		return creds{}
	}
	c := extractCreds(body)
	n := 0
	for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		if !c.empty() {
			break
		}
		if n >= 30 {
			break
		}
		abs := resolveRef(pageURL, m[1])
		if abs == "" || !strings.Contains(abs, ".js") {
			continue
		}
		n++
		if js, e := fetch(abs); e == nil {
			if cc := extractCreds(js); !cc.empty() {
				c = cc
			} else if c.URL == "" && cc.URL != "" {
				c.URL = cc.URL
			} else if c.Key == "" && cc.Key != "" {
				c.Key = cc.Key
			}
		}
	}
	return c
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

// applyAuth attaches the operator's shared auth context for this program —
// set once via PUT /api/programs/{name}/auth (internal/project.Auth),
// injected by the engine as env vars — to a request, but ONLY when it's
// going to the same host as the job's own target. Deliberately NOT used by
// apiGET's requests: those talk to the discovered Supabase project's own
// PostgREST API with its own anon key, a different origin and auth scheme —
// the target site's session cookie/token has no business going there.
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

// sameHostAsTarget reports whether host matches RECONHUB_TARGET's host
// (port ignored). No RECONHUB_TARGET set (e.g. running outside the hub)
// doesn't block — there's nothing to compare against.
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

func fetch(u string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 recon-hub/js-supabase-probe")
	req.Header.Set("Accept", "text/html,application/javascript,*/*")
	applyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 12<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(b), nil
}

func resolveRef(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return b.ResolveReference(r).String()
}

// --- helpers ---

func readPayload() payload {
	var p payload
	fi, err := os.Stdin.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) != 0 {
		return p
	}
	b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
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

func orDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func orNone(s []string) []string {
	if len(s) == 0 {
		return []string{"(nenhum)"}
	}
	return s
}

func trimList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], "…")
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
