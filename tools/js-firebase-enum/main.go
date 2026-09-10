// js-firebase-enum — acha o firebaseConfig no HTML/JS de uma página e testa o
// que dá pra ler sem autenticar: Realtime Database (.json?shallow=true),
// Firestore (documents.list em coleções comuns) e Storage (listagem do bucket).
// Só faz leitura. Contrato NDJSON do recon-hub no stdout.
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
		flagConfig = flag.String("config", "", "firebaseConfig colado (JSON ou trecho JS)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/12000)")
		flagNoFS   = flag.Bool("no-firestore", false, "não sondar Firestore")
		flagNoST   = flag.Bool("no-storage", false, "não sondar Storage")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 12000)) * time.Millisecond
	doFS := !*flagNoFS && !boolParam(pl.Params, "no_firestore")
	doST := !*flagNoST && !boolParam(pl.Params, "no_storage")

	client = &http.Client{
		Timeout: timeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: false,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	// origem: config colado, ou uma/mais páginas
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
	pastedCfg := firstNonEmpty(*flagConfig, strParam(pl.Params, "config"), os.Getenv("RECONHUB_PARAM_CONFIG"))

	if pastedCfg == "" && len(pages) == 0 {
		emit(ev{Type: "error", Msg: "informe target (URL da página) ou params.config"})
		os.Exit(2)
	}

	type found struct {
		cfg    fbConfig
		origin string
	}
	var configs []found

	if pastedCfg != "" {
		c := extractConfig(pastedCfg)
		if c.empty() {
			emit(ev{Type: "error", Msg: "não achei chaves de firebaseConfig no texto colado"})
			os.Exit(2)
		}
		configs = append(configs, found{c, "config colado"})
	}
	for _, p := range pages {
		emit(ev{Type: "log", Level: "info", Msg: "lendo " + p})
		c := harvestConfig(p)
		if c.empty() {
			emit(ev{Type: "log", Level: "info", Msg: "  sem firebaseConfig em " + p})
			continue
		}
		configs = append(configs, found{c, p})
	}
	if len(configs) == 0 {
		emit(ev{Type: "done", OK: true, Msg: "nenhum firebaseConfig encontrado"})
		return
	}

	for _, f := range configs {
		c := f.cfg
		emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf(
			"firebaseConfig em %s — projeto=%q db=%q bucket=%q apiKey=%s",
			f.origin, c.ProjectID, c.DatabaseURL, c.StorageBucket, redactKey(c.APIKey))})
		emit(ev{Type: "finding", Severity: "info", FindingType: "firebase-config-exposed",
			Title:    "firebaseConfig exposto: " + nz(c.ProjectID, f.origin),
			Asset:    nz(c.ProjectID, f.origin),
			Evidence: "config do Firebase embutido no cliente em " + f.origin + " (esperado, mas mapeia o projeto e habilita as sondagens abaixo)",
			Meta: map[string]any{
				"origin": f.origin, "project_id": c.ProjectID, "database_url": c.DatabaseURL,
				"storage_bucket": c.StorageBucket, "auth_domain": c.AuthDomain, "app_id": c.AppID,
			}})

		probeRTDB(c)
		if doFS && c.ProjectID != "" && c.APIKey != "" {
			probeFirestore(c)
		}
		if doST && c.StorageBucket != "" {
			probeStorage(c)
		}
	}

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d config(s), %d finding(s)", len(configs), finds)})
}

func probeRTDB(c fbConfig) {
	for _, base := range candidateRTDBs(c) {
		u := base + "/.json?shallow=true"
		status, body, err := get(u, "")
		if err != nil {
			continue
		}
		v := classifyRTDB(status, body)
		switch v.kind {
		case "open-rtdb-read":
			emit(ev{Type: "asset", Kind: "endpoint", Value: base})
			keys := topKeys(body)
			ev2 := ev{Type: "finding", Severity: v.severity, FindingType: v.kind,
				Title:    "Realtime Database com leitura anônima: " + base,
				Asset:    base,
				Evidence: fmt.Sprintf("GET %s → %d. %s", u, status, v.note),
				Meta:     map[string]any{"database_url": base, "http_status": status}}
			if len(keys) > 0 {
				ev2.Evidence += " — chaves de topo: " + strings.Join(trimList(keys, 20), ", ")
				ev2.Meta["top_level_keys"] = keys
			}
			emit(ev2)
			return // um endpoint que responde já basta
		case "rtdb-locked":
			emit(ev{Type: "asset", Kind: "endpoint", Value: base})
			emit(ev{Type: "finding", Severity: "info", FindingType: "rtdb-locked",
				Title:    "Realtime Database existe (regras fechadas): " + base,
				Asset:    base,
				Evidence: fmt.Sprintf("GET %s → %d, %s", u, status, v.note)})
			return
		}
	}
}

func probeFirestore(c fbConfig) {
	anyLocked := false
	for _, coll := range firestoreCollections {
		u := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s?pageSize=1&key=%s",
			url.PathEscape(c.ProjectID), url.PathEscape(coll), url.QueryEscape(c.APIKey))
		status, body, err := get(u, "")
		if err != nil {
			continue
		}
		kind, sev, note := classifyFirestore(status, body)
		switch kind {
		case "open-firestore-read":
			emit(ev{Type: "asset", Kind: "endpoint", Value: "firestore:" + c.ProjectID + "/" + coll})
			emit(ev{Type: "finding", Severity: sev, FindingType: "open-firestore-read",
				Title:    fmt.Sprintf("Firestore com leitura anônima: %s/%s", c.ProjectID, coll),
				Asset:    "firestore:" + c.ProjectID + "/" + coll,
				Evidence: fmt.Sprintf("GET documents/%s → %d. %s", coll, status, note),
				Meta:     map[string]any{"project_id": c.ProjectID, "collection": coll, "http_status": status}})
		case "firestore-locked":
			anyLocked = true
		}
	}
	if anyLocked {
		emit(ev{Type: "finding", Severity: "info", FindingType: "firestore-locked",
			Title:    "Firestore presente com regras fechadas: " + c.ProjectID,
			Asset:    "firestore:" + c.ProjectID,
			Evidence: "as coleções testadas responderam PERMISSION_DENIED (bom sinal)"})
	}
}

func probeStorage(c fbConfig) {
	u := "https://firebasestorage.googleapis.com/v0/b/" + url.PathEscape(c.StorageBucket) + "/o?maxResults=10"
	status, body, err := get(u, "")
	if err != nil {
		return
	}
	kind, sev, note := classifyStorage(status, body)
	switch kind {
	case "open-storage-list":
		emit(ev{Type: "asset", Kind: "endpoint", Value: "gs://" + c.StorageBucket})
		n := strings.Count(body, "\"name\"")
		emit(ev{Type: "finding", Severity: sev, FindingType: "open-storage-list",
			Title:    "Storage bucket lista objetos anonimamente: " + c.StorageBucket,
			Asset:    "gs://" + c.StorageBucket,
			Evidence: fmt.Sprintf("GET %s → %d. %s (~%d objeto(s) na 1ª página)", u, status, note, n),
			Meta:     map[string]any{"bucket": c.StorageBucket, "http_status": status}})
	case "storage-locked":
		emit(ev{Type: "finding", Severity: "info", FindingType: "storage-locked",
			Title:    "Storage bucket existe (regras fechadas): " + c.StorageBucket,
			Asset:    "gs://" + c.StorageBucket,
			Evidence: fmt.Sprintf("GET %s → %d, %s", u, status, note)})
	}
}

// harvestConfig fetches the page + its <script src> and merges any config found.
func harvestConfig(pageURL string) fbConfig {
	var cfg fbConfig
	body, err := fetch(pageURL)
	if err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: "  " + pageURL + ": " + err.Error()})
		return cfg
	}
	cfg.merge(extractConfig(body))
	n := 0
	for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		if cfg.APIKey != "" && cfg.ProjectID != "" && (cfg.DatabaseURL != "" || cfg.StorageBucket != "") {
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
		if js, err := fetch(abs); err == nil {
			cfg.merge(extractConfig(js))
		}
	}
	return cfg
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

// --- http ---

func fetch(u string) (string, error) {
	_, body, err := get(u, "text/html,application/javascript,*/*")
	return body, err
}

// applyAuth attaches the operator's shared auth context for this program —
// set once via PUT /api/programs/{name}/auth (internal/project.Auth),
// injected by the engine as env vars — to a request, but ONLY when it's
// going to the same host as the job's own target. get() below is shared
// between fetching the target's own page/JS and probing the discovered
// Firebase project's RTDB/Firestore endpoints — the host check is what
// keeps the target's session cookie/token from leaking to Google's hosts.
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

func get(u, accept string) (int, string, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "recon-hub/js-firebase-enum")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	applyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 && accept != "" && strings.HasPrefix(accept, "text/html") {
		return resp.StatusCode, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, string(b), nil
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

// topKeys pulls the top-level object keys from a shallow RTDB JSON response.
func topKeys(body string) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &m) != nil {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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

func nz(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func redactKey(k string) string {
	if k == "" {
		return "(nenhuma)"
	}
	if len(k) <= 8 {
		return "***"
	}
	return k[:4] + "…" + k[len(k)-2:]
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

func trimList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], "…")
}
