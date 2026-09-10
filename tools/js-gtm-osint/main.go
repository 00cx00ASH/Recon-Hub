// js-gtm-osint — OSINT de Google Tag Manager. Acha os GTM/GA/Ads IDs numa
// página, baixa o container gtm.js público de cada GTM-ID e o disseca: tipos de
// tag, tags de HTML customizado (possível injeção/exfil), pixels de terceiros,
// outros IDs de rastreamento e segredos hardcoded. Contrato NDJSON no stdout.
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
		flagGTM    = flag.String("gtm-id", "", "GTM-XXXX direto (pula a extração da página)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/12000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 12000)) * time.Millisecond
	client = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	// GTM ID direto?
	gtmSeen := map[string]bool{}
	var gtmIDs []string
	addGTM := func(id string) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if idRes["GTM"].MatchString(id) && !gtmSeen[id] {
			gtmSeen[id] = true
			gtmIDs = append(gtmIDs, id)
		}
	}
	for _, s := range splitList(firstNonEmpty(*flagGTM, strParam(pl.Params, "gtm_id"), os.Getenv("RECONHUB_PARAM_GTM_ID"))) {
		addGTM(s)
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

	if len(gtmIDs) == 0 && len(pages) == 0 {
		emit(ev{Type: "error", Msg: "informe target (URL) ou params.gtm_id"})
		os.Exit(2)
	}

	// varre as páginas por IDs de rastreamento
	pageIDs := map[string][]string{}
	for _, p := range pages {
		body, err := fetch(p)
		if err != nil {
			emit(ev{Type: "log", Level: "warn", Msg: p + ": " + err.Error()})
			continue
		}
		texts := []string{body}
		for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
			if abs := resolveRef(p, m[1]); abs != "" && strings.Contains(abs, ".js") && len(texts) < 25 {
				if js, e := fetch(abs); e == nil {
					texts = append(texts, js)
				}
			}
		}
		ids := extractTrackingIDs(strings.Join(texts, "\n"))
		for _, fid := range flatIDs(ids) {
			pageIDs[fid] = append(pageIDs[fid], p)
		}
		for _, id := range ids["GTM"] {
			addGTM(id)
		}
		emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%s — IDs: %s", p, strings.Join(orNone(flatIDs(ids)), ", "))})
	}

	for fid := range pageIDs {
		emit(ev{Type: "asset", Kind: "tracking-id", Value: fid})
	}
	if len(pageIDs) > 0 {
		emit(ev{Type: "finding", Severity: "info", FindingType: "tracking-ids-found",
			Title:    fmt.Sprintf("%d ID(s) de rastreamento na(s) página(s)", len(pageIDs)),
			Asset:    firstNonEmpty(pages...),
			Evidence: "IDs: " + strings.Join(sortedKeys(pageIDs), ", "),
			Meta:     map[string]any{"ids": sortedKeys(pageIDs)}})
	}

	if len(gtmIDs) == 0 {
		emit(ev{Type: "done", OK: true, Msg: "nenhum GTM-ID pra dissecar"})
		return
	}

	for _, id := range gtmIDs {
		auditContainer(id)
	}
	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d container(s) GTM, %d finding(s)", len(gtmIDs), finds)})
}

func auditContainer(gtmID string) {
	u := "https://www.googletagmanager.com/gtm.js?id=" + url.QueryEscape(gtmID)
	body, err := fetch(u)
	if err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: "gtm.js " + gtmID + ": " + err.Error()})
		return
	}
	emit(ev{Type: "asset", Kind: "tracking-id", Value: "GTM:" + gtmID})

	c := parseContainer(body)
	if !c.parsed || len(c.Tags) == 0 {
		if len(body) < 4000 || !strings.Contains(body, "google_tag_manager") {
			emit(ev{Type: "finding", Severity: "info", FindingType: "gtm-container-empty",
				Title:    "GTM-ID referenciado mas container vazio/não publicado: " + gtmID,
				Asset:    "GTM:" + gtmID,
				Evidence: fmt.Sprintf("GET %s devolveu %d bytes sem recurso utilizável", u, len(body))})
			return
		}
	}

	counts := c.tagTypeCounts()
	var typeList []string
	for f, n := range counts {
		typeList = append(typeList, fmt.Sprintf("%s×%d", strings.TrimPrefix(f, "__"), n))
	}
	sort.Strings(typeList)
	emit(ev{Type: "finding", Severity: "info", FindingType: "gtm-container-loaded",
		Title: fmt.Sprintf("container GTM %s carregado (v%s): %d tags, %d triggers, %d variáveis",
			gtmID, orDash(c.Version), len(c.Tags), len(c.Predicates), len(c.Macros)),
		Asset:    "GTM:" + gtmID,
		Evidence: "tipos de tag: " + strings.Join(orNone(typeList), ", "),
		Meta: map[string]any{
			"gtm_id": gtmID, "version": c.Version, "tags": len(c.Tags),
			"triggers": len(c.Predicates), "variables": len(c.Macros), "tag_types": counts,
		}})

	// tags de HTML customizado
	var thirdParty []string
	for _, ti := range c.tags() {
		if label, ok := thirdPartyTags[ti.Function]; ok {
			thirdParty = appendUniq(thirdParty, label)
		}
		if ti.Function != "__html" || ti.HTML == "" {
			continue
		}
		sev, ftype := "info", "gtm-custom-html"
		note := "tag de HTML customizado no container (revise: roda no contexto do site)"
		if interesting, why := interestingHTML(ti.HTML); interesting {
			sev, ftype = "medium", "gtm-custom-html-suspicious"
			note = "tag de HTML customizado — " + why
		}
		emit(ev{Type: "finding", Severity: sev, FindingType: ftype,
			Title:    fmt.Sprintf("GTM %s: tag HTML customizado %q", gtmID, orDash(ti.Name)),
			Asset:    "GTM:" + gtmID,
			Evidence: note + " — trecho: " + snippet(ti.HTML, 300),
			Meta:     map[string]any{"gtm_id": gtmID, "tag_name": ti.Name, "html_len": len(ti.HTML)}})
	}
	if len(thirdParty) > 0 {
		sort.Strings(thirdParty)
		emit(ev{Type: "finding", Severity: "info", FindingType: "gtm-third-party-tags",
			Title:    fmt.Sprintf("GTM %s: %d pixel(s)/tag(s) de terceiros", gtmID, len(thirdParty)),
			Asset:    "GTM:" + gtmID,
			Evidence: strings.Join(thirdParty, ", ") + " — rastreiam o usuário; relevante pra privacidade/inventário",
			Meta:     map[string]any{"gtm_id": gtmID, "vendors": thirdParty}})
	}

	// outros IDs de rastreamento embutidos no container
	other := extractTrackingIDs(body)
	var otherFlat []string
	for _, fid := range flatIDs(other) {
		if fid == "GTM:"+gtmID {
			continue
		}
		otherFlat = append(otherFlat, fid)
		emit(ev{Type: "asset", Kind: "tracking-id", Value: fid})
	}
	if len(otherFlat) > 0 {
		emit(ev{Type: "finding", Severity: "info", FindingType: "gtm-linked-ids",
			Title:    fmt.Sprintf("GTM %s referencia %d outro(s) ID(s) de rastreamento", gtmID, len(otherFlat)),
			Asset:    "GTM:" + gtmID,
			Evidence: strings.Join(otherFlat, ", "),
			Meta:     map[string]any{"gtm_id": gtmID, "linked_ids": otherFlat}})
	}

	// segredos hardcoded no container
	for _, h := range scanContainerSecrets(body) {
		emit(ev{Type: "finding", Severity: h.Severity, FindingType: "gtm-secret-in-container",
			Title:    fmt.Sprintf("GTM %s: possível segredo no container (%s)", gtmID, h.Kind),
			Asset:    "GTM:" + gtmID,
			Evidence: h.Kind + " = " + h.Value + " embutido em uma tag/variável do container",
			Meta:     map[string]any{"gtm_id": gtmID, "kind": h.Kind}})
	}
}

var (
	scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
)

// --- helpers ---

// applyAuth attaches the operator's shared auth context for this program —
// set once via PUT /api/programs/{name}/auth (internal/project.Auth),
// injected by the engine as env vars — to a request, but ONLY when it's
// going to the same host as the job's own target. fetch() below is shared
// between the target's own page and the GTM container it references
// (served from googletagmanager.com) — the host check is what keeps the
// target's session cookie/token from leaking to Google's CDN.
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
	req.Header.Set("User-Agent", "Mozilla/5.0 recon-hub/js-gtm-osint")
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

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func orNone(s []string) []string {
	if len(s) == 0 {
		return []string{"(nenhum)"}
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

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
