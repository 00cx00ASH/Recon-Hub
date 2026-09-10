// scan-actuator — procura Spring Boot Actuator (e endpoints antigos) expostos
// sem auth: índice, /env, /heapdump (confirma o dump), Jolokia, etc.
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
	w      = bufio.NewWriter(os.Stdout)
	pretty bool
)

func emit(e ev) {
	mu.Lock()
	defer mu.Unlock()
	if pretty {
		switch e.Type {
		case "finding":
			fmt.Fprintf(w, "[%s] %s\n        %s\n", strings.ToUpper(e.Severity), e.Title, e.Evidence)
		case "done":
			fmt.Fprintln(w, "done: "+e.Msg)
		default:
			lv := e.Level
			if lv == "" {
				lv = "info"
			}
			fmt.Fprintf(w, "[%s] %s\n", lv, e.Msg)
		}
	} else {
		b, _ := json.Marshal(e)
		w.Write(b)
		w.WriteByte('\n')
	}
	w.Flush()
}

func main() {
	var (
		flagTarget = flag.String("target", "", "URL base ou host")
		flagHosts  = flag.String("hosts", "", "vários alvos por vírgula/linha")
		flagHostsF = flag.String("hosts-file", "", "arquivo, um alvo por linha")
		flagConc   = flag.Int("concurrency", 0, "workers (0 = param/15)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout (0 = param/8000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer w.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 8000)) * time.Millisecond
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 15)

	seen := map[string]bool{}
	var bases []string
	add := func(s string) {
		if b := normBase(s); b != "" && !seen[b] {
			seen[b] = true
			bases = append(bases, b)
		}
	}
	add(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	for _, s := range splitList(firstNonEmpty(*flagHosts, strParam(pl.Params, "hosts"), os.Getenv("RECONHUB_PARAM_HOSTS"))) {
		add(s)
	}
	if f := firstNonEmpty(*flagHostsF, strParam(pl.Params, "hosts_file"), os.Getenv("RECONHUB_PARAM_HOSTS_FILE")); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			for _, s := range splitList(string(b)) {
				add(s)
			}
		}
	}
	if len(bases) == 0 {
		emit(ev{Type: "error", Msg: "informe target ou params.hosts"})
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

	type task struct{ base, path string }
	var tasks []task
	for _, b := range bases {
		for _, p := range probePaths {
			tasks = append(tasks, task{b, p})
		}
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%d alvo(s) × %d caminho(s) = %d requisições", len(bases), len(probePaths), len(tasks))})

	var (
		wg          sync.WaitGroup
		ch          = make(chan task)
		mu2         sync.Mutex
		done, finds int
	)
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range ch {
				u := t.base + "/" + t.path
				status, ctype, head := probe(client, u)

				mu2.Lock()
				done++
				d := done
				mu2.Unlock()
				if d%40 == 0 || d == len(tasks) {
					emit(ev{Type: "progress", Msg: fmt.Sprintf("%d/%d", d, len(tasks))})
				}

				v, hit := classify(t.path, status, ctype, head)
				if !hit {
					continue
				}
				mu2.Lock()
				finds++
				mu2.Unlock()

				emit(ev{Type: "asset", Kind: "endpoint", Value: u})
				emit(ev{
					Type: "finding", Severity: v.severity, FindingType: v.kind,
					Title:    v.kind + ": " + u,
					Asset:    u,
					Evidence: fmt.Sprintf("GET %s → %d %s — %s", u, status, ctype, v.note),
					Meta:     map[string]any{"status": status, "content_type": ctype, "path": "/" + t.path},
				})
			}
		}()
	}
	for _, t := range tasks {
		ch <- t
	}
	close(ch)
	wg.Wait()

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d alvo(s), %d finding(s)", len(bases), finds)})
}

// applyAuth attaches the operator's shared auth context for this program —
// set once via PUT /api/programs/{name}/auth (internal/project.Auth),
// injected by the engine as env vars — to a request, but ONLY when it's
// going to the same host as the job's own target. Without that check, a
// tool that also talks to an unrelated third party would leak the target's
// session cookie/token to a host it was never meant for.
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

// probe faz um GET e devolve status, content-type e os primeiros 4 KiB do corpo.
func probe(c *http.Client, u string) (status int, ctype, head string) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, "", ""
	}
	req.Header.Set("User-Agent", "recon-hub/scan-actuator")
	req.Header.Set("Accept", "application/json,*/*")
	applyAuth(req)
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Content-Type"), string(b)
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

func normBase(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	return strings.TrimRight(s, "/")
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
