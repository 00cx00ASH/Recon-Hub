package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// event é uma linha do contrato NDJSON do recon-hub.
type event struct {
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

type emitter struct {
	mu     sync.Mutex
	w      *bufio.Writer
	pretty bool
}

func newEmitter(pretty bool) *emitter {
	return &emitter{w: bufio.NewWriter(os.Stdout), pretty: pretty}
}

func (e *emitter) flush() {
	e.mu.Lock()
	e.w.Flush()
	e.mu.Unlock()
}

func (e *emitter) emit(ev event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pretty {
		switch ev.Type {
		case "finding":
			fmt.Fprintf(e.w, "[%s] %s\n        %s\n", strings.ToUpper(ev.Severity), ev.Title, ev.Evidence)
		case "asset":
			fmt.Fprintln(e.w, "  bucket: "+ev.Value)
		case "done":
			fmt.Fprintln(e.w, "done: "+ev.Msg)
		default:
			lv := ev.Level
			if lv == "" {
				lv = "info"
			}
			fmt.Fprintf(e.w, "[%s] %s\n", lv, ev.Msg)
		}
	} else {
		b, _ := json.Marshal(ev)
		e.w.Write(b)
		e.w.WriteByte('\n')
	}
	e.w.Flush()
}

var flushBeforeExit func()

func exit(code int) {
	if flushBeforeExit != nil {
		flushBeforeExit()
	}
	os.Exit(code)
}

// --- config / entrada ---

type payload struct {
	Target string         `json:"target"`
	Params map[string]any `json:"params"`
}

type config struct {
	urls        []string
	js, maps    bool
	concurrency int
	timeout     time.Duration
	onlyExposed bool
	pretty      bool
}

func parseConfig() config {
	var (
		flagURLs   = flag.String("urls", "", "URLs por vírgula/linha")
		flagTarget = flag.String("target", "", "alvo (fallback do stdin/env)")
		flagConc   = flag.Int("concurrency", 0, "workers do probe (0 = param/10)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout HTTP em ms (0 = param/10000)")
		flagNoJS   = flag.Bool("no-js", false, "não baixar os <script src>")
		flagNoMaps = flag.Bool("no-maps", false, "não tentar source maps")
		flagOnly   = flag.Bool("only-exposed", false, "esconder buckets privados")
		flagURLsF  = flag.String("urls-file", "", "arquivo com uma URL por linha")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()

	pl := readPayload()
	c := config{
		js:          !*flagNoJS,
		maps:        !*flagNoMaps,
		concurrency: *flagConc,
		timeout:     time.Duration(*flagTOms) * time.Millisecond,
		onlyExposed: *flagOnly,
		pretty:      *flagPretty,
	}

	if pl.Params != nil {
		if v, ok := pl.Params["js"].(bool); ok && !*flagNoJS {
			c.js = v
		}
		if v, ok := pl.Params["maps"].(bool); ok && !*flagNoMaps {
			c.maps = v
		}
		if v, ok := pl.Params["only_exposed"].(bool); ok && !*flagOnly {
			c.onlyExposed = v
		}
		if c.concurrency == 0 {
			c.concurrency = intParam(pl.Params, "concurrency")
		}
		if c.timeout == 0 {
			c.timeout = time.Duration(intParam(pl.Params, "timeout_ms")) * time.Millisecond
		}
	}
	if c.concurrency <= 0 {
		c.concurrency = 10
	}
	if c.timeout <= 0 {
		c.timeout = 10 * time.Second
	}

	set := map[string]struct{}{}
	addURL := func(s string) {
		if u := normURL(s); u != "" {
			set[u] = struct{}{}
		}
	}
	for _, s := range splitList(*flagURLs) {
		addURL(s)
	}
	if pl.Params != nil {
		for _, s := range asStrings(pl.Params["urls"]) {
			addURL(s)
		}
	}
	// arquivo: flag > param > env
	urlsFile := firstNonEmpty(*flagURLsF, argStrParam(pl.Params, "urls_file"), os.Getenv("RECONHUB_PARAM_URLS_FILE"))
	if urlsFile != "" {
		for _, s := range readLinesFile(urlsFile) {
			addURL(s)
		}
	}
	if len(set) == 0 {
		addURL(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	}
	for u := range set {
		c.urls = append(c.urls, u)
	}
	return c
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

func asStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return splitList(t)
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func intParam(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		var n int
		fmt.Sscan(v, &n)
		return n
	}
	return 0
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

func argStrParam(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func readLinesFile(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		if s := strings.TrimSpace(ln); s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, s)
		}
	}
	return out
}

func dialer(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout}).DialContext
}
