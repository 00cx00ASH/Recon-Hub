// recon-passive-enum — enumeração passiva de subdomínios de várias fontes
// gratuitas (crt.sh, certspotter, hackertarget, alienvault OTX, anubis/jldc,
// rapiddns, wayback). Cada fonte degrada sozinha; o que sobrar é mesclado,
// deduplicado e validado no escopo do domínio. Emite `asset` kind=subdomain.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
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
	Type  string `json:"type"`
	Level string `json:"level,omitempty"`
	Msg   string `json:"msg,omitempty"`
	Kind  string `json:"kind,omitempty"`
	Value string `json:"value,omitempty"`
	OK    bool   `json:"ok,omitempty"`
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
		case "asset":
			fmt.Fprintln(w, "  "+e.Value)
		case "done":
			fmt.Fprintln(w, "done: "+e.Msg)
		case "error":
			fmt.Fprintln(w, "erro: "+e.Msg)
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
		flagDomain  = flag.String("domain", "", "domínio raiz")
		flagSources = flag.String("sources", "", "csv de fontes a usar (default: todas)")
		flagResolve = flag.Bool("resolve", false, "manter só os hosts que resolvem em DNS")
		flagMax     = flag.Int("max", 0, "teto de subdomínios emitidos (0 = param/20000)")
		flagTOms    = flag.Int("timeout-ms", 0, "timeout por fonte (0 = param/25000)")
		flagPretty  = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer w.Flush()

	pl := readPayload()
	root := cleanRoot(firstNonEmpty(pl.Target, *flagDomain, os.Getenv("RECONHUB_TARGET")))
	if root == "" || !strings.Contains(root, ".") {
		emit(ev{Type: "error", Msg: "informe um domínio raiz (ex exemplo.com)"})
		os.Exit(2)
	}
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 25000)) * time.Millisecond
	maxOut := pick(*flagMax, intParam(pl.Params, "max"), 20000)
	doResolve := *flagResolve || boolParam(pl.Params, "resolve")
	wantSources := parseSourceList(firstNonEmpty(*flagSources, strParam(pl.Params, "sources"), os.Getenv("RECONHUB_PARAM_SOURCES")))

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:    20,
			IdleConnTimeout: 30 * time.Second,
			DialContext:     (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	srcs := allSources()
	var used []source
	for _, s := range srcs {
		if wantSources == nil || wantSources[s.name] {
			used = append(used, s)
		}
	}
	if len(used) == 0 {
		emit(ev{Type: "error", Msg: "nenhuma fonte válida em 'sources' — opções: " + strings.Join(sourceNames(srcs), ", ")})
		os.Exit(2)
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("domínio %s — %d fonte(s): %s", root, len(used), strings.Join(sourceNames(used), ", "))})

	type res struct {
		name  string
		hosts []string
		err   error
	}
	results := make(chan res, len(used))
	var wg sync.WaitGroup
	for _, s := range used {
		wg.Add(1)
		go func(s source) {
			defer wg.Done()
			hs, err := s.fetch(client, root)
			results <- res{s.name, hs, err}
		}(s)
	}
	go func() { wg.Wait(); close(results) }()

	merged := map[string]map[string]bool{} // host -> set of sources
	perSource := map[string]int{}
	var okSources, failSources int
	for r := range results {
		if r.err != nil {
			failSources++
			emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf("fonte %s falhou: %v", r.name, r.err)})
			continue
		}
		okSources++
		n := 0
		for _, raw := range r.hosts {
			h := normalizeHost(raw, root)
			if h == "" {
				continue
			}
			if merged[h] == nil {
				merged[h] = map[string]bool{}
			}
			if !merged[h][r.name] {
				merged[h][r.name] = true
				n++
			}
		}
		perSource[r.name] = n
		emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("fonte %s: %d host(s) no escopo", r.name, n)})
	}

	if len(merged) == 0 {
		emit(ev{Type: "log", Level: "warn", Msg: "nenhum subdomínio de nenhuma fonte"})
		emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("0 subdomínios (%d/%d fontes ok)", okSources, len(used))})
		return
	}

	hosts := make([]string, 0, len(merged))
	for h := range merged {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	emitted := 0
	multi := 0
	if doResolve {
		emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("resolvendo %d host(s)…", len(hosts))})
		hosts = resolveFilter(hosts, timeout)
	}
	for _, h := range hosts {
		if emitted >= maxOut {
			emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf("teto de %d atingido — %d hosts não emitidos", maxOut, len(hosts)-emitted)})
			break
		}
		emit(ev{Type: "asset", Kind: "subdomain", Value: h})
		emitted++
		if len(merged[h]) > 1 {
			multi++
		}
		if emitted%200 == 0 {
			emit(ev{Type: "progress", Msg: fmt.Sprintf("%d/%d", emitted, len(hosts))})
		}
	}

	parts := make([]string, 0, len(perSource))
	for _, s := range used {
		if c, ok := perSource[s.name]; ok {
			parts = append(parts, fmt.Sprintf("%s=%d", s.name, c))
		}
	}
	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf(
		"%d subdomínios únicos (%d confirmados por 2+ fontes) · fontes ok %d/%d [%s]",
		emitted, multi, okSources, len(used), strings.Join(parts, " "))})
}

func resolveFilter(hosts []string, timeout time.Duration) []string {
	out := make([]string, 0, len(hosts))
	var mu sync.Mutex
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	r := &net.Resolver{}
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if addrs, err := r.LookupHost(ctx, h); err == nil && len(addrs) > 0 {
				mu.Lock()
				out = append(out, h)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	sort.Strings(out)
	return out
}

// --- helpers ---

func parseSourceList(s string) map[string]bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	m := map[string]bool{}
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		m[strings.ToLower(strings.TrimSpace(p))] = true
	}
	return m
}

func sourceNames(s []source) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = x.name
	}
	return out
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
