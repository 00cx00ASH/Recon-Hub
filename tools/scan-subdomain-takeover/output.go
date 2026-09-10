package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
)

// event é uma linha do contrato NDJSON do recon-hub.
type event struct {
	Type        string         `json:"type"`
	Level       string         `json:"level,omitempty"`
	Msg         string         `json:"msg,omitempty"`
	Data        map[string]any `json:"data,omitempty"`
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
		e.w.WriteString(prettyLine(ev))
	} else {
		b, _ := json.Marshal(ev)
		e.w.Write(b)
	}
	e.w.WriteByte('\n')
	e.w.Flush()
}

func (e *emitter) progress(msg string, done, total int) {
	e.emit(event{Type: "progress", Msg: msg, Data: map[string]any{
		"pct": pct(done, total), "done": done, "total": total,
	}})
}

func prettyLine(ev event) string {
	switch ev.Type {
	case "finding":
		return fmt.Sprintf("[%s] %s\n        %s", strings.ToUpper(ev.Severity), ev.Title, ev.Evidence)
	case "progress":
		return "  ... " + ev.Msg
	case "done":
		return "done: " + ev.Msg
	default:
		lv := ev.Level
		if lv == "" {
			lv = "info"
		}
		return fmt.Sprintf("[%s] %s", lv, ev.Msg)
	}
}

func pct(a, b int) int {
	if b <= 0 {
		return 0
	}
	if a > b {
		a = b
	}
	return a * 100 / b
}

// --- entrada / parâmetros

func readPayload() payload {
	var p payload
	fi, err := os.Stdin.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) != 0 {
		return p // rodando num terminal: sem stdin
	}
	b, _ := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if s := strings.TrimSpace(string(b)); s != "" {
		_ = json.Unmarshal([]byte(s), &p)
	}
	return p
}

func numParam(m map[string]any, key string) (int, bool) {
	switch v := m[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case string:
		var n int
		if _, err := fmt.Sscan(v, &n); err == nil {
			return n, true
		}
	}
	return 0, false
}

func addSubs(dst map[string]struct{}, v any) {
	split := func(s string) {
		for _, part := range strings.FieldsFunc(s, func(r rune) bool {
			return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
		}) {
			if c := clean(part); c != "" {
				dst[c] = struct{}{}
			}
		}
	}
	switch t := v.(type) {
	case string:
		split(t)
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				split(s)
			}
		}
	}
}

func clean(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "*.")
	if i := strings.IndexAny(s, "/:"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

func orUnknown(s string) string {
	if s == "" {
		return "serviço desconhecido"
	}
	return s
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
