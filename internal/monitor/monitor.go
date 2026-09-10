// Package monitor runs pipelines on a schedule, diffs each run's findings
// against the previous run of the same watch, and posts new findings to a
// webhook (Discord-compatible). A watch lives in watches/<name>.json; its
// mutable state (last run id/time) is written back to the same file.
package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"reconhub/internal/pipeline"
	"reconhub/internal/scope"
)

// Watch is one scheduled pipeline plus alerting config.
type Watch struct {
	Name     string `json:"name"`
	Pipeline string `json:"pipeline"`
	Target   string `json:"target"`
	Program  string `json:"program,omitempty"`
	Every    string `json:"every"`             // Go duration, e.g. "6h" (min 1m)
	Webhook  string `json:"webhook,omitempty"` // POST target for new findings
	Enabled  bool   `json:"enabled"`

	// mutable runtime state, persisted back to the file
	LastRunID string     `json:"last_run_id,omitempty"`
	LastRunAt *time.Time `json:"last_run_at,omitempty"`
	LastNew   int        `json:"last_new_findings,omitempty"`
}

func (w Watch) interval() time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(w.Every))
	if err != nil || d < time.Minute {
		return time.Minute
	}
	return d
}

func (w Watch) due(now time.Time) bool {
	if !w.Enabled {
		return false
	}
	if w.LastRunAt == nil {
		return true
	}
	return now.Sub(*w.LastRunAt) >= w.interval()
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidName reports whether s is a usable watch name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// Registry is the set of watches loaded from a directory.
type Registry struct {
	mu   sync.RWMutex
	dir  string
	byID map[string]Watch
}

// Load reads every watches/*.json under dir. A missing dir is not an error.
func Load(dir string) (*Registry, error) {
	r := &Registry{dir: dir, byID: map[string]Watch{}}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload re-scans the directory.
func (r *Registry) Reload() error {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		if os.IsNotExist(err) {
			r.mu.Lock()
			r.byID = map[string]Watch{}
			r.mu.Unlock()
			return nil
		}
		return fmt.Errorf("read watches dir: %w", err)
	}
	next := map[string]Watch{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(r.dir, e.Name()))
		if err != nil {
			return err
		}
		var w Watch
		if err := json.Unmarshal(b, &w); err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
		if w.Name == "" {
			w.Name = strings.TrimSuffix(e.Name(), ".json")
		}
		if w.Pipeline == "" || w.Target == "" {
			return fmt.Errorf("%s: watch precisa de pipeline e target", e.Name())
		}
		next[w.Name] = w
	}
	r.mu.Lock()
	r.byID = next
	r.mu.Unlock()
	return nil
}

// List returns all watches sorted by name.
func (r *Registry) List() []Watch {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Watch, 0, len(r.byID))
	for _, w := range r.byID {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns one watch.
func (r *Registry) Get(name string) (Watch, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	w, ok := r.byID[name]
	return w, ok
}

// Save writes a new watch. Refuses to overwrite an existing one.
func (r *Registry) Save(w Watch) error {
	w.Name = strings.ToLower(strings.TrimSpace(w.Name))
	if !ValidName(w.Name) {
		return fmt.Errorf("nome inválido (a-z, 0-9, . _ -; até 64 chars)")
	}
	if strings.TrimSpace(w.Pipeline) == "" || strings.TrimSpace(w.Target) == "" {
		return fmt.Errorf("pipeline e target são obrigatórios")
	}
	if _, err := time.ParseDuration(strings.TrimSpace(w.Every)); err != nil {
		return fmt.Errorf("'every' inválido (use ex 30m, 6h, 24h)")
	}
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(r.dir, w.Name+".json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("já existe um watch %q", w.Name)
	}
	return r.write(w)
}

// setState persists the mutable fields after a run.
func (r *Registry) setState(name, runID string, at time.Time, newCount int) {
	r.mu.Lock()
	w, ok := r.byID[name]
	if !ok {
		r.mu.Unlock()
		return
	}
	w.LastRunID = runID
	t := at.UTC()
	w.LastRunAt = &t
	w.LastNew = newCount
	r.byID[name] = w
	r.mu.Unlock()
	_ = r.write(w)
}

func (r *Registry) write(w Watch) error {
	b, _ := json.MarshalIndent(w, "", "  ")
	if err := os.WriteFile(filepath.Join(r.dir, w.Name+".json"), append(b, '\n'), 0o644); err != nil {
		return err
	}
	r.mu.Lock()
	r.byID[w.Name] = w
	r.mu.Unlock()
	return nil
}

// --- scheduler ---

// Hub is what the monitor needs from the engine/store.
type Hub interface {
	Pipeline(name string) (pipeline.Pipeline, bool)
	Program(name string) (*scope.Program, error)
	Submit(pl pipeline.Pipeline, target string, prog *scope.Program) (runID string, err error)
	RunStatus(runID string) (status string, terminal bool)
	FindingKeys(runID string) []string
}

// FindingBrief is one new finding in a webhook payload.
type FindingBrief struct {
	Severity string `json:"severity"`
	Type     string `json:"type"`
	Title    string `json:"title"`
	Asset    string `json:"asset,omitempty"`
}

// Monitor schedules watches and alerts on new findings.
type Monitor struct {
	reg  *Registry
	hub  Hub
	post func(url string, body []byte) error // overridable for tests
	tick time.Duration

	mu      sync.Mutex
	running map[string]bool

	// FindingsForBrief is optional: maps a run id to a short list of new
	// findings for the webhook body. Set by the adapter; nil = keys only.
	FindingsForBrief func(runID string, keys []string) []FindingBrief
}

// New builds a Monitor. tick is how often the scheduler wakes (min 15s).
func New(reg *Registry, hub Hub, tick time.Duration) *Monitor {
	if tick < 15*time.Second {
		tick = 30 * time.Second
	}
	return &Monitor{reg: reg, hub: hub, tick: tick, running: map[string]bool{}, post: httpPost}
}

// Run blocks, scheduling watches until ctx is done.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.tick)
	defer t.Stop()
	m.sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.sweep(ctx)
		}
	}
}

func (m *Monitor) sweep(ctx context.Context) {
	now := time.Now()
	for _, w := range m.reg.List() {
		if !w.due(now) {
			continue
		}
		m.mu.Lock()
		if m.running[w.Name] {
			m.mu.Unlock()
			continue
		}
		m.running[w.Name] = true
		m.mu.Unlock()
		go m.fire(ctx, w)
	}
}

// Trigger runs a watch now (used by the "run now" API). Non-blocking.
func (m *Monitor) Trigger(name string) error {
	w, ok := m.reg.Get(name)
	if !ok {
		return fmt.Errorf("watch %q não existe", name)
	}
	m.mu.Lock()
	if m.running[w.Name] {
		m.mu.Unlock()
		return fmt.Errorf("watch %q já está rodando", name)
	}
	m.running[w.Name] = true
	m.mu.Unlock()
	go m.fire(context.Background(), w)
	return nil
}

func (m *Monitor) fire(ctx context.Context, w Watch) {
	defer func() {
		m.mu.Lock()
		delete(m.running, w.Name)
		m.mu.Unlock()
	}()

	pl, ok := m.hub.Pipeline(w.Pipeline)
	if !ok {
		return
	}
	prog, _ := m.hub.Program(w.Program)
	runID, err := m.hub.Submit(pl, w.Target, prog)
	if err != nil {
		return
	}
	prevRun := w.LastRunID

	// poll to completion
	deadline := time.Now().Add(6 * time.Hour)
	for {
		if ctx.Err() != nil {
			return
		}
		status, terminal := m.hub.RunStatus(runID)
		if terminal {
			_ = status
			break
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(5 * time.Second)
	}

	cur := keySet(m.hub.FindingKeys(runID))
	var newKeys []string
	if prevRun == "" {
		for k := range cur {
			newKeys = append(newKeys, k)
		}
	} else {
		prev := keySet(m.hub.FindingKeys(prevRun))
		for k := range cur {
			if !prev[k] {
				newKeys = append(newKeys, k)
			}
		}
	}
	sort.Strings(newKeys)
	m.reg.setState(w.Name, runID, time.Now(), len(newKeys))

	if len(newKeys) == 0 || w.Webhook == "" {
		return
	}
	var brief []FindingBrief
	if m.FindingsForBrief != nil {
		brief = m.FindingsForBrief(runID, newKeys)
	}
	body := buildPayload(w, runID, len(newKeys), brief)
	_ = m.post(w.Webhook, body)
}

func buildPayload(w Watch, runID string, n int, brief []FindingBrief) []byte {
	var sb strings.Builder
	fmt.Fprintf(&sb, "**recon-hub** · watch `%s` · %d finding(s) novo(s)\n", w.Name, n)
	fmt.Fprintf(&sb, "pipeline `%s` → `%s`", w.Pipeline, w.Target)
	if w.Program != "" {
		fmt.Fprintf(&sb, " (escopo %s)", w.Program)
	}
	sb.WriteByte('\n')
	max := len(brief)
	if max > 20 {
		max = 20
	}
	for _, f := range brief[:max] {
		fmt.Fprintf(&sb, "• [%s] %s", strings.ToUpper(f.Severity), f.Title)
		if f.Asset != "" {
			fmt.Fprintf(&sb, " — %s", f.Asset)
		}
		sb.WriteByte('\n')
	}
	if len(brief) > max {
		fmt.Fprintf(&sb, "… e mais %d\n", len(brief)-max)
	}

	payload := map[string]any{
		"content":      sb.String(), // Discord reads this
		"watch":        w.Name,
		"pipeline":     w.Pipeline,
		"target":       w.Target,
		"program":      w.Program,
		"run_id":       runID,
		"new_findings": n,
		"findings":     brief,
		"generated_at": time.Now().UTC(),
	}
	b, _ := json.Marshal(payload)
	return b
}

func httpPost(url string, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "recon-hub/monitor")
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func keySet(keys []string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}
