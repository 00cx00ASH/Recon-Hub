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

// WebhookType selects the payload shape POSTed to Watch.Webhook. The zero
// value (WebhookDiscord) is what every watch created before this field
// existed already gets — no migration needed.
const (
	WebhookDiscord  = "discord"
	WebhookSlack    = "slack"
	WebhookTelegram = "telegram"
	WebhookGeneric  = "generic"
)

// ValidWebhookType reports whether t is a type the API should accept ("" is
// valid — it means "discord", the default).
func ValidWebhookType(t string) bool {
	switch t {
	case "", WebhookDiscord, WebhookSlack, WebhookTelegram, WebhookGeneric:
		return true
	}
	return false
}

// Watch is one scheduled pipeline plus alerting config.
type Watch struct {
	Name     string `json:"name"`
	Pipeline string `json:"pipeline"`
	Target   string `json:"target"`
	Program  string `json:"program,omitempty"`
	Every    string `json:"every"`             // Go duration, e.g. "6h" (min 1m)
	Webhook  string `json:"webhook,omitempty"` // POST target for new findings
	// WebhookType picks the payload shape: "discord" (default), "slack",
	// "telegram", or "generic". For Telegram there's no separate chat-id
	// field — embed it in the webhook URL itself, e.g.
	// https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>, so Watch
	// keeps a single URL field regardless of provider.
	WebhookType string `json:"webhook_type,omitempty"`
	Enabled     bool   `json:"enabled"`

	// mutable runtime state, persisted back to the file
	LastRunID string     `json:"last_run_id,omitempty"`
	LastRunAt *time.Time `json:"last_run_at,omitempty"`
	LastNew   int        `json:"last_new_findings,omitempty"`
	// LastNewJS/LastRemovedJS is the diff of JS-derived assets (endpoints,
	// urls) against the previous run of this same watch — a signal that the
	// site shipped new JS even when nothing new showed up as a finding.
	LastNewJS     int `json:"last_new_js,omitempty"`
	LastRemovedJS int `json:"last_removed_js,omitempty"`
	// History is a short rolling window of recent runs' finding totals —
	// enough to tell "this run looks normal" from "this run is way off",
	// see anomaly.go. Capped at anomalyHistoryCap entries.
	History []RunStat `json:"history,omitempty"`
}

// RunStat is one completed run's footprint.
type RunStat struct {
	At    time.Time `json:"at"`
	Total int       `json:"total"` // findings na run inteira (não só os novos)
	New   int       `json:"new"`
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

// setState persists the mutable fields after a run, including the rolling
// history anomaly detection reads.
func (r *Registry) setState(name, runID string, at time.Time, newCount, total, newJS, removedJS int) {
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
	w.LastNewJS = newJS
	w.LastRemovedJS = removedJS
	w.History = append(w.History, RunStat{At: t, Total: total, New: newCount})
	if len(w.History) > anomalyHistoryCap {
		w.History = w.History[len(w.History)-anomalyHistoryCap:]
	}
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
	// JSAssets returns the JS-derived asset values (kind url/endpoint — what
	// js-hunter and friends extract from a bundle) discovered in a run. Used
	// to flag "the site's JS changed since last time" even when nothing new
	// showed up as a finding — a new endpoint often means new code shipped,
	// which is worth a look on its own.
	JSAssets(runID string) []string
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
	anomaly := detectAnomaly(w.History, len(cur))

	curJS := keySet(m.hub.JSAssets(runID))
	var newJS, removedJS int
	if prevRun != "" {
		prevJS := keySet(m.hub.JSAssets(prevRun))
		for a := range curJS {
			if !prevJS[a] {
				newJS++
			}
		}
		for a := range prevJS {
			if !curJS[a] {
				removedJS++
			}
		}
	}
	m.reg.setState(w.Name, runID, time.Now(), len(newKeys), len(cur), newJS, removedJS)

	if (len(newKeys) == 0 && !anomaly.Detected && newJS == 0) || w.Webhook == "" {
		return
	}
	var brief []FindingBrief
	if m.FindingsForBrief != nil {
		brief = m.FindingsForBrief(runID, newKeys)
	}
	body := buildPayload(w, runID, len(newKeys), brief, anomaly, newJS, removedJS)
	_ = m.post(w.Webhook, body)
}

// renderMessage builds the human-readable notification text, shared across
// every webhook type (only the JSON field it rides in changes).
func renderMessage(w Watch, n int, brief []FindingBrief, anomaly Anomaly, newJS, removedJS int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "**recon-hub** · watch `%s` · %d finding(s) novo(s)\n", w.Name, n)
	fmt.Fprintf(&sb, "pipeline `%s` → `%s`", w.Pipeline, w.Target)
	if w.Program != "" {
		fmt.Fprintf(&sb, " (escopo %s)", w.Program)
	}
	sb.WriteByte('\n')
	if anomaly.Detected {
		fmt.Fprintf(&sb, "⚠️ %s\n", anomaly.Reason)
	}
	if newJS > 0 || removedJS > 0 {
		fmt.Fprintf(&sb, "🧩 JS mudou desde a última run: %d endpoint(s) novo(s), %d removido(s)\n", newJS, removedJS)
	}
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
	return sb.String()
}

// webhookType returns w.WebhookType normalized, defaulting to Discord —
// every watch created before this field existed keeps working unchanged.
func webhookType(w Watch) string {
	t := strings.ToLower(strings.TrimSpace(w.WebhookType))
	if t == "" {
		return WebhookDiscord
	}
	return t
}

// buildPayload shapes the notification for whichever provider Watch.Webhook
// points at. Discord/Slack (and most custom receivers) read a plain
// "content"/"text" field; Telegram's sendMessage only looks at "text" (its
// chat_id travels in the URL itself, see Watch.WebhookType's doc comment).
func buildPayload(w Watch, runID string, n int, brief []FindingBrief, anomaly Anomaly, newJS, removedJS int) []byte {
	msg := renderMessage(w, n, brief, anomaly, newJS, removedJS)

	if webhookType(w) == WebhookTelegram {
		b, _ := json.Marshal(map[string]any{"text": msg, "parse_mode": "Markdown"})
		return b
	}

	payload := map[string]any{
		"watch":        w.Name,
		"pipeline":     w.Pipeline,
		"target":       w.Target,
		"program":      w.Program,
		"run_id":       runID,
		"new_findings": n,
		"findings":     brief,
		"anomaly":      anomaly,
		"js_new":       newJS,
		"js_removed":   removedJS,
		"generated_at": time.Now().UTC(),
	}
	switch webhookType(w) {
	case WebhookSlack:
		payload["text"] = msg
	case WebhookGeneric:
		payload["content"] = msg
		payload["text"] = msg
	default: // discord
		payload["content"] = msg
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
