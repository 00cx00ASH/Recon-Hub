// Package registry loads tool manifests from <toolsDir>/<name>/tool.json.
package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Param describes one input a tool accepts.
type Param struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // string | int | bool
	Required bool   `json:"required"`
	Default  any    `json:"default,omitempty"`
	Help     string `json:"help,omitempty"`
}

// Mode is a preset way of running a tool (single target / list / from file…).
// The dashboard shows a mode picker; the chosen mode's name is passed to the
// tool as the "mode" param, and only its Params (plus the mode-agnostic ones)
// are shown.
type Mode struct {
	Name        string   `json:"name"`
	Label       string   `json:"label,omitempty"`
	Help        string   `json:"help,omitempty"`
	Params      []string `json:"params,omitempty"`       // params shown only in this mode
	TargetLabel string   `json:"target_label,omitempty"` // relabel the "Alvo" field
}

// Tool is a parsed tool.json manifest plus resolved runtime fields.
type Tool struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Language string   `json:"language"`
	Category string   `json:"category"`
	Summary  string   `json:"summary"`
	Guide    string   `json:"guide,omitempty"` // 1-2 frases: o que pôr no Alvo, wordlists…
	Exec     []string `json:"exec"`            // argv; {target} and {job_id} are substituted
	Timeout  string   `json:"timeout"`         // Go duration string, e.g. "30m"
	Params   []Param  `json:"params,omitempty"`
	Modes    []Mode   `json:"modes,omitempty"`

	Dir        string        `json:"dir"`
	TimeoutDur time.Duration `json:"-"`
}

// Registry is a concurrency-safe set of tools loaded from disk.
type Registry struct {
	mu    sync.RWMutex
	dir   string
	tools map[string]Tool
}

// Load reads every manifest under dir.
func Load(dir string) (*Registry, error) {
	r := &Registry{dir: dir, tools: map[string]Tool{}}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload re-scans the tools directory, replacing the in-memory set.
func (r *Registry) Reload() error {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return fmt.Errorf("read tools dir: %w", err)
	}
	next := map[string]Tool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		manifest := filepath.Join(r.dir, e.Name(), "tool.json")
		b, err := os.ReadFile(manifest)
		if err != nil {
			continue // directory without a manifest: ignore
		}
		var t Tool
		if err := json.Unmarshal(b, &t); err != nil {
			return fmt.Errorf("%s: %w", manifest, err)
		}
		if t.Name == "" {
			t.Name = e.Name()
		}
		if len(t.Exec) == 0 {
			return fmt.Errorf("%s: \"exec\" is required", manifest)
		}
		t.Dir = filepath.Join(r.dir, e.Name())
		t.TimeoutDur = 30 * time.Minute
		if t.Timeout != "" {
			if d, err := time.ParseDuration(t.Timeout); err == nil {
				t.TimeoutDur = d
			} else {
				return fmt.Errorf("%s: invalid timeout %q: %w", manifest, t.Timeout, err)
			}
		}
		next[t.Name] = t
	}
	r.mu.Lock()
	r.tools = next
	r.mu.Unlock()
	return nil
}

// List returns all tools sorted by name.
func (r *Registry) List() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns one tool by name.
func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}
