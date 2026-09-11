// Package scopetemplate lets the operator save reusable scope presets —
// out_of_scope patterns (and an optional platform default) they always want
// on a new program — and apply one when creating a program, instead of
// retyping the same boilerplate exclusions every time. Templates never
// define in_scope: that's always specific to the target being onboarded, and
// scope.Registry already refuses an empty in_scope, so nothing can go live
// without the operator explicitly naming what's actually being tested.
package scopetemplate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"reconhub/internal/scope"
)

// Template is a reusable scope preset.
type Template struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Platform    string   `json:"platform,omitempty"`
	OutOfScope  []string `json:"out_of_scope"`
}

// Registry is a concurrency-safe set of templates loaded from disk.
type Registry struct {
	mu   sync.RWMutex
	dir  string
	byID map[string]Template
}

// Load reads every <dir>/*.json template. A missing directory yields an
// empty registry, not an error.
func Load(dir string) (*Registry, error) {
	r := &Registry{dir: dir, byID: map[string]Template{}}
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
			return nil
		}
		return fmt.Errorf("read scope-templates dir: %w", err)
	}
	next := map[string]Template{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(r.dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var t Template
		if err := json.Unmarshal(b, &t); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if t.Name == "" {
			t.Name = strings.TrimSuffix(e.Name(), ".json")
		}
		next[t.Name] = t
	}
	r.mu.Lock()
	r.byID = next
	r.mu.Unlock()
	return nil
}

// List returns all templates sorted by name.
func (r *Registry) List() []Template {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Template, 0, len(r.byID))
	for _, t := range r.byID {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns one template by name.
func (r *Registry) Get(name string) (Template, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.byID[name]
	return t, ok
}

// normalize validates and cleans t in place, ready to write to disk.
func normalize(t *Template) error {
	t.Name = strings.ToLower(strings.TrimSpace(t.Name))
	if !scope.ValidName(t.Name) {
		return fmt.Errorf("nome inválido (use a-z, 0-9, . _ -; até 63 chars)")
	}
	t.OutOfScope = scope.CleanList(t.OutOfScope)
	if len(t.OutOfScope) == 0 {
		return fmt.Errorf("out_of_scope não pode ser vazio — é o único motivo de existir de um template")
	}
	t.Platform = strings.TrimSpace(t.Platform)
	t.Description = strings.TrimSpace(t.Description)
	return nil
}

// Save validates t, writes <dir>/<name>.json and reloads the registry. It
// refuses to overwrite an existing template — use Update for that.
func (r *Registry) Save(t Template) error {
	if err := normalize(&t); err != nil {
		return err
	}
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(r.dir, t.Name+".json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("já existe um template %q", t.Name)
	}
	b, _ := json.MarshalIndent(t, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return r.Reload()
}

// Update overwrites an existing template. Refuses to "update" one that
// doesn't exist yet — use Save for that.
func (r *Registry) Update(name string, t Template) error {
	name = strings.ToLower(strings.TrimSpace(name))
	path := filepath.Join(r.dir, name+".json")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("template %q não existe", name)
	}
	t.Name = name
	if err := normalize(&t); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(t, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return r.Reload()
}

// Delete removes a template definition and reloads the registry. It never
// touches any program that was created from this template in the past —
// applying a template only copies its patterns once, at creation time.
func (r *Registry) Delete(name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	path := filepath.Join(r.dir, name+".json")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("template %q não existe", name)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return r.Reload()
}
