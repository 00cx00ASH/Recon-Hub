// Package scope loads bug-bounty programs from programs/<name>.json and answers
// "is this host in scope?". Pipelines use it to keep a step from scanning hosts
// the program does not cover.
package scope

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Program is one bug-bounty program and its scope.
type Program struct {
	Name       string   `json:"name"`
	Platform   string   `json:"platform,omitempty"` // hackerone | intigriti | ...
	URL        string   `json:"url,omitempty"`
	InScope    []string `json:"in_scope"`               // patterns: "*.example.com", "example.com", "10.0.0.0/8"
	OutOfScope []string `json:"out_of_scope,omitempty"` // takes precedence over in_scope
}

// Host returns the bare hostname for a value that may be a URL or a
// "provider:bucket" style token (returned unchanged when it is not a host).
func Host(value string) string {
	v := strings.TrimSpace(strings.ToLower(value))
	if v == "" {
		return ""
	}
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			v = u.Host
		}
	}
	if i := strings.IndexByte(v, '/'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, ':'); i >= 0 && !strings.Contains(v[i+1:], ".") {
		v = v[:i] // strip :port (but not a "provider:bucket.name")
	}
	return strings.TrimSuffix(v, ".")
}

// Contains reports whether host is in scope: matched by in_scope and not by
// out_of_scope. A program with an empty in_scope matches nothing.
func (p Program) Contains(host string) bool {
	h := Host(host)
	if h == "" {
		return false
	}
	for _, pat := range p.OutOfScope {
		if matchPattern(pat, h) {
			return false
		}
	}
	for _, pat := range p.InScope {
		if matchPattern(pat, h) {
			return true
		}
	}
	return false
}

// matchPattern supports:
//
//	example.com     exact host
//	*.example.com   example.com and any subdomain
//	.example.com    any subdomain (not the apex)
func matchPattern(pattern, host string) bool {
	pattern = cleanPattern(pattern)
	switch {
	case pattern == "":
		return false
	case strings.HasPrefix(pattern, "*."):
		root := pattern[2:]
		return host == root || strings.HasSuffix(host, "."+root)
	case strings.HasPrefix(pattern, "."):
		return strings.HasSuffix(host, pattern)
	default:
		return host == pattern
	}
}

// Registry is a concurrency-safe set of programs loaded from disk.
type Registry struct {
	mu   sync.RWMutex
	dir  string
	byID map[string]Program
}

// Load reads every programs/*.json under dir. A missing directory yields an
// empty registry, not an error.
func Load(dir string) (*Registry, error) {
	r := &Registry{dir: dir, byID: map[string]Program{}}
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
		return fmt.Errorf("read programs dir: %w", err)
	}
	next := map[string]Program{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(r.dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var p Program
		if err := json.Unmarshal(b, &p); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if p.Name == "" {
			p.Name = strings.TrimSuffix(e.Name(), ".json")
		}
		if len(p.InScope) == 0 {
			return fmt.Errorf("%s: in_scope vazio", path)
		}
		next[p.Name] = p
	}
	r.mu.Lock()
	r.byID = next
	r.mu.Unlock()
	return nil
}

// List returns all programs sorted by name.
func (r *Registry) List() []Program {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Program, 0, len(r.byID))
	for _, p := range r.byID {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns one program by name.
func (r *Registry) Get(name string) (Program, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byID[name]
	return p, ok
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidName reports whether s is a safe program/file name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// normalize validates and cleans p in place, ready to write to disk.
func normalize(p *Program) error {
	p.Name = strings.ToLower(strings.TrimSpace(p.Name))
	if !ValidName(p.Name) {
		return fmt.Errorf("nome inválido (use a-z, 0-9, . _ -; até 63 chars)")
	}
	if len(cleanList(p.InScope)) == 0 {
		return fmt.Errorf("in_scope não pode ser vazio")
	}
	p.InScope = cleanList(p.InScope)
	p.OutOfScope = cleanList(p.OutOfScope)
	return nil
}

// Save validates p, writes programs/<name>.json and reloads the registry.
// It refuses to overwrite an existing program — use Update for that.
func (r *Registry) Save(p Program) error {
	if err := normalize(&p); err != nil {
		return err
	}
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(r.dir, p.Name+".json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("já existe um programa %q", p.Name)
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return r.Reload()
}

// Update overwrites an existing program's scope (in_scope/out_of_scope,
// platform, url) — the name is fixed by the URL path, not editable here (a
// rename would orphan every job/finding/asset already tagged with the old
// program name, so it's deliberately not supported). Refuses to "update"
// a program that doesn't exist yet — use Save for that.
func (r *Registry) Update(name string, p Program) error {
	name = strings.ToLower(strings.TrimSpace(name))
	path := filepath.Join(r.dir, name+".json")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("programa %q não existe", name)
	}
	p.Name = name
	if err := normalize(&p); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return r.Reload()
}

// Delete removes a program's scope definition (programs/<name>.json) and
// reloads the registry. It does NOT touch data/projects/<name>/ — jobs,
// findings and assets already tagged with this program name stay exactly
// where they are; only the in_scope/out_of_scope definition goes away, so
// new jobs against that name lose scope enforcement until it's recreated.
func (r *Registry) Delete(name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	path := filepath.Join(r.dir, name+".json")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("programa %q não existe", name)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return r.Reload()
}

func cleanList(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = cleanPattern(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// cleanPattern normalizes a scope pattern to a bare host pattern: lowercases,
// trims, and strips a URL scheme, path, or port a user may have pasted in — so
// "https://*.example.com/api" and "example.com:443" become "*.example.com" and
// "example.com". The "*." and "." subdomain prefixes are preserved. Applied
// both when scope is saved and at match time, so programs saved with messy
// patterns still match correctly without re-editing.
func cleanPattern(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		if _, err := strconv.Atoi(s[i+1:]); err == nil {
			s = s[:i]
		}
	}
	return strings.TrimSuffix(s, ".")
}
