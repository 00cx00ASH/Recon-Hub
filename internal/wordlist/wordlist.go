// Package wordlist indexes wordlists the tools can use: the ones bundled under
// wordlists/ and, if configured, a SecLists checkout.
package wordlist

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// List is one indexed wordlist.
type List struct {
	Name     string `json:"name"`     // stable id, also shown in the picker
	Category string `json:"category"` // web-content | dns | parameters | fuzzing | misc
	Path     string `json:"path"`     // absolute
	Lines    int    `json:"lines"`    // -1 when not counted (very large file)
	Source   string `json:"source"`   // builtin | seclists
}

// Registry is a concurrency-safe index of wordlists.
type Registry struct {
	mu     sync.RWMutex
	byPath map[string]List
}

// Load indexes builtinDir (wordlists/*.txt) and, when seclistsDir exists, a
// curated slice of SecLists (Discovery/**, Fuzzing/**, Usernames/**).
func Load(builtinDir, seclistsDir string) (*Registry, error) {
	r := &Registry{byPath: map[string]List{}}
	r.indexBuiltin(builtinDir)
	r.indexSecLists(seclistsDir)
	return r, nil
}

func (r *Registry) indexBuiltin(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		p, _ := filepath.Abs(filepath.Join(dir, e.Name()))
		name := strings.TrimSuffix(e.Name(), ".txt")
		r.add(List{
			Name:     "builtin/" + name,
			Category: categoryOf(name),
			Path:     p,
			Lines:    countLines(p),
			Source:   "builtin",
		})
	}
}

// which SecLists subtrees to index, and the category to file them under.
var seclistsRoots = []struct{ sub, cat string }{
	{"Discovery/Web-Content", "web-content"},
	{"Discovery/DNS", "dns"},
	{"Discovery/Web-Content/CMS", "web-content"},
	{"Fuzzing", "fuzzing"},
	{"Usernames", "usernames"},
	{"Passwords/Common-Credentials", "passwords"},
}

func (r *Registry) indexSecLists(root string) {
	if root == "" {
		return
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return
	}
	const maxLists = 800
	count := 0
	for _, sr := range seclistsRoots {
		base := filepath.Join(root, sr.sub)
		_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".txt") {
				return nil
			}
			if count >= maxLists {
				return filepath.SkipAll
			}
			abs, _ := filepath.Abs(path)
			rel, _ := filepath.Rel(root, abs)
			r.add(List{
				Name:     "seclists/" + filepath.ToSlash(rel),
				Category: sr.cat,
				Path:     abs,
				Lines:    countLines(abs),
				Source:   "seclists",
			})
			count++
			return nil
		})
	}
}

// List returns every indexed wordlist, sorted by name.
func (r *Registry) List() []List {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]List, 0, len(r.byPath))
	for _, l := range r.byPath {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Resolve returns the absolute path for an indexed list name, or the input
// unchanged if it is already an existing file path.
func (r *Registry) Resolve(nameOrPath string) (string, bool) {
	s := strings.TrimSpace(nameOrPath)
	if s == "" {
		return "", false
	}
	r.mu.RLock()
	for _, l := range r.byPath {
		if l.Name == s || l.Path == s {
			r.mu.RUnlock()
			return l.Path, true
		}
	}
	r.mu.RUnlock()
	if fi, err := os.Stat(s); err == nil && !fi.IsDir() {
		return s, true
	}
	return "", false
}

func (r *Registry) add(l List) {
	r.mu.Lock()
	if _, ok := r.byPath[l.Path]; !ok {
		r.byPath[l.Path] = l
	}
	r.mu.Unlock()
}

func categoryOf(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "sub") || strings.Contains(n, "dns"):
		return "dns"
	case strings.Contains(n, "param"):
		return "parameters"
	case strings.Contains(n, "redirect"):
		return "parameters"
	case strings.Contains(n, "web") || strings.Contains(n, "content") || strings.Contains(n, "dir"):
		return "web-content"
	default:
		return "misc"
	}
}

func countLines(path string) int {
	fi, err := os.Stat(path)
	if err != nil {
		return -1
	}
	if fi.Size() > 30<<20 { // don't slurp giant lists just to count
		return -1
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	n := bytes.Count(b, []byte{'\n'})
	if len(b) > 0 && b[len(b)-1] != '\n' {
		n++
	}
	return n
}
