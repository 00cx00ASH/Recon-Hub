// Package pipeline loads multi-step recon pipelines from pipelines/<name>.json.
//
// A pipeline is a small dependency graph of steps. Each step runs one tool as a
// normal job; a step's `feed` says which upstream step's output becomes one of
// this step's parameters (`feed.from`, defaulting to the step just before it),
// and `needs` adds ordering-only edges. Steps with no pending dependency run in
// parallel. A plain linear pipeline (no ids, each step feeding from the previous)
// is just the chain case of the graph. See Plan.
package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Feed describes how an upstream step's output feeds this step.
type Feed struct {
	Param  string `json:"param"`            // parameter to inject
	From   string `json:"from,omitempty"`   // upstream step id (default: the step just before)
	Source string `json:"source,omitempty"` // assets | findings | both (default: both)
	Kind   string `json:"kind,omitempty"`   // when source includes assets, keep only this kind
	As     string `json:"as,omitempty"`     // csv (default) | lines
}

func (f *Feed) source() string {
	if f == nil || f.Source == "" {
		return "both"
	}
	return f.Source
}

// Join renders the fed values the way the step expects them.
func (f *Feed) Join(values []string) string {
	sep := ","
	if f != nil && f.As == "lines" {
		sep = "\n"
	}
	return strings.Join(values, sep)
}

// WantAssets / WantFindings report which stores to read for the feed.
func (f *Feed) WantAssets() bool   { s := f.source(); return s == "assets" || s == "both" }
func (f *Feed) WantFindings() bool { s := f.source(); return s == "findings" || s == "both" }

// Step is one stage of a pipeline.
type Step struct {
	ID     string         `json:"id,omitempty"` // stable id so other steps can depend on this one
	Tool   string         `json:"tool"`
	Params map[string]any `json:"params,omitempty"`
	Feed   *Feed          `json:"feed,omitempty"`
	Needs  []string       `json:"needs,omitempty"`   // extra upstream step ids to wait for (ordering only)
	OnFail string         `json:"on_fail,omitempty"` // "stop" (default) | "continue"
}

// ContinueOnFail reports whether the pipeline should keep going when this step
// fails.
func (s Step) ContinueOnFail() bool { return s.OnFail == "continue" }

// StepPlan is a resolved step: its id and the upstream step ids it depends on.
type StepPlan struct {
	Index    int
	ID       string
	Deps     []string // step ids that must finish before this one runs
	FeedFrom string   // step id whose output feeds this step ("" = no feed)
}

// Plan resolves step ids and the dependency graph. A linear pipeline (no ids,
// each non-first step feeding from the previous) resolves to a chain, so old
// pipelines behave exactly as before. Fan-out happens when several steps depend
// on the same upstream id. Returns an error on duplicate ids, unknown refs, or
// a cycle.
func (p Pipeline) Plan() ([]StepPlan, error) {
	ids := make([]string, len(p.Steps))
	idSet := map[string]int{}
	for i, s := range p.Steps {
		id := strings.TrimSpace(s.ID)
		if id == "" {
			id = fmt.Sprintf("s%d", i+1)
		}
		if _, dup := idSet[id]; dup {
			return nil, fmt.Errorf("step %d: id %q duplicado", i+1, id)
		}
		idSet[id] = i
		ids[i] = id
	}

	plans := make([]StepPlan, len(p.Steps))
	for i, s := range p.Steps {
		sp := StepPlan{Index: i, ID: ids[i]}
		depSet := map[string]bool{}

		feedFrom := ""
		if s.Feed != nil && s.Feed.Param != "" {
			feedFrom = strings.TrimSpace(s.Feed.From)
			if feedFrom == "" {
				if i == 0 {
					return nil, fmt.Errorf("step %d (%s): feed sem 'from' e não há step anterior", i+1, ids[i])
				}
				feedFrom = ids[i-1]
			}
			if _, ok := idSet[feedFrom]; !ok {
				return nil, fmt.Errorf("step %d (%s): feed.from %q não existe", i+1, ids[i], feedFrom)
			}
			depSet[feedFrom] = true
		}
		sp.FeedFrom = feedFrom

		for _, n := range s.Needs {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			if _, ok := idSet[n]; !ok {
				return nil, fmt.Errorf("step %d (%s): needs %q não existe", i+1, ids[i], n)
			}
			depSet[n] = true
		}
		// a step with no feed and no needs but not the first still can't run
		// before the pipeline starts; give it no deps (it runs in wave 0).
		for d := range depSet {
			if d == ids[i] {
				return nil, fmt.Errorf("step %d (%s): depende de si mesmo", i+1, ids[i])
			}
			sp.Deps = append(sp.Deps, d)
		}
		sort.Strings(sp.Deps)
		plans[i] = sp
	}

	// cycle check via Kahn
	indeg := make([]int, len(plans))
	for _, sp := range plans {
		indeg[sp.Index] = len(sp.Deps)
	}
	queue := []int{}
	for i, d := range indeg {
		if d == 0 {
			queue = append(queue, i)
		}
	}
	done := 0
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		done++
		for _, sp := range plans {
			for _, dep := range sp.Deps {
				if idSet[dep] == cur {
					indeg[sp.Index]--
					if indeg[sp.Index] == 0 {
						queue = append(queue, sp.Index)
					}
				}
			}
		}
	}
	if done != len(plans) {
		return nil, fmt.Errorf("pipeline tem ciclo de dependência entre steps")
	}
	return plans, nil
}

// Pipeline is a named sequence of steps.
type Pipeline struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Steps       []Step `json:"steps"`
}

// Registry is a concurrency-safe set of pipelines loaded from disk.
type Registry struct {
	mu   sync.RWMutex
	dir  string
	byID map[string]Pipeline
}

// Load reads every pipelines/*.json under dir. A missing directory is not an
// error — it just yields an empty registry.
func Load(dir string) (*Registry, error) {
	r := &Registry{dir: dir, byID: map[string]Pipeline{}}
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
		return fmt.Errorf("read pipelines dir: %w", err)
	}
	next := map[string]Pipeline{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(r.dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var pl Pipeline
		if err := json.Unmarshal(b, &pl); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if pl.Name == "" {
			pl.Name = strings.TrimSuffix(e.Name(), ".json")
		}
		if len(pl.Steps) == 0 {
			return fmt.Errorf("%s: pipeline sem steps", path)
		}
		for i, s := range pl.Steps {
			if s.Tool == "" {
				return fmt.Errorf("%s: step %d sem \"tool\"", path, i+1)
			}
		}
		if _, err := pl.Plan(); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		next[pl.Name] = pl
	}
	r.mu.Lock()
	r.byID = next
	r.mu.Unlock()
	return nil
}

// List returns all pipelines sorted by name.
func (r *Registry) List() []Pipeline {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Pipeline, 0, len(r.byID))
	for _, p := range r.byID {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns one pipeline by name.
func (r *Registry) Get(name string) (Pipeline, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byID[name]
	return p, ok
}
