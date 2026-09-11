// Package project manages a physical per-program workspace under
// <data_dir>/projects/<name>/: freeform notes plus a synced snapshot
// (summary, bounty report, assets) rebuilt from the store on demand and
// after every job that carries that program. It turns the "program" scope
// concept (in_scope/out_of_scope, already tagged on every job/finding/asset)
// into an actual folder you can open, back up or hand off.
package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"reconhub/internal/copilot"
	"reconhub/internal/registry"
	"reconhub/internal/report"
	"reconhub/internal/scope"
	"reconhub/internal/store"
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Dir returns the project's folder path, or "" for an unsafe/invalid name.
func Dir(dataDir, name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if !nameRe.MatchString(name) {
		return ""
	}
	return filepath.Join(dataDir, "projects", name)
}

// Summary is the at-a-glance snapshot written to summary.json.
type Summary struct {
	Program            string         `json:"program"`
	SyncedAt           time.Time      `json:"synced_at"`
	Jobs               int            `json:"jobs"`
	JobsByStatus       map[string]int `json:"jobs_by_status"`
	PipelineRuns       int            `json:"pipeline_runs"`
	Findings           int            `json:"findings"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	Assets             int            `json:"assets"`
	AssetsByKind       map[string]int `json:"assets_by_kind"`
	LastActivity       *time.Time     `json:"last_activity,omitempty"`
}

// one lock per project name, so concurrent syncs of the same project (e.g.
// a pipeline's fan-out steps finishing together) never interleave writes.
var (
	locksMu sync.Mutex
	locks   = map[string]*sync.Mutex{}
)

func lockFor(name string) *sync.Mutex {
	locksMu.Lock()
	defer locksMu.Unlock()
	l, ok := locks[name]
	if !ok {
		l = &sync.Mutex{}
		locks[name] = l
	}
	return l
}

const notesHeader = "Notas do projeto — escreva o que quiser aqui.\n"

// Init creates the project folder (if missing) and a starter notes.md — it
// never overwrites notes that already exist.
func Init(dataDir, name string) error {
	dir := Dir(dataDir, name)
	if dir == "" {
		return fmt.Errorf("nome de projeto inválido: %q", name)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	notes := filepath.Join(dir, "notes.md")
	if _, err := os.Stat(notes); os.IsNotExist(err) {
		return os.WriteFile(notes, []byte("# "+name+"\n\n"+notesHeader), 0o644)
	}
	return nil
}

// ReadNotes returns the project's notes.md content ("" if none yet).
func ReadNotes(dataDir, name string) (string, error) {
	dir := Dir(dataDir, name)
	if dir == "" {
		return "", fmt.Errorf("nome de projeto inválido: %q", name)
	}
	b, err := os.ReadFile(filepath.Join(dir, "notes.md"))
	if os.IsNotExist(err) {
		return "", nil
	}
	return string(b), err
}

// WriteNotes overwrites notes.md, creating the project folder if needed.
func WriteNotes(dataDir, name, content string) error {
	dir := Dir(dataDir, name)
	if dir == "" {
		return fmt.Errorf("nome de projeto inválido: %q", name)
	}
	l := lockFor(name)
	l.Lock()
	defer l.Unlock()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "notes.md"), []byte(content), 0o644)
}

// lessonsLockKey is a sentinel that can never collide with a real program
// name (nameRe requires a lowercase-alnum start; this starts with a NUL).
const lessonsLockKey = "\x00lessons"

// Lesson is one entry in the cross-program knowledge base: a pattern worth
// remembering on OTHER programs too, not just the one where it was
// noticed — unlike notes.md (per-program, freeform), lessons.md lives at
// the root of dataDir and is shared by every program.
type Lesson struct {
	Text    string   `json:"text"`
	Tags    []string `json:"tags,omitempty"`
	Program string   `json:"program,omitempty"` // where this was learned — context only, never enforced as scope
	Tool    string   `json:"tool,omitempty"`
}

const lessonsHeader = "# Lições cross-programa\n\n" +
	"Padrões que se repetem entre programas diferentes — comportamento de " +
	"WAF/rate-limit, peculiaridade de uma plataforma (HackerOne/Bugcrowd/...), " +
	"técnica que funcionou ou que NÃO funcionou. O valor de uma entrada aqui " +
	"é ser reaproveitável em QUALQUER programa novo, não só onde foi " +
	"aprendida — isso é o que distingue lessons.md de notes.md por programa.\n\n"

func lessonsPath(dataDir string) string { return filepath.Join(dataDir, "lessons.md") }

// ReadLessons returns lessons.md content ("" if none recorded yet).
func ReadLessons(dataDir string) (string, error) {
	b, err := os.ReadFile(lessonsPath(dataDir))
	if os.IsNotExist(err) {
		return "", nil
	}
	return string(b), err
}

// WriteLessons overwrites lessons.md wholesale — for manual reorganizing or
// cleanup. AppendLesson is the safer default for recording a new one: it
// can never clobber existing entries the way a WriteLessons call built from
// stale content would.
func WriteLessons(dataDir, content string) error {
	l := lockFor(lessonsLockKey)
	l.Lock()
	defer l.Unlock()
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(lessonsPath(dataDir), []byte(content), 0o644)
}

// AppendLesson adds one dated, attributed entry to lessons.md without
// touching what's already there.
func AppendLesson(dataDir string, ls Lesson) error {
	text := strings.TrimSpace(ls.Text)
	if text == "" {
		return fmt.Errorf("lição vazia — informe o texto")
	}
	l := lockFor(lessonsLockKey)
	l.Lock()
	defer l.Unlock()
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	path := lessonsPath(dataDir)
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(existing) == 0 {
		existing = []byte(lessonsHeader)
	}
	var meta []string
	if p := strings.TrimSpace(ls.Program); p != "" {
		meta = append(meta, "programa: "+p)
	}
	if t := strings.TrimSpace(ls.Tool); t != "" {
		meta = append(meta, "tool: "+t)
	}
	for _, tag := range ls.Tags {
		if tag = strings.TrimSpace(tag); tag != "" {
			meta = append(meta, "#"+tag)
		}
	}
	line := "- **" + time.Now().UTC().Format("2006-01-02") + "** " + text
	if len(meta) > 0 {
		line += " _(" + strings.Join(meta, ", ") + ")_"
	}
	out := append(existing, []byte(line+"\n")...)
	return os.WriteFile(path, out, 0o644)
}

// SyncFromStore rebuilds the project's snapshot from current store state:
//
//	summary.json   counts by status/severity/kind + last activity
//	report.md      bounty-ready report, scoped to this program
//	assets.json    every asset discovered under this program
//
// coverage.json     tools already run vs applicable-but-unused ones (see internal/copilot)
//
// The program's scope itself is not duplicated here — it already lives in
// programs/<name>.json (scope.Registry is the source of truth for it).
//
// It's cheap enough to call after every job completes and on every read of
// the summary — there's no separate "stale" state to track. reg is optional
// (nil is fine) — when set, it keeps coverage suggestions limited to tools
// actually registered on this hub.
func SyncFromStore(dataDir, name string, progs *scope.Registry, st store.Store, reg *registry.Registry) (Summary, error) {
	dir := Dir(dataDir, name)
	if dir == "" {
		return Summary{}, fmt.Errorf("nome de projeto inválido: %q", name)
	}
	if _, ok := progs.Get(name); !ok {
		return Summary{}, fmt.Errorf("programa desconhecido: %s", name)
	}

	l := lockFor(name)
	l.Lock()
	defer l.Unlock()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Summary{}, err
	}

	jobs, _ := st.ListJobs(store.JobFilter{Program: name, Limit: 1000000})
	runs, _ := st.ListPipelineRuns(store.PipelineRunFilter{Program: name, Limit: 1000000})
	findings, _ := st.ListFindings(store.FindingFilter{Program: name, Limit: 1000000})
	assets, _ := st.ListAssets(store.AssetFilter{Program: name, Limit: 1000000})

	sum := Summary{
		Program:            name,
		SyncedAt:           time.Now().UTC(),
		Jobs:               len(jobs),
		JobsByStatus:       map[string]int{},
		PipelineRuns:       len(runs),
		Findings:           len(findings),
		FindingsBySeverity: map[string]int{},
		Assets:             len(assets),
		AssetsByKind:       map[string]int{},
	}
	var last time.Time
	for _, j := range jobs {
		sum.JobsByStatus[j.Status]++
		if j.CreatedAt.After(last) {
			last = j.CreatedAt
		}
		if j.EndedAt != nil && j.EndedAt.After(last) {
			last = *j.EndedAt
		}
	}
	for _, f := range findings {
		sum.FindingsBySeverity[strings.ToLower(f.Severity)]++
		if f.LastSeen.After(last) {
			last = f.LastSeen
		}
	}
	for _, a := range assets {
		sum.AssetsByKind[a.Kind]++
	}
	if !last.IsZero() {
		sum.LastActivity = &last
	}

	items := make([]report.Item, 0, len(findings))
	for _, f := range findings {
		items = append(items, report.Item{
			Type: f.Type, Severity: f.Severity, Title: f.Title, Asset: f.Asset,
			Evidence: f.Evidence, Tool: f.Tool, Target: f.Target, Count: f.Count,
			FirstAt: f.CreatedAt, LastAt: f.LastSeen,
			Meta: report.MetaFromRaw(f.Meta),
		})
	}
	rep := report.Build(name, "", items, false)

	if err := writeJSON(filepath.Join(dir, "summary.json"), sum); err != nil {
		return sum, err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(rep.Markdown()), 0o644); err != nil {
		return sum, err
	}
	sortAssets(assets)
	if err := writeJSON(filepath.Join(dir, "assets.json"), assets); err != nil {
		return sum, err
	}
	cov := copilot.Compute(name, jobs, assets, reg)
	if err := writeJSON(filepath.Join(dir, "coverage.json"), cov); err != nil {
		return sum, err
	}
	notesPath := filepath.Join(dir, "notes.md")
	if _, err := os.Stat(notesPath); os.IsNotExist(err) {
		_ = os.WriteFile(notesPath, []byte("# "+name+"\n\n"+notesHeader), 0o644)
	}
	return sum, nil
}

func sortAssets(as []*store.Asset) {
	sort.Slice(as, func(i, j int) bool {
		if as[i].Kind != as[j].Kind {
			return as[i].Kind < as[j].Kind
		}
		return as[i].Value < as[j].Value
	})
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
