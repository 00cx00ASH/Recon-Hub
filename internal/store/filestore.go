// Package store persists jobs, events and findings.
//
// The v1 implementation is an append-only JSON-lines store kept fully in memory
// and mirrored to disk under DataDir:
//
//	<data>/jobs.jsonl        one line per job snapshot (last line per ID wins)
//	<data>/findings.jsonl    one line per finding
//	<data>/events/<id>.jsonl one line per event, per job
//
// It has zero external dependencies. The method set is deliberately small so a
// SQLite-backed implementation can replace it later without touching callers.
package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileStore is the append-only, in-memory-indexed store.
type FileStore struct {
	dir string

	mu          sync.RWMutex
	jobs        map[string]*Job
	jobOrder    []string
	findings    []*Finding
	findingSeen map[string]*Finding // Finding.Key() -> current row
	assets      []*Asset
	assetSeen   map[string]bool // "jobID|kind|value" -> deduped
	pruns       map[string]*PipelineRun
	prunOrder   []string
	events      map[string][]Event

	jobsFile     *os.File
	findingsFile *os.File
	assetsFile   *os.File
	prunsFile    *os.File

	evMu    sync.Mutex
	evFiles map[string]*os.File
}

// Open loads any existing data under dir and returns a ready store.
func Open(dir string) (*FileStore, error) {
	if err := os.MkdirAll(filepath.Join(dir, "events"), 0o755); err != nil {
		return nil, err
	}
	fs := &FileStore{
		dir:         dir,
		jobs:        map[string]*Job{},
		findingSeen: map[string]*Finding{},
		assetSeen:   map[string]bool{},
		pruns:       map[string]*PipelineRun{},
		events:      map[string][]Event{},
		evFiles:     map[string]*os.File{},
	}
	if err := fs.replay(); err != nil {
		return nil, err
	}
	var err error
	if fs.jobsFile, err = openAppend(filepath.Join(dir, "jobs.jsonl")); err != nil {
		return nil, err
	}
	if fs.findingsFile, err = openAppend(filepath.Join(dir, "findings.jsonl")); err != nil {
		return nil, err
	}
	if fs.assetsFile, err = openAppend(filepath.Join(dir, "assets.jsonl")); err != nil {
		return nil, err
	}
	if fs.prunsFile, err = openAppend(filepath.Join(dir, "pipeline_runs.jsonl")); err != nil {
		return nil, err
	}
	return fs, nil
}

func openAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}

func (fs *FileStore) replay() error {
	lines, err := readLines(filepath.Join(fs.dir, "jobs.jsonl"))
	if err != nil {
		return err
	}
	for _, ln := range lines {
		var j Job
		if json.Unmarshal(ln, &j) != nil || j.ID == "" {
			continue
		}
		if _, seen := fs.jobs[j.ID]; !seen {
			fs.jobOrder = append(fs.jobOrder, j.ID)
		}
		jc := j
		fs.jobs[j.ID] = &jc
	}

	lines, err = readLines(filepath.Join(fs.dir, "findings.jsonl"))
	if err != nil {
		return err
	}
	for _, ln := range lines {
		var f Finding
		if json.Unmarshal(ln, &f) != nil {
			continue
		}
		fc := f
		if prev, ok := fs.findingSeen[fc.Key()]; ok {
			*prev = fc // later snapshot wins (carries updated Count/LastSeen)
			continue
		}
		fs.findingSeen[fc.Key()] = &fc
		fs.findings = append(fs.findings, &fc)
	}

	lines, err = readLines(filepath.Join(fs.dir, "assets.jsonl"))
	if err != nil {
		return err
	}
	for _, ln := range lines {
		var a Asset
		if json.Unmarshal(ln, &a) != nil {
			continue
		}
		key := a.JobID + "|" + a.Kind + "|" + a.Value
		if fs.assetSeen[key] {
			continue
		}
		fs.assetSeen[key] = true
		ac := a
		fs.assets = append(fs.assets, &ac)
	}

	lines, err = readLines(filepath.Join(fs.dir, "pipeline_runs.jsonl"))
	if err != nil {
		return err
	}
	for _, ln := range lines {
		var p PipelineRun
		if json.Unmarshal(ln, &p) != nil || p.ID == "" {
			continue
		}
		if _, seen := fs.pruns[p.ID]; !seen {
			fs.prunOrder = append(fs.prunOrder, p.ID)
		}
		pc := p
		fs.pruns[p.ID] = &pc
	}

	evDir := filepath.Join(fs.dir, "events")
	entries, _ := os.ReadDir(evDir)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".jsonl" {
			continue
		}
		jobID := e.Name()[:len(e.Name())-len(".jsonl")]
		lns, err := readLines(filepath.Join(evDir, e.Name()))
		if err != nil {
			return err
		}
		for _, ln := range lns {
			var ev Event
			if json.Unmarshal(ln, &ev) != nil {
				continue
			}
			fs.events[jobID] = append(fs.events[jobID], ev)
		}
	}
	return nil
}

func readLines(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		cp := make([]byte, len(b))
		copy(cp, b)
		out = append(out, cp)
	}
	return out, sc.Err()
}

// CreateJob records a new job.
func (fs *FileStore) CreateJob(j *Job) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if _, ok := fs.jobs[j.ID]; ok {
		return errors.New("job already exists")
	}
	jc := *j
	fs.jobs[j.ID] = &jc
	fs.jobOrder = append(fs.jobOrder, j.ID)
	return fs.writeJobLocked(&jc)
}

// UpdateJob writes a new snapshot of an existing job.
func (fs *FileStore) UpdateJob(j *Job) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	jc := *j
	fs.jobs[j.ID] = &jc
	return fs.writeJobLocked(&jc)
}

func (fs *FileStore) writeJobLocked(j *Job) error {
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	_, err = fs.jobsFile.Write(append(b, '\n'))
	return err
}

// GetJob returns a copy of the job and whether it was found.
func (fs *FileStore) GetJob(id string) (*Job, bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	j, ok := fs.jobs[id]
	if !ok {
		return nil, false
	}
	jc := *j
	return &jc, true
}

// ListJobs returns jobs newest-first, applying the filter.
func (fs *FileStore) ListJobs(f JobFilter) ([]*Job, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	var out []*Job
	for i := len(fs.jobOrder) - 1; i >= 0; i-- {
		j := fs.jobs[fs.jobOrder[i]]
		if j == nil {
			continue
		}
		if f.Tool != "" && j.Tool != f.Tool {
			continue
		}
		if f.Program != "" && j.Program != f.Program {
			continue
		}
		if f.Status != "" && j.Status != f.Status {
			continue
		}
		if f.Target != "" && j.Target != f.Target {
			continue
		}
		jc := *j
		out = append(out, &jc)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out, nil
}

// AppendEvent assigns the next sequence number for the job, persists the event
// and returns the stored copy.
func (fs *FileStore) AppendEvent(e Event) (Event, error) {
	fs.mu.Lock()
	list := fs.events[e.JobID]
	e.Seq = len(list) + 1
	fs.events[e.JobID] = append(list, e)
	fs.mu.Unlock()

	fs.evMu.Lock()
	defer fs.evMu.Unlock()
	f, ok := fs.evFiles[e.JobID]
	if !ok {
		var err error
		f, err = openAppend(filepath.Join(fs.dir, "events", e.JobID+".jsonl"))
		if err != nil {
			return e, err
		}
		fs.evFiles[e.JobID] = f
	}
	b, _ := json.Marshal(e)
	_, err := f.Write(append(b, '\n'))
	return e, err
}

// ListEvents returns stored events for a job with Seq greater than sinceSeq.
func (fs *FileStore) ListEvents(jobID string, sinceSeq int) ([]Event, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	var out []Event
	for _, e := range fs.events[jobID] {
		if e.Seq > sinceSeq {
			out = append(out, e)
		}
	}
	return out, nil
}

// AddFinding records a finding, deduped by Finding.Key(). A repeat bumps Count
// and LastSeen on the existing row (a new snapshot is appended so the change
// survives a restart). It reports whether the finding was new.
func (fs *FileStore) AddFinding(f *Finding) (bool, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	now := f.LastSeen
	if now.IsZero() {
		now = f.CreatedAt
	}

	if prev, ok := fs.findingSeen[f.Key()]; ok {
		prev.Count++
		prev.LastSeen = now
		b, _ := json.Marshal(prev)
		_, err := fs.findingsFile.Write(append(b, '\n'))
		return false, err
	}

	fc := *f
	fc.Count = 1
	fc.LastSeen = now
	fs.findingSeen[fc.Key()] = &fc
	fs.findings = append(fs.findings, &fc)
	b, _ := json.Marshal(&fc)
	_, err := fs.findingsFile.Write(append(b, '\n'))
	return true, err
}

// AddAsset records an asset, deduped per (job, kind, value). It reports whether
// the asset was new.
func (fs *FileStore) AddAsset(a *Asset) (bool, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	key := a.JobID + "|" + a.Kind + "|" + a.Value
	if fs.assetSeen[key] {
		return false, nil
	}
	fs.assetSeen[key] = true
	ac := *a
	fs.assets = append(fs.assets, &ac)
	b, _ := json.Marshal(&ac)
	_, err := fs.assetsFile.Write(append(b, '\n'))
	return true, err
}

// ListAssets returns assets newest-first, applying the filter.
func (fs *FileStore) ListAssets(f AssetFilter) ([]*Asset, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	var out []*Asset
	for i := len(fs.assets) - 1; i >= 0; i-- {
		x := fs.assets[i]
		if f.JobID != "" && x.JobID != f.JobID {
			continue
		}
		if f.Tool != "" && x.Tool != f.Tool {
			continue
		}
		if f.Program != "" && x.Program != f.Program {
			continue
		}
		if f.Kind != "" && x.Kind != f.Kind {
			continue
		}
		xc := *x
		out = append(out, &xc)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out, nil
}

// SetFindingTriage records operator feedback on a finding (by ID) and
// appends a new snapshot line — replay's "later line wins" rule (keyed by
// Finding.Key(), which Triage doesn't affect) picks it up on restart just
// like a count/last_seen update.
// GetFinding looks up one finding by id. Linear scan — findings aren't
// keyed by id in memory (only by dedup Key(), see findingSeen), and this is
// a low-frequency lookup (one finding, one report draft), not a hot path.
func (fs *FileStore) GetFinding(id string) (*Finding, bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	for _, f := range fs.findings {
		if f.ID == id {
			fc := *f
			return &fc, true
		}
	}
	return nil, false
}

func (fs *FileStore) SetFindingTriage(id, verdict, reason string) (*Finding, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for _, f := range fs.findings {
		if f.ID != id {
			continue
		}
		f.Triage = verdict
		f.TriageReason = reason
		now := time.Now().UTC()
		f.TriagedAt = &now
		b, err := json.Marshal(f)
		if err != nil {
			return nil, err
		}
		if _, err := fs.findingsFile.Write(append(b, '\n')); err != nil {
			return nil, err
		}
		fc := *f
		return &fc, nil
	}
	return nil, errors.New("finding não encontrado")
}

// ListFindings returns findings newest-first, applying the filter.
func (fs *FileStore) ListFindings(f FindingFilter) ([]*Finding, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	var out []*Finding
	for i := len(fs.findings) - 1; i >= 0; i-- {
		x := fs.findings[i]
		if f.JobID != "" && x.JobID != f.JobID {
			continue
		}
		if f.Tool != "" && x.Tool != f.Tool {
			continue
		}
		if f.Program != "" && x.Program != f.Program {
			continue
		}
		if f.Target != "" && x.Target != f.Target {
			continue
		}
		if f.Severity != "" && x.Severity != f.Severity {
			continue
		}
		if f.Type != "" && x.Type != f.Type {
			continue
		}
		xc := *x
		out = append(out, &xc)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out, nil
}

// CreatePipelineRun records a new pipeline run.
func (fs *FileStore) CreatePipelineRun(p *PipelineRun) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if _, ok := fs.pruns[p.ID]; ok {
		return errors.New("pipeline run already exists")
	}
	pc := *p
	fs.pruns[p.ID] = &pc
	fs.prunOrder = append(fs.prunOrder, p.ID)
	return fs.writePipelineRunLocked(&pc)
}

// UpdatePipelineRun writes a new snapshot of an existing run.
func (fs *FileStore) UpdatePipelineRun(p *PipelineRun) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	pc := *p
	fs.pruns[p.ID] = &pc
	return fs.writePipelineRunLocked(&pc)
}

func (fs *FileStore) writePipelineRunLocked(p *PipelineRun) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = fs.prunsFile.Write(append(b, '\n'))
	return err
}

// GetPipelineRun returns a copy of the run and whether it was found.
func (fs *FileStore) GetPipelineRun(id string) (*PipelineRun, bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	p, ok := fs.pruns[id]
	if !ok {
		return nil, false
	}
	pc := *p
	return &pc, true
}

// ListPipelineRuns returns runs newest-first, applying the filter.
func (fs *FileStore) ListPipelineRuns(f PipelineRunFilter) ([]*PipelineRun, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	var out []*PipelineRun
	for i := len(fs.prunOrder) - 1; i >= 0; i-- {
		p := fs.pruns[fs.prunOrder[i]]
		if p == nil {
			continue
		}
		if f.Pipeline != "" && p.Pipeline != f.Pipeline {
			continue
		}
		if f.Program != "" && p.Program != f.Program {
			continue
		}
		if f.Status != "" && p.Status != f.Status {
			continue
		}
		pc := *p
		out = append(out, &pc)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out, nil
}

// Close flushes and closes all open files.
func (fs *FileStore) Close() error {
	fs.evMu.Lock()
	for _, f := range fs.evFiles {
		f.Close()
	}
	fs.evFiles = map[string]*os.File{}
	fs.evMu.Unlock()

	if fs.jobsFile != nil {
		fs.jobsFile.Close()
	}
	if fs.findingsFile != nil {
		fs.findingsFile.Close()
	}
	if fs.assetsFile != nil {
		fs.assetsFile.Close()
	}
	if fs.prunsFile != nil {
		fs.prunsFile.Close()
	}
	return nil
}
