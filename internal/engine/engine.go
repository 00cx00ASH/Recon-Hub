// Package engine ties the registry, runner, store and bus together: it accepts
// job submissions, runs them under a concurrency limit, and streams their
// output to persistence and to live subscribers.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"reconhub/internal/bus"
	"reconhub/internal/registry"
	"reconhub/internal/runner"
	"reconhub/internal/store"
)

// ErrUnknownTool is returned by Submit when the named tool is not registered.
var ErrUnknownTool = errors.New("ferramenta desconhecida")

// wordlistResolver resolves a wordlist name to an absolute path.
type wordlistResolver interface {
	Resolve(nameOrPath string) (string, bool)
}

// Engine schedules and supervises job execution.
type Engine struct {
	store store.Store
	reg   *registry.Registry
	bus   *bus.Bus
	sem   chan struct{}

	// Wordlists, when set, resolves a "wordlist" param (a name) to a path
	// before the job runs. Optional.
	Wordlists wordlistResolver

	// OnJobDone, when set, is called (in its own goroutine) with the final
	// state of every job that finishes, queued or synchronous (pipeline
	// steps included). Used to keep a job's project folder in sync without
	// coupling the engine to the project package.
	OnJobDone func(job *store.Job)

	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

// New builds an Engine that runs at most maxConcurrent jobs at once.
func New(st store.Store, reg *registry.Registry, b *bus.Bus, maxConcurrent int) *Engine {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &Engine{
		store:   st,
		reg:     reg,
		bus:     b,
		sem:     make(chan struct{}, maxConcurrent),
		cancels: map[string]context.CancelFunc{},
	}
}

// NewID returns a random 24-hex-char identifier.
func NewID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Bus exposes the event bus for SSE handlers.
func (e *Engine) Bus() *bus.Bus { return e.bus }

func (e *Engine) create(tool, target, program string, params map[string]any) (*store.Job, error) {
	if _, ok := e.reg.Get(tool); !ok {
		return nil, ErrUnknownTool
	}
	// resolve a wordlist name -> absolute path so the tool just opens it
	if e.Wordlists != nil && params != nil {
		if name, ok := params["wordlist"].(string); ok && name != "" {
			if p, ok := e.Wordlists.Resolve(name); ok {
				params["wordlist"] = p
			}
		}
	}
	job := &store.Job{
		ID:        NewID(),
		Tool:      tool,
		Target:    target,
		Program:   program,
		Params:    params,
		Status:    store.StatusQueued,
		CreatedAt: time.Now().UTC(),
	}
	if err := e.store.CreateJob(job); err != nil {
		return nil, err
	}
	return job, nil
}

// Submit validates the request, records a queued job and starts it in the
// background. It returns immediately with the created job.
func (e *Engine) Submit(tool, target, program string, params map[string]any) (*store.Job, error) {
	job, err := e.create(tool, target, program, params)
	if err != nil {
		return nil, err
	}
	go e.execute(job)
	jc := *job
	return &jc, nil
}

// RunJobSync creates a job and runs it to completion, returning the final job
// state. Used by pipelines, which need each step to finish before the next
// starts. It still respects the concurrency limit.
func (e *Engine) RunJobSync(tool, target, program string, params map[string]any) (*store.Job, error) {
	job, err := e.create(tool, target, program, params)
	if err != nil {
		return nil, err
	}
	return e.execute(job), nil
}

// Cancel stops a running job. It reports whether a running job was found.
func (e *Engine) Cancel(jobID string) bool {
	e.mu.Lock()
	cancel, ok := e.cancels[jobID]
	e.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

// execute runs a queued job to completion and returns its final state.
func (e *Engine) execute(job *store.Job) *store.Job {
	e.sem <- struct{}{}
	defer func() { <-e.sem }()

	tool, ok := e.reg.Get(job.Tool)
	if !ok {
		e.finish(job, store.StatusFailed, nil, "ferramenta saiu do registro antes de iniciar")
		return job
	}

	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.cancels[job.ID] = cancel
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.cancels, job.ID)
		e.mu.Unlock()
		cancel()
	}()

	now := time.Now().UTC()
	job.Status = store.StatusRunning
	job.StartedAt = &now
	_ = e.store.UpdateJob(job)
	e.emit(job.ID, store.Event{Type: "log", Level: "info", Msg: "job iniciado: " + tool.Name + " → " + job.Target})

	var findings int
	res := runner.Run(ctx, tool, job,
		func(ev store.Event) { e.emit(job.ID, ev) },
		func(f store.Finding) {
			f.ID = NewID()
			f.Program = job.Program
			f.CreatedAt = time.Now().UTC()
			findings++ // count every finding the tool reports this run
			_, _ = e.store.AddFinding(&f)
		},
		func(a store.Asset) {
			a.ID = NewID()
			a.Program = job.Program
			a.CreatedAt = time.Now().UTC()
			_, _ = e.store.AddAsset(&a)
		},
	)

	job.Findings = findings
	ec := res.ExitCode
	switch {
	case errors.Is(res.Err, context.Canceled):
		e.finish(job, store.StatusCanceled, &ec, "cancelado pelo operador")
	case res.Err != nil:
		e.finish(job, store.StatusFailed, &ec, res.Err.Error())
	case ec != 0:
		e.finish(job, store.StatusFailed, &ec, "exit code diferente de zero")
	default:
		e.finish(job, store.StatusSucceeded, &ec, "")
	}
	return job
}

func (e *Engine) finish(job *store.Job, status string, ec *int, msg string) {
	end := time.Now().UTC()
	job.Status = status
	job.EndedAt = &end
	job.ExitCode = ec
	job.Error = msg
	_ = e.store.UpdateJob(job)

	detail := "job " + status
	if msg != "" {
		detail += ": " + msg
	}
	e.emit(job.ID, store.Event{Type: "done", Level: "info", Msg: detail})

	if e.OnJobDone != nil {
		jc := *job
		go e.OnJobDone(&jc)
	}
}

func (e *Engine) emit(jobID string, ev store.Event) {
	ev.JobID = jobID
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	stored, err := e.store.AppendEvent(ev)
	if err != nil {
		stored = ev
	}
	e.bus.Publish(jobID, stored)
}
