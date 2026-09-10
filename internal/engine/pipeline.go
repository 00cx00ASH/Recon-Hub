package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"reconhub/internal/pipeline"
	"reconhub/internal/scope"
	"reconhub/internal/store"
)

// SubmitPipeline validates a pipeline, records a run and starts it in the
// background. `program` (may be nil) tags every job/asset/finding of the run and
// constrains the feed between steps to in-scope hosts.
func (e *Engine) SubmitPipeline(pl pipeline.Pipeline, target string, program *scope.Program) (*store.PipelineRun, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("target obrigatório")
	}
	for _, s := range pl.Steps {
		if _, ok := e.reg.Get(s.Tool); !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownTool, s.Tool)
		}
	}

	run := &store.PipelineRun{
		ID:        NewID(),
		Pipeline:  pl.Name,
		Target:    target,
		Status:    store.StatusQueued,
		CreatedAt: time.Now().UTC(),
	}
	if program != nil {
		run.Program = program.Name
	}
	plan, err := pl.Plan()
	if err != nil {
		return nil, fmt.Errorf("pipeline %s: %w", pl.Name, err)
	}
	for i, s := range pl.Steps {
		run.Steps = append(run.Steps, store.StepRun{
			Index: i, ID: plan[i].ID, Tool: s.Tool, Status: store.StatusQueued, Needs: plan[i].Deps,
		})
	}
	if err := e.store.CreatePipelineRun(run); err != nil {
		return nil, err
	}
	// snapshot before starting the background goroutine: runPipeline mutates
	// run.Status/StartedAt/Steps concurrently, so copying after `go` races
	// with those writes (caught by `go test -race`).
	rc := *run
	go e.runPipeline(pl, run, program)
	return &rc, nil
}

// CancelPipeline cancels every currently-running step's job. Steps that depend
// on a canceled step are then skipped and the run ends as failed.
func (e *Engine) CancelPipeline(runID string) bool {
	run, ok := e.store.GetPipelineRun(runID)
	if !ok {
		return false
	}
	any := false
	for _, s := range run.Steps {
		if s.Status == store.StatusRunning && s.JobID != "" {
			if e.Cancel(s.JobID) {
				any = true
			}
		}
	}
	return any
}

func (e *Engine) runPipeline(pl pipeline.Pipeline, run *store.PipelineRun, program *scope.Program) {
	start := time.Now().UTC()
	run.Status = store.StatusRunning
	run.StartedAt = &start
	_ = e.store.UpdatePipelineRun(run)

	plan, err := pl.Plan()
	if err != nil {
		e.failPipeline(run, -1, err.Error())
		return
	}
	idToIdx := map[string]int{}
	for _, sp := range plan {
		idToIdx[sp.ID] = sp.Index
	}

	waves := 1
	for _, sp := range plan {
		if len(sp.Deps) > 0 {
			waves = 2
			break
		}
	}
	msg := "pipeline iniciada: " + pl.Name + " → " + run.Target
	if program != nil {
		msg += "  (escopo: " + program.Name + ")"
	}
	if waves > 1 {
		msg += "  (grafo: fan-out)"
	}
	e.pipeEmit(run.ID, "log", msg, nil)

	var (
		mu       sync.Mutex
		state    = make([]string, len(plan)) // "" | running | succeeded | failed | skipped
		jobID    = make([]string, len(plan))
		total    int
		softFail int
		hardFail bool
	)

	// depsClear returns (ready, skip) for a queued step.
	depsClear := func(i int) (ready, skip bool) {
		for _, dep := range plan[i].Deps {
			switch state[idToIdx[dep]] {
			case store.StatusSucceeded:
			case store.StatusFailed, store.StatusSkipped, store.StatusCanceled:
				return false, true
			default:
				return false, false
			}
		}
		return true, false
	}

	runStep := func(i int) {
		step := pl.Steps[i]
		params := cloneParams(step.Params)

		fed := 0
		if step.Feed != nil && step.Feed.Param != "" && plan[i].FeedFrom != "" {
			srcJob := ""
			mu.Lock()
			srcJob = jobID[idToIdx[plan[i].FeedFrom]]
			mu.Unlock()
			vals := e.collectStepValues(srcJob, step.Feed)
			vals = filterScope(vals, step.Feed, program, e, run.ID)
			if len(vals) > 0 {
				fed = len(vals)
				params[step.Feed.Param] = step.Feed.Join(vals)
			}
		}

		mu.Lock()
		state[i] = store.StatusRunning
		run.Steps[i].Fed = fed
		run.Steps[i].Status = store.StatusRunning
		_ = e.store.UpdatePipelineRun(run)
		mu.Unlock()
		e.pipeEmit(run.ID, "step_start",
			fmt.Sprintf("step %s (%s) — fed %d", plan[i].ID, step.Tool, fed),
			map[string]any{"step": i, "id": plan[i].ID, "tool": step.Tool, "fed": fed})

		job, err := e.RunJobSync(step.Tool, run.Target, run.Program, params)

		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			state[i] = store.StatusFailed
			run.Steps[i].Status = store.StatusFailed
			if step.ContinueOnFail() {
				state[i] = store.StatusSucceeded // libera dependentes
				softFail++
			} else {
				hardFail = true
			}
			_ = e.store.UpdatePipelineRun(run)
			e.pipeEmit(run.ID, "step_end",
				fmt.Sprintf("step %s não iniciou: %s", plan[i].ID, err.Error()),
				map[string]any{"step": i, "id": plan[i].ID, "status": "failed", "error": err.Error()})
			return
		}

		jobID[i] = job.ID
		run.Steps[i].JobID = job.ID
		total += job.Findings
		run.Findings = total

		switch job.Status {
		case store.StatusSucceeded:
			state[i] = store.StatusSucceeded
			run.Steps[i].Status = store.StatusSucceeded
		default:
			run.Steps[i].Status = job.Status
			if step.ContinueOnFail() {
				state[i] = store.StatusSucceeded
				softFail++
			} else {
				state[i] = store.StatusFailed
				hardFail = true
			}
		}
		_ = e.store.UpdatePipelineRun(run)
		e.pipeEmit(run.ID, "step_end",
			fmt.Sprintf("step %s %s — %d finding(s)", plan[i].ID, job.Status, job.Findings),
			map[string]any{"step": i, "id": plan[i].ID, "tool": step.Tool,
				"job_id": job.ID, "status": job.Status, "findings": job.Findings})
	}

	// wave loop: run every currently-ready step concurrently, repeat until all
	// steps have a terminal state.
	for {
		mu.Lock()
		var ready []int
		pending, skippedNow := 0, 0
		for i := range plan {
			if state[i] != "" {
				continue
			}
			pending++
			if r, skip := depsClear(i); skip {
				state[i] = store.StatusSkipped
				run.Steps[i].Status = store.StatusSkipped
				_ = e.store.UpdatePipelineRun(run)
				skippedNow++
				e.pipeEmit(run.ID, "step_end",
					fmt.Sprintf("step %s pulado (dependência falhou)", plan[i].ID),
					map[string]any{"step": i, "id": plan[i].ID, "status": "skipped"})
			} else if r {
				ready = append(ready, i)
			}
		}
		mu.Unlock()
		if pending == 0 {
			break
		}
		if len(ready) == 0 {
			if skippedNow == 0 {
				// impossível num DAG válido (Plan() já rejeitou ciclos), mas
				// não trava a run se acontecer.
				e.failPipeline(run, -1, "impasse no grafo da pipeline")
				return
			}
			continue // só houve skip nesta volta; reavalia
		}
		var wg sync.WaitGroup
		for _, i := range ready {
			wg.Add(1)
			go func(i int) { defer wg.Done(); runStep(i) }(i)
		}
		wg.Wait()
	}

	end := time.Now().UTC()
	run.EndedAt = &end
	skipped := 0
	for _, s := range state {
		if s == store.StatusSkipped {
			skipped++
		}
	}
	if hardFail {
		run.Status = store.StatusFailed
		run.Error = fmt.Sprintf("%d step(s) pulado(s) por dependência falha", skipped)
		_ = e.store.UpdatePipelineRun(run)
		e.pipeEmit(run.ID, "done",
			fmt.Sprintf("pipeline falhou: %d finding(s), %d step(s) pulado(s)", run.Findings, skipped),
			map[string]any{"status": run.Status, "findings": run.Findings, "skipped": skipped})
		return
	}
	run.Status = store.StatusSucceeded
	if softFail > 0 {
		run.Error = fmt.Sprintf("%d step(s) falharam (on_fail=continue)", softFail)
	}
	_ = e.store.UpdatePipelineRun(run)
	e.pipeEmit(run.ID, "done",
		fmt.Sprintf("pipeline concluída: %d finding(s)%s", run.Findings, plSuffix(softFail)),
		map[string]any{"status": run.Status, "findings": run.Findings, "failed_steps": softFail})
}

func plSuffix(failed int) string {
	if failed == 0 {
		return ""
	}
	return fmt.Sprintf(", %d step(s) com falha", failed)
}

// filterScope keeps only in-scope values when a program is set and the feed
// carries hostnames/URLs (kinds subdomain/url). Other kinds (bucket, …) pass
// through untouched.
func filterScope(values []string, feed *pipeline.Feed, program *scope.Program, e *Engine, runID string) []string {
	if program == nil || feed == nil {
		return values
	}
	if feed.Kind != "" && feed.Kind != "subdomain" && feed.Kind != "url" {
		return values
	}
	kept := values[:0:0]
	var dropped int
	for _, v := range values {
		if program.Contains(v) {
			kept = append(kept, v)
		} else {
			dropped++
		}
	}
	if dropped > 0 {
		e.pipeEmit(runID, "log",
			fmt.Sprintf("escopo %s: %d de %d valores fora do escopo, descartados", program.Name, dropped, len(values)), nil)
	}
	return kept
}

func (e *Engine) failPipeline(run *store.PipelineRun, stepIdx int, msg string) {
	end := time.Now().UTC()
	run.Status = store.StatusFailed
	run.Error = msg
	run.EndedAt = &end
	if stepIdx >= 0 && stepIdx < len(run.Steps) && run.Steps[stepIdx].Status == store.StatusRunning {
		run.Steps[stepIdx].Status = store.StatusFailed
	}
	_ = e.store.UpdatePipelineRun(run)
	e.pipeEmit(run.ID, "done", "pipeline falhou: "+msg,
		map[string]any{"status": run.Status, "error": msg})
}

// collectStepValues gathers the values a finished step exposes to the next one,
// according to that next step's feed config.
func (e *Engine) collectStepValues(jobID string, feed *pipeline.Feed) []string {
	if feed == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	if feed.WantAssets() {
		as, _ := e.store.ListAssets(store.AssetFilter{JobID: jobID, Kind: feed.Kind})
		for _, a := range as {
			add(a.Value)
		}
	}
	if feed.WantFindings() {
		fs, _ := e.store.ListFindings(store.FindingFilter{JobID: jobID})
		for _, f := range fs {
			add(f.Asset)
		}
	}
	return out
}

func (e *Engine) pipeEmit(runID, typ, msg string, data map[string]any) {
	var raw json.RawMessage
	if data != nil {
		b, _ := json.Marshal(data)
		raw = b
	}
	e.bus.Publish("pipe:"+runID, store.Event{
		JobID: runID, Type: typ, Msg: msg, Data: raw, Time: time.Now().UTC(),
	})
}

func cloneParams(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
