// Package runner executes a tool subprocess and translates its stdout NDJSON
// stream into normalized events and findings. See docs/TOOL_CONTRACT.md.
package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"reconhub/internal/registry"
	"reconhub/internal/store"
)

// rawEvent is one line a tool prints on stdout.
type rawEvent struct {
	Type        string          `json:"type"`
	Level       string          `json:"level"`
	Msg         string          `json:"msg"`
	Data        json.RawMessage `json:"data"`
	Severity    string          `json:"severity"`
	FindingType string          `json:"finding_type"`
	Title       string          `json:"title"`
	Asset       string          `json:"asset"`
	Evidence    string          `json:"evidence"`
	Meta        json.RawMessage `json:"meta"`
	Value       string          `json:"value"` // asset events
	Kind        string          `json:"kind"`  // asset events
}

// Result reports how the subprocess ended.
type Result struct {
	ExitCode int
	Err      error
}

// Emit receives every normalized event.
type Emit func(store.Event)

// OnFinding receives every finding the tool reports.
type OnFinding func(store.Finding)

// OnAsset receives every asset the tool discovers.
type OnAsset func(store.Asset)

type stdinPayload struct {
	Target string         `json:"target"`
	Params map[string]any `json:"params"`
	JobID  string         `json:"job_id"`
}

// Run executes tool for job. It blocks until the process exits, the context is
// canceled, or the tool's timeout elapses. extraEnv is appended to the
// subprocess environment as-is (KEY=VALUE strings) — used to inject a
// program's shared auth context (RECONHUB_AUTH_*, see internal/project.Auth)
// without runner needing to know anything about where that comes from.
func Run(ctx context.Context, tool registry.Tool, job *store.Job, extraEnv []string, emit Emit, onFinding OnFinding, onAsset OnAsset) Result {
	ctx, cancel := context.WithTimeout(ctx, tool.TimeoutDur)
	defer cancel()

	argv := make([]string, len(tool.Exec))
	for i, a := range tool.Exec {
		a = strings.ReplaceAll(a, "{target}", job.Target)
		a = strings.ReplaceAll(a, "{job_id}", job.ID)
		argv[i] = a
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = tool.Dir

	env := os.Environ()
	env = append(env, "RECONHUB_TARGET="+job.Target, "RECONHUB_JOB_ID="+job.ID)
	for k, v := range job.Params {
		env = append(env, "RECONHUB_PARAM_"+strings.ToUpper(k)+"="+fmt.Sprint(v))
	}
	env = append(env, extraEnv...)
	cmd.Env = env

	payload, _ := json.Marshal(stdinPayload{Target: job.Target, Params: job.Params, JobID: job.ID})
	cmd.Stdin = strings.NewReader(string(payload) + "\n")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{ExitCode: -1, Err: err}
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return Result{ExitCode: -1, Err: err}
	}
	if err := cmd.Start(); err != nil {
		return Result{ExitCode: -1, Err: fmt.Errorf("start %s: %w", argv[0], err)}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				emit(store.Event{Type: "log", Level: "error", Msg: line, Time: time.Now().UTC()})
			}
		}
	}()

	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var re rawEvent
			if err := json.Unmarshal([]byte(line), &re); err != nil || re.Type == "" {
				// Not our protocol: surface the raw line as a log.
				emit(store.Event{Type: "log", Level: "info", Msg: line, Time: time.Now().UTC()})
				continue
			}
			switch re.Type {
			case "finding":
				sev := re.Severity
				if sev == "" {
					sev = "info"
				}
				onFinding(store.Finding{
					JobID:    job.ID,
					Tool:     job.Tool,
					Target:   job.Target,
					Type:     re.FindingType,
					Severity: sev,
					Title:    re.Title,
					Asset:    re.Asset,
					Evidence: re.Evidence,
					Meta:     re.Meta,
				})
				emit(store.Event{Type: "finding", Level: sev, Msg: re.Title, Data: re.Meta, Time: time.Now().UTC()})
			case "asset":
				val := strings.TrimSpace(re.Value)
				if val == "" {
					val = strings.TrimSpace(re.Msg)
				}
				if val != "" {
					onAsset(store.Asset{JobID: job.ID, Tool: job.Tool, Kind: re.Kind, Value: val})
					emit(store.Event{Type: "asset", Level: re.Kind, Msg: val, Time: time.Now().UTC()})
				}
			case "progress":
				emit(store.Event{Type: "progress", Msg: re.Msg, Data: re.Data, Time: time.Now().UTC()})
			case "done":
				emit(store.Event{Type: "done", Msg: re.Msg, Data: re.Data, Time: time.Now().UTC()})
			case "error":
				emit(store.Event{Type: "error", Level: "error", Msg: re.Msg, Data: re.Data, Time: time.Now().UTC()})
			default: // "log" and anything unknown
				lvl := re.Level
				if lvl == "" {
					lvl = "info"
				}
				emit(store.Event{Type: "log", Level: lvl, Msg: re.Msg, Data: re.Data, Time: time.Now().UTC()})
			}
		}
	}()

	wg.Wait()
	waitErr := cmd.Wait()

	exitCode := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}

	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return Result{ExitCode: exitCode, Err: fmt.Errorf("timeout após %s", tool.TimeoutDur)}
	case ctx.Err() == context.Canceled:
		return Result{ExitCode: exitCode, Err: context.Canceled}
	case waitErr != nil:
		return Result{ExitCode: exitCode, Err: waitErr}
	default:
		return Result{ExitCode: exitCode}
	}
}
