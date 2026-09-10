package runner

import (
	"context"
	"testing"
	"time"

	"reconhub/internal/registry"
	"reconhub/internal/store"
)

// echoTool runs a tiny shell command that prints an env var. A plain
// (non-JSON) stdout line becomes a "log" event per the tool contract, which
// is enough to prove extraEnv actually reached the subprocess.
func echoTool(script string) registry.Tool {
	return registry.Tool{
		Name:       "echo-test",
		Exec:       []string{"sh", "-c", script},
		TimeoutDur: 5 * time.Second,
	}
}

func TestRunPassesExtraEnvToSubprocess(t *testing.T) {
	job := &store.Job{ID: "j1", Target: "acme.com"}
	var logs []string
	res := Run(context.Background(), echoTool(`echo "bearer=$RECONHUB_AUTH_BEARER"`), job,
		[]string{"RECONHUB_AUTH_BEARER=tok-abc123"},
		func(e store.Event) {
			if e.Type == "log" {
				logs = append(logs, e.Msg)
			}
		},
		func(store.Finding) {}, func(store.Asset) {},
	)
	if res.Err != nil || res.ExitCode != 0 {
		t.Fatalf("res = %+v", res)
	}
	found := false
	for _, l := range logs {
		if l == "bearer=tok-abc123" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RECONHUB_AUTH_BEARER não chegou no subprocesso: logs=%v", logs)
	}
}

func TestRunWithoutExtraEnvLeavesAuthVarsUnset(t *testing.T) {
	job := &store.Job{ID: "j2", Target: "acme.com"}
	var logs []string
	res := Run(context.Background(), echoTool(`echo "bearer=[$RECONHUB_AUTH_BEARER]"`), job, nil,
		func(e store.Event) {
			if e.Type == "log" {
				logs = append(logs, e.Msg)
			}
		},
		func(store.Finding) {}, func(store.Asset) {},
	)
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	found := false
	for _, l := range logs {
		if l == "bearer=[]" {
			found = true
		}
	}
	if !found {
		t.Fatalf("esperava RECONHUB_AUTH_BEARER vazio sem extraEnv: logs=%v", logs)
	}
}

func TestRunStillInjectsTargetAndParams(t *testing.T) {
	// regressão: extraEnv não pode substituir o env base (RECONHUB_TARGET,
	// RECONHUB_PARAM_*) — só complementa.
	job := &store.Job{ID: "j3", Target: "acme.com", Params: map[string]any{"max": 5}}
	var logs []string
	res := Run(context.Background(), echoTool(`echo "t=$RECONHUB_TARGET m=$RECONHUB_PARAM_MAX"`), job,
		[]string{"RECONHUB_AUTH_COOKIE=session=x"},
		func(e store.Event) {
			if e.Type == "log" {
				logs = append(logs, e.Msg)
			}
		},
		func(store.Finding) {}, func(store.Asset) {},
	)
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	found := false
	for _, l := range logs {
		if l == "t=acme.com m=5" {
			found = true
		}
	}
	if !found {
		t.Fatalf("target/params sumiram com extraEnv presente: logs=%v", logs)
	}
}
