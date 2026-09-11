package store

import (
	"encoding/json"
	"time"
)

// Job lifecycle states.
const (
	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusCanceled  = "canceled"
	// StatusSkipped is used for a pipeline step whose dependency failed.
	StatusSkipped = "skipped"
)

// Job is one execution of a tool against a target.
type Job struct {
	ID        string         `json:"id"`
	Tool      string         `json:"tool"`
	Target    string         `json:"target"`
	Program   string         `json:"program,omitempty"`
	Params    map[string]any `json:"params,omitempty"`
	Status    string         `json:"status"`
	ExitCode  *int           `json:"exit_code,omitempty"`
	Error     string         `json:"error,omitempty"`
	Findings  int            `json:"findings"`
	CreatedAt time.Time      `json:"created_at"`
	StartedAt *time.Time     `json:"started_at,omitempty"`
	EndedAt   *time.Time     `json:"ended_at,omitempty"`
}

// Event is a single normalized line of output from a running job.
// Type is one of: log, progress, finding, done, error.
type Event struct {
	Seq   int             `json:"seq"`
	JobID string          `json:"job_id"`
	Time  time.Time       `json:"time"`
	Type  string          `json:"type"`
	Level string          `json:"level,omitempty"`
	Msg   string          `json:"msg,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Asset is something a tool discovered (a subdomain, URL, bucket, endpoint…).
// Pipelines feed assets from one step into the next step's parameters.
type Asset struct {
	ID        string          `json:"id"`
	JobID     string          `json:"job_id"`
	Tool      string          `json:"tool"`
	Program   string          `json:"program,omitempty"`
	Kind      string          `json:"kind"` // subdomain | url | bucket | endpoint | ip | ""
	Value     string          `json:"value"`
	Meta      json.RawMessage `json:"meta,omitempty"` // optional: http_status, content_type, etc — set by tools that already know it at discovery time
	CreatedAt time.Time       `json:"created_at"`
}

// AssetFilter narrows an asset listing. Zero values mean "no filter".
type AssetFilter struct {
	JobID   string
	Tool    string
	Program string
	Kind    string
	Limit   int
}

// Finding is a normalized result emitted by a tool. The store deduplicates
// findings by Key() — a repeat bumps Count and LastSeen instead of adding a row,
// so re-running a program's recon stays idempotent.
type Finding struct {
	ID        string          `json:"id"`
	JobID     string          `json:"job_id"`
	Tool      string          `json:"tool"`
	Program   string          `json:"program,omitempty"`
	Target    string          `json:"target"`
	Type      string          `json:"type"`
	Severity  string          `json:"severity"`
	Title     string          `json:"title"`
	Asset     string          `json:"asset,omitempty"`
	Evidence  string          `json:"evidence,omitempty"`
	Meta      json.RawMessage `json:"meta,omitempty"`
	Count     int             `json:"count"`
	CreatedAt time.Time       `json:"created_at"` // first seen
	LastSeen  time.Time       `json:"last_seen"`

	// Triage is optional operator feedback: "" | "confirmed" | "false_positive"
	// | "ignored". internal/intel uses the accumulated history (grouped by
	// tool+type) to weigh how much to trust new findings of the same kind.
	Triage    string     `json:"triage,omitempty"`
	TriagedAt *time.Time `json:"triaged_at,omitempty"`
}

// Key is the dedup identity of a finding.
func (f Finding) Key() string {
	return f.Program + "\x00" + f.Tool + "\x00" + f.Type + "\x00" + f.Asset + "\x00" + f.Title
}

// PipelineRun is one execution of a multi-step pipeline. Each step is also a
// normal Job (referenced by StepRun.JobID), so steps show up in the jobs list
// and stream individually.
type PipelineRun struct {
	ID        string     `json:"id"`
	Pipeline  string     `json:"pipeline"`
	Target    string     `json:"target"`
	Program   string     `json:"program,omitempty"`
	Status    string     `json:"status"`
	Steps     []StepRun  `json:"steps"`
	Findings  int        `json:"findings"`
	Error     string     `json:"error,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
}

// StepRun is the state of one pipeline step.
type StepRun struct {
	Index  int      `json:"index"`
	ID     string   `json:"id,omitempty"` // stable step id (for fan-out refs)
	Tool   string   `json:"tool"`
	JobID  string   `json:"job_id,omitempty"`
	Status string   `json:"status"`
	Fed    int      `json:"fed"`             // values fed in from upstream
	Needs  []string `json:"needs,omitempty"` // step ids this one waited for
}

// PipelineRunFilter narrows a run listing. Zero values mean "no filter".
type PipelineRunFilter struct {
	Pipeline string
	Program  string
	Status   string
	Limit    int
}

// JobFilter narrows a job listing. Zero values mean "no filter".
type JobFilter struct {
	Tool    string
	Program string
	Status  string
	Target  string
	Limit   int
}

// FindingFilter narrows a finding listing. Zero values mean "no filter".
type FindingFilter struct {
	JobID    string
	Tool     string
	Program  string
	Target   string
	Severity string
	Type     string
	Limit    int
}
