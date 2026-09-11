package store

// Store is the persistence surface the engine and API depend on. FileStore is
// the default implementation (append-only JSON-lines, zero deps); a SQLite
// implementation is available when the binary is built with `-tags sqlite`.
type Store interface {
	CreateJob(j *Job) error
	UpdateJob(j *Job) error
	GetJob(id string) (*Job, bool)
	ListJobs(f JobFilter) ([]*Job, error)

	AppendEvent(e Event) (Event, error)
	ListEvents(jobID string, sinceSeq int) ([]Event, error)

	AddFinding(f *Finding) (isNew bool, err error)
	ListFindings(f FindingFilter) ([]*Finding, error)
	GetFinding(id string) (*Finding, bool)
	SetFindingTriage(id, verdict, reason string) (*Finding, error)

	AddAsset(a *Asset) (isNew bool, err error)
	ListAssets(f AssetFilter) ([]*Asset, error)

	CreatePipelineRun(p *PipelineRun) error
	UpdatePipelineRun(p *PipelineRun) error
	GetPipelineRun(id string) (*PipelineRun, bool)
	ListPipelineRuns(f PipelineRunFilter) ([]*PipelineRun, error)

	Close() error
}

var _ Store = (*FileStore)(nil)
