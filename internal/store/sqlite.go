//go:build sqlite

package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// New opens the configured storage backend.
func New(dataDir, backend, sqlitePath string) (Store, error) {
	switch backend {
	case "", "files", "file":
		return Open(dataDir)
	case "sqlite":
		if sqlitePath == "" {
			sqlitePath = filepath.Join(dataDir, "reconhub.db")
		}
		return OpenSQLite(sqlitePath)
	default:
		return nil, fmt.Errorf("backend de store desconhecido: %q", backend)
	}
}

// SQLiteStore is a Store backed by a single SQLite file (pure-Go driver).
type SQLiteStore struct {
	db *sql.DB
	mu sync.Mutex // serializes writes (mirrors FileStore semantics, keeps AddFinding atomic)
}

const schema = `
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, tool TEXT, target TEXT, program TEXT, params TEXT,
  status TEXT, exit_code INTEGER, error TEXT, findings INTEGER,
  created_at TEXT, started_at TEXT, ended_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_program ON jobs(program);

CREATE TABLE IF NOT EXISTS events (
  job_id TEXT, seq INTEGER, time TEXT, type TEXT, level TEXT, msg TEXT, data TEXT,
  PRIMARY KEY (job_id, seq)
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, dedup_key TEXT UNIQUE, job_id TEXT, tool TEXT, program TEXT,
  target TEXT, type TEXT, severity TEXT, title TEXT, asset TEXT, evidence TEXT,
  meta TEXT, count INTEGER, created_at TEXT, last_seen TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_job ON findings(job_id);
CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program);
CREATE INDEX IF NOT EXISTS idx_findings_last ON findings(last_seen);

CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY, dedup_key TEXT UNIQUE, job_id TEXT, tool TEXT, program TEXT,
  kind TEXT, value TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_assets_job ON assets(job_id);
CREATE INDEX IF NOT EXISTS idx_assets_program ON assets(program);

CREATE TABLE IF NOT EXISTS pipeline_runs (
  id TEXT PRIMARY KEY, pipeline TEXT, target TEXT, program TEXT, status TEXT,
  steps TEXT, findings INTEGER, error TEXT, created_at TEXT, started_at TEXT, ended_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_pruns_created ON pipeline_runs(created_at);
CREATE INDEX IF NOT EXISTS idx_pruns_program ON pipeline_runs(program);
`

// OpenSQLite opens (creating if needed) the database at path.
func OpenSQLite(path string) (*SQLiteStore, error) {
	if d := filepath.Dir(path); d != "" {
		_ = os.MkdirAll(d, 0o755)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // WAL + single writer keeps it simple and correct
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

// --- time helpers ---

func tstr(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func tptr(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func ptime(v sql.NullString) *time.Time {
	if !v.Valid || v.String == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339Nano, v.String); err == nil {
		u := t.UTC()
		return &u
	}
	return nil
}
func rtime(sv string) time.Time {
	if sv == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, sv)
	return t.UTC()
}
func jmarshal(v any) string {
	if v == nil {
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// --- jobs ---

func (s *SQLiteStore) CreateJob(j *Job) error { return s.upsertJob(j) }
func (s *SQLiteStore) UpdateJob(j *Job) error { return s.upsertJob(j) }

func (s *SQLiteStore) upsertJob(j *Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ec any
	if j.ExitCode != nil {
		ec = *j.ExitCode
	}
	_, err := s.db.Exec(`INSERT INTO jobs
	 (id,tool,target,program,params,status,exit_code,error,findings,created_at,started_at,ended_at)
	 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
	 ON CONFLICT(id) DO UPDATE SET tool=excluded.tool,target=excluded.target,program=excluded.program,
	 params=excluded.params,status=excluded.status,exit_code=excluded.exit_code,error=excluded.error,
	 findings=excluded.findings,created_at=excluded.created_at,started_at=excluded.started_at,ended_at=excluded.ended_at`,
		j.ID, j.Tool, j.Target, j.Program, jmarshal(j.Params), j.Status, ec, j.Error, j.Findings,
		tstr(j.CreatedAt), tptr(j.StartedAt), tptr(j.EndedAt))
	return err
}

func (s *SQLiteStore) GetJob(id string) (*Job, bool) {
	row := s.db.QueryRow(`SELECT id,tool,target,program,params,status,exit_code,error,findings,created_at,started_at,ended_at FROM jobs WHERE id=?`, id)
	j, err := scanJob(row)
	if err != nil {
		return nil, false
	}
	return j, true
}

type scanner interface{ Scan(...any) error }

func scanJob(sc scanner) (*Job, error) {
	var j Job
	var params, created string
	var started, ended sql.NullString
	var ec sql.NullInt64
	if err := sc.Scan(&j.ID, &j.Tool, &j.Target, &j.Program, &params, &j.Status, &ec, &j.Error, &j.Findings, &created, &started, &ended); err != nil {
		return nil, err
	}
	if params != "" {
		_ = json.Unmarshal([]byte(params), &j.Params)
	}
	if ec.Valid {
		v := int(ec.Int64)
		j.ExitCode = &v
	}
	j.CreatedAt = rtime(created)
	j.StartedAt = ptime(started)
	j.EndedAt = ptime(ended)
	return &j, nil
}

func (s *SQLiteStore) ListJobs(f JobFilter) ([]*Job, error) {
	q := `SELECT id,tool,target,program,params,status,exit_code,error,findings,created_at,started_at,ended_at FROM jobs`
	where, args := whereClause(map[string]string{
		"tool": f.Tool, "program": f.Program, "status": f.Status, "target": f.Target,
	})
	q += where + " ORDER BY created_at DESC" + limit(f.Limit, 100)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// --- events ---

func (s *SQLiteStore) AppendEvent(e Event) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var maxSeq sql.NullInt64
	_ = s.db.QueryRow(`SELECT MAX(seq) FROM events WHERE job_id=?`, e.JobID).Scan(&maxSeq)
	e.Seq = int(maxSeq.Int64) + 1
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	_, err := s.db.Exec(`INSERT INTO events (job_id,seq,time,type,level,msg,data) VALUES (?,?,?,?,?,?,?)`,
		e.JobID, e.Seq, tstr(e.Time), e.Type, e.Level, e.Msg, string(e.Data))
	return e, err
}

func (s *SQLiteStore) ListEvents(jobID string, sinceSeq int) ([]Event, error) {
	rows, err := s.db.Query(`SELECT seq,time,type,level,msg,data FROM events WHERE job_id=? AND seq>? ORDER BY seq`, jobID, sinceSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var tm, data string
		if err := rows.Scan(&e.Seq, &tm, &e.Type, &e.Level, &e.Msg, &data); err != nil {
			return nil, err
		}
		e.JobID = jobID
		e.Time = rtime(tm)
		if data != "" {
			e.Data = json.RawMessage(data)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- findings ---

func (s *SQLiteStore) AddFinding(f *Finding) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := f.Key()
	now := time.Now().UTC()
	if f.CreatedAt.IsZero() {
		f.CreatedAt = now
	}
	f.LastSeen = now

	var existingCount int
	err := s.db.QueryRow(`SELECT count FROM findings WHERE dedup_key=?`, key).Scan(&existingCount)
	if err == nil {
		f.Count = existingCount + 1
		_, uerr := s.db.Exec(`UPDATE findings SET count=?, last_seen=?, evidence=?, severity=?, meta=? WHERE dedup_key=?`,
			f.Count, tstr(f.LastSeen), f.Evidence, f.Severity, string(f.Meta), key)
		return false, uerr
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	if f.ID == "" {
		f.ID = newID()
	}
	if f.Count == 0 {
		f.Count = 1
	}
	_, ierr := s.db.Exec(`INSERT INTO findings
	 (id,dedup_key,job_id,tool,program,target,type,severity,title,asset,evidence,meta,count,created_at,last_seen)
	 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		f.ID, key, f.JobID, f.Tool, f.Program, f.Target, f.Type, f.Severity, f.Title, f.Asset,
		f.Evidence, string(f.Meta), f.Count, tstr(f.CreatedAt), tstr(f.LastSeen))
	return true, ierr
}

func (s *SQLiteStore) ListFindings(f FindingFilter) ([]*Finding, error) {
	q := `SELECT id,job_id,tool,program,target,type,severity,title,asset,evidence,meta,count,created_at,last_seen FROM findings`
	where, args := whereClause(map[string]string{
		"job_id": f.JobID, "tool": f.Tool, "program": f.Program, "target": f.Target,
		"severity": f.Severity, "type": f.Type,
	})
	q += where + " ORDER BY last_seen DESC" + limit(f.Limit, 500)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Finding
	for rows.Next() {
		var fd Finding
		var meta, created, last string
		if err := rows.Scan(&fd.ID, &fd.JobID, &fd.Tool, &fd.Program, &fd.Target, &fd.Type, &fd.Severity,
			&fd.Title, &fd.Asset, &fd.Evidence, &meta, &fd.Count, &created, &last); err != nil {
			return nil, err
		}
		if meta != "" {
			fd.Meta = json.RawMessage(meta)
		}
		fd.CreatedAt = rtime(created)
		fd.LastSeen = rtime(last)
		out = append(out, &fd)
	}
	return out, rows.Err()
}

// --- assets ---

func (s *SQLiteStore) AddAsset(a *Asset) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := a.JobID + "\x00" + a.Kind + "\x00" + a.Value
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM assets WHERE dedup_key=?`, key).Scan(&one)
	if err == nil {
		return false, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	if a.ID == "" {
		a.ID = newID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	_, ierr := s.db.Exec(`INSERT INTO assets (id,dedup_key,job_id,tool,program,kind,value,created_at) VALUES (?,?,?,?,?,?,?,?)`,
		a.ID, key, a.JobID, a.Tool, a.Program, a.Kind, a.Value, tstr(a.CreatedAt))
	return true, ierr
}

func (s *SQLiteStore) ListAssets(f AssetFilter) ([]*Asset, error) {
	q := `SELECT id,job_id,tool,program,kind,value,created_at FROM assets`
	where, args := whereClause(map[string]string{
		"job_id": f.JobID, "tool": f.Tool, "program": f.Program, "kind": f.Kind,
	})
	q += where + " ORDER BY created_at DESC" + limit(f.Limit, 1000)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Asset
	for rows.Next() {
		var a Asset
		var created string
		if err := rows.Scan(&a.ID, &a.JobID, &a.Tool, &a.Program, &a.Kind, &a.Value, &created); err != nil {
			return nil, err
		}
		a.CreatedAt = rtime(created)
		out = append(out, &a)
	}
	return out, rows.Err()
}

// --- pipeline runs ---

func (s *SQLiteStore) CreatePipelineRun(p *PipelineRun) error { return s.upsertRun(p) }
func (s *SQLiteStore) UpdatePipelineRun(p *PipelineRun) error { return s.upsertRun(p) }

func (s *SQLiteStore) upsertRun(p *PipelineRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO pipeline_runs
	 (id,pipeline,target,program,status,steps,findings,error,created_at,started_at,ended_at)
	 VALUES (?,?,?,?,?,?,?,?,?,?,?)
	 ON CONFLICT(id) DO UPDATE SET pipeline=excluded.pipeline,target=excluded.target,program=excluded.program,
	 status=excluded.status,steps=excluded.steps,findings=excluded.findings,error=excluded.error,
	 created_at=excluded.created_at,started_at=excluded.started_at,ended_at=excluded.ended_at`,
		p.ID, p.Pipeline, p.Target, p.Program, p.Status, jmarshal(p.Steps), p.Findings, p.Error,
		tstr(p.CreatedAt), tptr(p.StartedAt), tptr(p.EndedAt))
	return err
}

func (s *SQLiteStore) GetPipelineRun(id string) (*PipelineRun, bool) {
	row := s.db.QueryRow(`SELECT id,pipeline,target,program,status,steps,findings,error,created_at,started_at,ended_at FROM pipeline_runs WHERE id=?`, id)
	p, err := scanRun(row)
	if err != nil {
		return nil, false
	}
	return p, true
}

func scanRun(sc scanner) (*PipelineRun, error) {
	var p PipelineRun
	var steps, created string
	var started, ended sql.NullString
	if err := sc.Scan(&p.ID, &p.Pipeline, &p.Target, &p.Program, &p.Status, &steps, &p.Findings, &p.Error, &created, &started, &ended); err != nil {
		return nil, err
	}
	if steps != "" {
		_ = json.Unmarshal([]byte(steps), &p.Steps)
	}
	p.CreatedAt = rtime(created)
	p.StartedAt = ptime(started)
	p.EndedAt = ptime(ended)
	return &p, nil
}

func (s *SQLiteStore) ListPipelineRuns(f PipelineRunFilter) ([]*PipelineRun, error) {
	q := `SELECT id,pipeline,target,program,status,steps,findings,error,created_at,started_at,ended_at FROM pipeline_runs`
	where, args := whereClause(map[string]string{
		"pipeline": f.Pipeline, "program": f.Program, "status": f.Status,
	})
	q += where + " ORDER BY created_at DESC" + limit(f.Limit, 100)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*PipelineRun
	for rows.Next() {
		p, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// --- query helpers ---

func whereClause(eq map[string]string) (string, []any) {
	var parts []string
	var args []any
	// deterministic order
	for _, col := range []string{"job_id", "tool", "program", "status", "target", "severity", "type", "kind", "pipeline"} {
		if v, ok := eq[col]; ok && v != "" {
			parts = append(parts, col+"=?")
			args = append(args, v)
		}
	}
	if len(parts) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(parts, " AND "), args
}

func limit(n, def int) string {
	if n <= 0 {
		n = def
	}
	return fmt.Sprintf(" LIMIT %d", n)
}

// --- migration from FileStore ---

// Migrate imports every record from a FileStore at dataDir into a fresh SQLite
// database at sqlitePath.
func Migrate(dataDir, sqlitePath string) error {
	fs, err := Open(dataDir)
	if err != nil {
		return fmt.Errorf("abrir FileStore: %w", err)
	}
	defer fs.Close()
	if sqlitePath == "" {
		sqlitePath = filepath.Join(dataDir, "reconhub.db")
	}
	if _, err := os.Stat(sqlitePath); err == nil {
		return fmt.Errorf("%s já existe — mova ou apague antes de migrar", sqlitePath)
	}
	sq, err := OpenSQLite(sqlitePath)
	if err != nil {
		return err
	}
	defer sq.Close()

	jobs, _ := fs.ListJobs(JobFilter{Limit: 1 << 30})
	for _, j := range jobs {
		if err := sq.upsertJob(j); err != nil {
			return fmt.Errorf("job %s: %w", j.ID, err)
		}
		evs, _ := fs.ListEvents(j.ID, 0)
		for _, e := range evs {
			if _, err := sq.db.Exec(`INSERT OR IGNORE INTO events (job_id,seq,time,type,level,msg,data) VALUES (?,?,?,?,?,?,?)`,
				e.JobID, e.Seq, tstr(e.Time), e.Type, e.Level, e.Msg, string(e.Data)); err != nil {
				return fmt.Errorf("evento %s#%d: %w", e.JobID, e.Seq, err)
			}
		}
	}
	fnd, _ := fs.ListFindings(FindingFilter{Limit: 1 << 30})
	for _, f := range fnd {
		key := f.Key()
		if _, err := sq.db.Exec(`INSERT OR REPLACE INTO findings
		 (id,dedup_key,job_id,tool,program,target,type,severity,title,asset,evidence,meta,count,created_at,last_seen)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			orID(f.ID), key, f.JobID, f.Tool, f.Program, f.Target, f.Type, f.Severity, f.Title, f.Asset,
			f.Evidence, string(f.Meta), maxInt(f.Count, 1), tstr(f.CreatedAt), tstr(f.LastSeen)); err != nil {
			return fmt.Errorf("finding: %w", err)
		}
	}
	as, _ := fs.ListAssets(AssetFilter{Limit: 1 << 30})
	for _, a := range as {
		key := a.JobID + "\x00" + a.Kind + "\x00" + a.Value
		if _, err := sq.db.Exec(`INSERT OR IGNORE INTO assets (id,dedup_key,job_id,tool,program,kind,value,created_at) VALUES (?,?,?,?,?,?,?,?)`,
			orID(a.ID), key, a.JobID, a.Tool, a.Program, a.Kind, a.Value, tstr(a.CreatedAt)); err != nil {
			return fmt.Errorf("asset: %w", err)
		}
	}
	runs, _ := fs.ListPipelineRuns(PipelineRunFilter{Limit: 1 << 30})
	for _, p := range runs {
		if err := sq.upsertRun(p); err != nil {
			return fmt.Errorf("run %s: %w", p.ID, err)
		}
	}
	return nil
}

func orID(s string) string {
	if s == "" {
		return newID()
	}
	return s
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
