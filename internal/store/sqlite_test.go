//go:build sqlite

package store

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func openTmp(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSQLiteJobRoundTrip(t *testing.T) {
	s := openTmp(t)
	j := &Job{ID: "j1", Tool: "x", Target: "acme.com", Program: "acme", Status: StatusQueued,
		Params: map[string]any{"n": float64(3)}, CreatedAt: time.Now()}
	if err := s.CreateJob(j); err != nil {
		t.Fatal(err)
	}
	ec := 0
	now := time.Now()
	j.Status = StatusSucceeded
	j.ExitCode = &ec
	j.EndedAt = &now
	j.Findings = 5
	if err := s.UpdateJob(j); err != nil {
		t.Fatal(err)
	}
	got, ok := s.GetJob("j1")
	if !ok || got.Status != StatusSucceeded || got.Findings != 5 || got.ExitCode == nil || *got.ExitCode != 0 {
		t.Fatalf("got %+v", got)
	}
	if got.Params["n"] != float64(3) {
		t.Errorf("params = %v", got.Params)
	}
	if got.EndedAt == nil {
		t.Error("ended_at deveria persistir")
	}
	list, _ := s.ListJobs(JobFilter{Program: "acme"})
	if len(list) != 1 {
		t.Errorf("ListJobs = %d", len(list))
	}
}

func TestSQLiteFindingDedup(t *testing.T) {
	s := openTmp(t)
	mk := func() *Finding {
		return &Finding{JobID: "j", Tool: "scan-x", Program: "acme", Type: "cors", Title: "t",
			Asset: "https://a", Severity: "high", Evidence: "e1"}
	}
	isNew, err := s.AddFinding(mk())
	if err != nil || !isNew {
		t.Fatalf("1ª: isNew=%v err=%v", isNew, err)
	}
	f2 := mk()
	f2.Evidence = "e2"
	isNew, err = s.AddFinding(f2)
	if err != nil || isNew {
		t.Fatalf("2ª (mesma key): isNew=%v err=%v", isNew, err)
	}
	fs, _ := s.ListFindings(FindingFilter{Program: "acme"})
	if len(fs) != 1 {
		t.Fatalf("deveria ter deduplicado para 1, tem %d", len(fs))
	}
	if fs[0].Count != 2 {
		t.Errorf("count = %d, quer 2", fs[0].Count)
	}
	if fs[0].Evidence != "e2" {
		t.Errorf("evidência não atualizou: %q", fs[0].Evidence)
	}
	// key diferente -> novo
	f3 := mk()
	f3.Asset = "https://b"
	if isNew, _ := s.AddFinding(f3); !isNew {
		t.Error("asset diferente deveria ser novo")
	}
}

func TestSQLiteSetFindingTriage(t *testing.T) {
	s := openTmp(t)
	f := &Finding{JobID: "j", Tool: "scan-x", Type: "takeover", Title: "t", Asset: "a.acme.com", Severity: "high"}
	if _, err := s.AddFinding(f); err != nil {
		t.Fatal(err)
	}
	fs, _ := s.ListFindings(FindingFilter{})
	if len(fs) != 1 {
		t.Fatalf("esperava 1 finding, veio %d", len(fs))
	}
	id := fs[0].ID

	got, err := s.SetFindingTriage(id, "false_positive", "confirmei manualmente, era um 403 sem prova")
	if err != nil {
		t.Fatal(err)
	}
	if got.Triage != "false_positive" || got.TriagedAt == nil {
		t.Fatalf("triage não aplicado: %+v", got)
	}
	if got.TriageReason != "confirmei manualmente, era um 403 sem prova" {
		t.Fatalf("triage_reason não aplicado: %+v", got)
	}

	fs2, _ := s.ListFindings(FindingFilter{})
	if len(fs2) != 1 || fs2[0].Triage != "false_positive" || fs2[0].TriageReason == "" {
		t.Fatalf("triage não persistiu: %+v", fs2)
	}

	if _, err := s.SetFindingTriage("ghost", "confirmed", ""); err == nil {
		t.Fatal("esperava erro para finding inexistente")
	}
}

func TestSQLiteGetFinding(t *testing.T) {
	s := openTmp(t)
	f := &Finding{JobID: "j", Tool: "scan-x", Type: "takeover", Title: "t", Asset: "a.acme.com", Severity: "high"}
	if _, err := s.AddFinding(f); err != nil {
		t.Fatal(err)
	}
	fs, _ := s.ListFindings(FindingFilter{})
	if len(fs) != 1 {
		t.Fatalf("esperava 1 finding, veio %d", len(fs))
	}
	id := fs[0].ID

	got, ok := s.GetFinding(id)
	if !ok || got.Title != "t" || got.Asset != "a.acme.com" {
		t.Fatalf("GetFinding: ok=%v got=%+v", ok, got)
	}

	if _, ok := s.GetFinding("ghost"); ok {
		t.Fatal("esperava ok=false para finding inexistente")
	}
}

func TestSQLiteDedupSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.db")
	s1, _ := OpenSQLite(path)
	f := &Finding{JobID: "j", Tool: "t", Type: "x", Title: "y", Asset: "a", Severity: "low"}
	s1.AddFinding(f)
	s1.Close()

	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	f2 := &Finding{JobID: "j", Tool: "t", Type: "x", Title: "y", Asset: "a", Severity: "low"}
	if isNew, _ := s2.AddFinding(f2); isNew {
		t.Error("após reabrir, a mesma key deveria deduplicar (não ser nova)")
	}
	fs, _ := s2.ListFindings(FindingFilter{})
	if len(fs) != 1 || fs[0].Count != 2 {
		t.Errorf("fs = %d, count = %d", len(fs), fs[0].Count)
	}
}

func TestSQLiteEventsSeq(t *testing.T) {
	s := openTmp(t)
	for i := 0; i < 3; i++ {
		e, err := s.AppendEvent(Event{JobID: "j", Type: "log", Msg: "x"})
		if err != nil {
			t.Fatal(err)
		}
		if e.Seq != i+1 {
			t.Errorf("seq = %d, quer %d", e.Seq, i+1)
		}
	}
	evs, _ := s.ListEvents("j", 1)
	if len(evs) != 2 || evs[0].Seq != 2 {
		t.Errorf("ListEvents(since 1) = %+v", evs)
	}
}

func TestSQLiteAssetsAndRuns(t *testing.T) {
	s := openTmp(t)
	if isNew, _ := s.AddAsset(&Asset{JobID: "j", Kind: "subdomain", Value: "a.acme.com", Tool: "t"}); !isNew {
		t.Error("1º asset novo")
	}
	if isNew, _ := s.AddAsset(&Asset{JobID: "j", Kind: "subdomain", Value: "a.acme.com", Tool: "t"}); isNew {
		t.Error("asset repetido não é novo")
	}
	as, _ := s.ListAssets(AssetFilter{Kind: "subdomain"})
	if len(as) != 1 {
		t.Errorf("assets = %d", len(as))
	}

	if _, err := s.AddAsset(&Asset{JobID: "j", Kind: "url", Value: "https://a.acme.com/admin", Tool: "t",
		Meta: json.RawMessage(`{"http_status":403,"confirmed":false}`)}); err != nil {
		t.Fatalf("AddAsset com meta: %v", err)
	}
	urlAssets, _ := s.ListAssets(AssetFilter{Kind: "url"})
	if len(urlAssets) != 1 {
		t.Fatalf("assets kind=url = %d", len(urlAssets))
	}
	var meta struct {
		HTTPStatus int  `json:"http_status"`
		Confirmed  bool `json:"confirmed"`
	}
	if err := json.Unmarshal(urlAssets[0].Meta, &meta); err != nil {
		t.Fatalf("meta não voltou como JSON válido: %v (raw: %s)", err, urlAssets[0].Meta)
	}
	if meta.HTTPStatus != 403 || meta.Confirmed {
		t.Errorf("meta do asset não bateu: %+v", meta)
	}

	run := &PipelineRun{ID: "r1", Pipeline: "p", Target: "acme.com", Status: StatusRunning,
		Steps: []StepRun{{Index: 0, ID: "s1", Tool: "t", Status: StatusSucceeded}}, CreatedAt: time.Now()}
	if err := s.CreatePipelineRun(run); err != nil {
		t.Fatal(err)
	}
	run.Status = StatusSucceeded
	run.Findings = 4
	s.UpdatePipelineRun(run)
	got, ok := s.GetPipelineRun("r1")
	if !ok || got.Status != StatusSucceeded || got.Findings != 4 || len(got.Steps) != 1 || got.Steps[0].ID != "s1" {
		t.Fatalf("run = %+v", got)
	}
}
