package project

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"reconhub/internal/scope"
	"reconhub/internal/store"
)

func setup(t *testing.T) (dataDir string, progs *scope.Registry, st *store.FileStore) {
	t.Helper()
	root := t.TempDir()
	dataDir = filepath.Join(root, "data")
	progDir := filepath.Join(root, "programs")
	if err := os.MkdirAll(progDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(progDir, "acme.json"), []byte(`{"name":"acme","in_scope":["*.acme.com"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var err error
	progs, err = scope.Load(progDir)
	if err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return
}

func TestInitCreatesFolderAndNotes(t *testing.T) {
	dataDir, _, _ := setup(t)
	if err := Init(dataDir, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "projects", "acme", "notes.md")); err != nil {
		t.Fatalf("notes.md não foi criado: %v", err)
	}
}

func TestInitDoesNotOverwriteNotes(t *testing.T) {
	dataDir, _, _ := setup(t)
	if err := Init(dataDir, "acme"); err != nil {
		t.Fatal(err)
	}
	if err := WriteNotes(dataDir, "acme", "minhas notas"); err != nil {
		t.Fatal(err)
	}
	if err := Init(dataDir, "acme"); err != nil {
		t.Fatal(err)
	}
	got, err := ReadNotes(dataDir, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if got != "minhas notas" {
		t.Fatalf("notas sobrescritas: %q", got)
	}
}

func TestInvalidNameRejected(t *testing.T) {
	dataDir, _, _ := setup(t)
	if err := Init(dataDir, "../evil"); err == nil {
		t.Fatal("esperava erro para nome inseguro")
	}
	if err := Init(dataDir, "UPPER CASE"); err == nil {
		t.Fatal("esperava erro para nome inválido")
	}
	if Dir(dataDir, "../evil") != "" {
		t.Fatal("Dir deveria recusar nome inseguro")
	}
}

func TestSyncFromStoreWritesSnapshot(t *testing.T) {
	dataDir, progs, st := setup(t)
	now := time.Now().UTC()

	job := &store.Job{ID: "j1", Tool: "recon-crtsh", Target: "acme.com", Program: "acme", Status: store.StatusSucceeded, CreatedAt: now}
	if err := st.CreateJob(job); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddFinding(&store.Finding{
		ID: "f1", JobID: "j1", Tool: "recon-crtsh", Program: "acme", Target: "acme.com",
		Type: "takeover", Severity: "high", Title: "dangling cname", Asset: "a.acme.com",
		CreatedAt: now, LastSeen: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddAsset(&store.Asset{
		ID: "a1", JobID: "j1", Tool: "recon-crtsh", Program: "acme", Kind: "subdomain", Value: "a.acme.com", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	sum, err := SyncFromStore(dataDir, "acme", progs, st)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Jobs != 1 || sum.Findings != 1 || sum.Assets != 1 {
		t.Fatalf("summary inesperado: %+v", sum)
	}
	if sum.FindingsBySeverity["high"] != 1 {
		t.Fatalf("severidade não contada: %+v", sum.FindingsBySeverity)
	}
	if sum.LastActivity == nil {
		t.Fatal("last_activity não deveria ser nil")
	}

	dir := Dir(dataDir, "acme")
	for _, f := range []string{"project.json", "summary.json", "report.md", "assets.json", "notes.md"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("faltou %s: %v", f, err)
		}
	}
}

func TestSyncUnknownProgram(t *testing.T) {
	dataDir, progs, st := setup(t)
	if _, err := SyncFromStore(dataDir, "ghost", progs, st); err == nil {
		t.Fatal("esperava erro para programa desconhecido")
	}
}
