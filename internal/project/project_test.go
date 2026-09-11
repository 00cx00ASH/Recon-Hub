package project

import (
	"os"
	"path/filepath"
	"strings"
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

func TestLessonsEmptyByDefault(t *testing.T) {
	dataDir, _, _ := setup(t)
	got, err := ReadLessons(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("esperava vazio antes de qualquer lição, veio: %q", got)
	}
}

func TestAppendLessonRejectsEmptyText(t *testing.T) {
	dataDir, _, _ := setup(t)
	if err := AppendLesson(dataDir, Lesson{}); err == nil {
		t.Fatal("lição sem texto deveria ser rejeitada")
	}
}

func TestAppendLessonAccumulatesAndNeverClobbers(t *testing.T) {
	dataDir, _, _ := setup(t)

	if err := AppendLesson(dataDir, Lesson{
		Text: "este WAF bloqueia após ~20 requisições em 10s", Program: "acme", Tool: "scan-fuzz", Tags: []string{"waf", "rate-limit"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := AppendLesson(dataDir, Lesson{Text: "programas HackerOne costumam aceitar CORS wildcard sem credentials como info"}); err != nil {
		t.Fatal(err)
	}

	got, err := ReadLessons(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"este WAF bloqueia após ~20 requisições em 10s",
		"programa: acme", "tool: scan-fuzz", "#waf", "#rate-limit",
		"programas HackerOne costumam aceitar CORS wildcard",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lessons.md sem %q:\n%s", want, got)
		}
	}
	// a 1ª lição continua lá depois da 2ª — nunca foi sobrescrita
	if strings.Count(got, "- **") != 2 {
		t.Fatalf("esperava 2 entradas, veio:\n%s", got)
	}
}

func TestWriteLessonsOverwritesWholesale(t *testing.T) {
	dataDir, _, _ := setup(t)
	if err := AppendLesson(dataDir, Lesson{Text: "lição antiga"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteLessons(dataDir, "# reorganizado\n\n- lição reescrita\n"); err != nil {
		t.Fatal(err)
	}
	got, err := ReadLessons(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "lição antiga") || !strings.Contains(got, "lição reescrita") {
		t.Fatalf("WriteLessons deveria substituir tudo, veio:\n%s", got)
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

	sum, err := SyncFromStore(dataDir, "acme", progs, st, nil)
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
	for _, f := range []string{"summary.json", "report.md", "assets.json", "notes.md", "coverage.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("faltou %s: %v", f, err)
		}
	}
	// o escopo já vive em programs/<nome>.json — não duplicamos aqui.
	if _, err := os.Stat(filepath.Join(dir, "project.json")); !os.IsNotExist(err) {
		t.Error("project.json não deveria existir (duplicaria programs/<nome>.json)")
	}
}

func TestSyncUnknownProgram(t *testing.T) {
	dataDir, progs, st := setup(t)
	if _, err := SyncFromStore(dataDir, "ghost", progs, st, nil); err == nil {
		t.Fatal("esperava erro para programa desconhecido")
	}
}
