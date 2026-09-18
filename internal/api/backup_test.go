package api

import (
	"testing"
	"time"

	"reconhub/internal/auth"
	"reconhub/internal/bus"
	"reconhub/internal/engine"
	"reconhub/internal/monitor"
	"reconhub/internal/pipeline"
	"reconhub/internal/project"
	"reconhub/internal/registry"
	"reconhub/internal/scope"
	"reconhub/internal/scopetemplate"
	"reconhub/internal/store"
)

// backupServer builds a Server whose registries all live in fresh, writable
// temp dirs, so Save/AddFinding/etc. persist. Returns the Server (the backup
// helpers are methods on it) so a test can collect/restore directly.
func backupServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	reg, err := registry.Load(t.TempDir())
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	progs, err := scope.Load(t.TempDir())
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	tpls, err := scopetemplate.Load(t.TempDir())
	if err != nil {
		t.Fatalf("scopetemplate: %v", err)
	}
	watches, err := monitor.Load(t.TempDir())
	if err != nil {
		t.Fatalf("monitor: %v", err)
	}
	pipes, _ := pipeline.Load(t.TempDir())
	eng := engine.New(st, reg, bus.New(), 2)
	return &Server{
		Store: st, Reg: reg, Engine: eng, Pipelines: pipes,
		Programs: progs, ScopeTemplates: tpls, Watches: watches,
		Token: auth.Token{Value: "t"}, DataDir: t.TempDir(),
	}
}

// seedInstance fills a server with one of every backable entity.
func seedInstance(t *testing.T, s *Server) {
	t.Helper()
	now := time.Now().UTC()
	if err := s.Programs.Save(scope.Program{Name: "acme", Platform: "hackerone", InScope: []string{"*.acme.com"}}); err != nil {
		t.Fatalf("save program: %v", err)
	}
	if err := s.ScopeTemplates.Save(scopetemplate.Template{Name: "h1", Platform: "hackerone", OutOfScope: []string{"blog.acme.com"}}); err != nil {
		t.Fatalf("save template: %v", err)
	}
	if err := s.Watches.Save(monitor.Watch{Name: "w1", Pipeline: "full-recon", Target: "*.acme.com", Program: "acme", Every: "6h", Enabled: true}); err != nil {
		t.Fatalf("save watch: %v", err)
	}
	if err := s.Store.CreateJob(&store.Job{ID: "job1", Tool: "recon-crtsh", Target: "acme.com", Program: "acme", Status: "succeeded", CreatedAt: now}); err != nil {
		t.Fatalf("create job: %v", err)
	}
	if _, err := s.Store.AddFinding(&store.Finding{ID: "f1", JobID: "job1", Tool: "scan-xss", Program: "acme", Type: "xss", Severity: "high", Title: "refletido", Asset: "https://app.acme.com/q", Triage: "confirmed", CreatedAt: now}); err != nil {
		t.Fatalf("add finding: %v", err)
	}
	if _, err := s.Store.AddAsset(&store.Asset{ID: "a1", JobID: "job1", Tool: "recon-crtsh", Program: "acme", Kind: "subdomain", Value: "app.acme.com", CreatedAt: now}); err != nil {
		t.Fatalf("add asset: %v", err)
	}
	if err := s.Store.CreatePipelineRun(&store.PipelineRun{ID: "pr1", Pipeline: "full-recon", Target: "acme.com", Program: "acme", Status: "succeeded", CreatedAt: now}); err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := project.WriteNotes(s.DataDir, "acme", "## sessão 1\nachei um xss"); err != nil {
		t.Fatalf("notes: %v", err)
	}
	if err := project.WriteLessons(s.DataDir, "# lições\nWAF da acme bloqueia UA vazio"); err != nil {
		t.Fatalf("lessons: %v", err)
	}
	if err := project.SaveAuth(s.DataDir, "acme", project.Auth{Bearer: "secret-token"}); err != nil {
		t.Fatalf("auth: %v", err)
	}
}

func TestBackupRoundTrip(t *testing.T) {
	src := backupServer(t)
	seedInstance(t, src)

	// Sem secrets: auth NÃO entra no bundle.
	if b := src.collectBackup(false); len(b.Auth) != 0 {
		t.Fatalf("sem ?secrets, auth não deveria ser exportado; veio %v", b.Auth)
	}

	b := src.collectBackup(true)
	if len(b.Programs) != 1 || len(b.ScopeTemplates) != 1 || len(b.Watches) != 1 {
		t.Fatalf("bundle faltando registries: %+v", b)
	}
	if len(b.Findings) != 1 || len(b.Assets) != 1 || len(b.Jobs) != 1 || len(b.PipelineRuns) != 1 {
		t.Fatalf("bundle faltando dados do store: findings=%d assets=%d jobs=%d runs=%d",
			len(b.Findings), len(b.Assets), len(b.Jobs), len(b.PipelineRuns))
	}
	if b.Notes["acme"] == "" || b.Lessons == "" || b.Auth["acme"].Bearer != "secret-token" {
		t.Fatalf("bundle faltando notes/lessons/auth: notes=%q lessons=%q auth=%+v", b.Notes["acme"], b.Lessons, b.Auth["acme"])
	}

	// Restaura num instância zerado — o cenário de recuperação de desastre.
	dst := backupServer(t)
	sum := dst.restoreBackup(b)
	if sum.Programs.Added != 1 || sum.ScopeTemplates.Added != 1 || sum.Watches.Added != 1 ||
		sum.Findings.Added != 1 || sum.Assets.Added != 1 || sum.Jobs.Added != 1 ||
		sum.PipelineRuns.Added != 1 || sum.Notes.Added != 1 || sum.Lessons.Added != 1 || sum.Auth.Added != 1 {
		t.Fatalf("nem tudo foi restaurado: %+v (warnings: %v)", sum, sum.Warnings)
	}
	if len(sum.Warnings) != 0 {
		t.Fatalf("restore não deveria ter warnings: %v", sum.Warnings)
	}

	// Confere que os dados realmente aterrissaram no destino.
	if _, ok := dst.Programs.Get("acme"); !ok {
		t.Fatal("programa acme não restaurado")
	}
	fs, _ := dst.Store.ListFindings(store.FindingFilter{Limit: 10})
	if len(fs) != 1 || fs[0].Triage != "confirmed" {
		t.Fatalf("finding não restaurado com triagem: %+v", fs)
	}
	if txt, _ := project.ReadNotes(dst.DataDir, "acme"); txt == "" {
		t.Fatal("notas não restauradas")
	}
	if a, _ := project.LoadAuth(dst.DataDir, "acme"); a.Bearer != "secret-token" {
		t.Fatalf("auth não restaurado: %+v", a)
	}

	// Idempotência: reimportar o mesmo bundle não duplica nada.
	sum2 := dst.restoreBackup(b)
	if sum2.Programs.Added != 0 || sum2.Findings.Added != 0 || sum2.Assets.Added != 0 ||
		sum2.Jobs.Added != 0 || sum2.PipelineRuns.Added != 0 || sum2.Notes.Added != 0 ||
		sum2.Lessons.Added != 0 || sum2.Auth.Added != 0 || sum2.ScopeTemplates.Added != 0 || sum2.Watches.Added != 0 {
		t.Fatalf("reimport deveria pular tudo (idempotente), veio %+v", sum2)
	}
	if fs2, _ := dst.Store.ListFindings(store.FindingFilter{Limit: 10}); len(fs2) != 1 {
		t.Fatalf("reimport duplicou finding: %d", len(fs2))
	}
}

// TestRestoreNeverClobbersLiveText: notes/lessons já preenchidos no destino
// não são sobrescritos por um restore (só um destino vazio recebe o texto).
func TestRestoreNeverClobbersLiveText(t *testing.T) {
	src := backupServer(t)
	seedInstance(t, src)
	b := src.collectBackup(true)

	dst := backupServer(t)
	if err := dst.Programs.Save(scope.Program{Name: "acme", InScope: []string{"*.acme.com"}}); err != nil {
		t.Fatalf("seed dst program: %v", err)
	}
	if err := project.WriteNotes(dst.DataDir, "acme", "MINHAS notas — não mexer"); err != nil {
		t.Fatalf("seed dst notes: %v", err)
	}
	sum := dst.restoreBackup(b)
	if sum.Notes.Skipped != 1 || sum.Notes.Added != 0 {
		t.Fatalf("notas existentes deveriam ser puladas: %+v", sum.Notes)
	}
	if txt, _ := project.ReadNotes(dst.DataDir, "acme"); txt != "MINHAS notas — não mexer" {
		t.Fatalf("restore sobrescreveu notas vivas: %q", txt)
	}
}
