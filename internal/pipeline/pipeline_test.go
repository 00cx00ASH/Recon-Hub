package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFeedSemantics(t *testing.T) {
	var nilFeed *Feed
	if !nilFeed.WantAssets() || !nilFeed.WantFindings() {
		t.Fatal("feed nil deve significar both")
	}

	f := &Feed{Source: "assets"}
	if !f.WantAssets() || f.WantFindings() {
		t.Fatalf("source=assets: %+v", f)
	}
	f = &Feed{Source: "findings"}
	if f.WantAssets() || !f.WantFindings() {
		t.Fatalf("source=findings: %+v", f)
	}

	if got := (&Feed{}).Join([]string{"a", "b"}); got != "a,b" {
		t.Fatalf("csv default: %q", got)
	}
	if got := (&Feed{As: "lines"}).Join([]string{"a", "b"}); got != "a\nb" {
		t.Fatalf("lines: %q", got)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("crtsh-takeover.json", `{
	  "description": "enum -> takeover",
	  "steps": [
	    {"tool": "recon-crtsh"},
	    {"tool": "scan-subdomain-takeover", "feed": {"param": "subdomains", "source": "assets", "kind": "subdomain"}}
	  ]
	}`)
	write("notes.txt", "ignored")

	r, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(r.List()) != 1 {
		t.Fatalf("esperava 1 pipeline, veio %d", len(r.List()))
	}
	p, ok := r.Get("crtsh-takeover") // nome default = arquivo
	if !ok {
		t.Fatal("pipeline não encontrada pelo nome do arquivo")
	}
	if len(p.Steps) != 2 || p.Steps[1].Feed == nil || p.Steps[1].Feed.Param != "subdomains" {
		t.Fatalf("steps/feed errados: %+v", p)
	}
}

func TestLoadRejectsBad(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"steps":[{"params":{}}]}`), 0o644)
	if _, err := Load(dir); err == nil {
		t.Fatal("esperava erro: step sem tool")
	}
}

func TestLoadMissingDirIsEmpty(t *testing.T) {
	r, err := Load(filepath.Join(t.TempDir(), "nao-existe"))
	if err != nil || len(r.List()) != 0 {
		t.Fatalf("dir ausente deve dar registry vazio: %v %d", err, len(r.List()))
	}
}

func TestPlanLinear(t *testing.T) {
	p := Pipeline{Name: "lin", Steps: []Step{
		{Tool: "a"},
		{Tool: "b", Feed: &Feed{Param: "x"}},
		{Tool: "c", Feed: &Feed{Param: "y"}},
	}}
	plan, err := p.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if plan[0].ID != "s1" || plan[1].ID != "s2" || plan[2].ID != "s3" {
		t.Fatalf("ids = %v", plan)
	}
	if len(plan[0].Deps) != 0 {
		t.Errorf("s1 sem deps, got %v", plan[0].Deps)
	}
	if len(plan[1].Deps) != 1 || plan[1].Deps[0] != "s1" || plan[1].FeedFrom != "s1" {
		t.Errorf("s2 deps=%v from=%q", plan[1].Deps, plan[1].FeedFrom)
	}
	if plan[2].Deps[0] != "s2" {
		t.Errorf("s3 deps=%v", plan[2].Deps)
	}
}

func TestPlanFanOut(t *testing.T) {
	p := Pipeline{Name: "fan", Steps: []Step{
		{ID: "recon", Tool: "recon-crtsh"},
		{ID: "takeover", Tool: "scan-subdomain-takeover", Feed: &Feed{Param: "subdomains", From: "recon"}},
		{ID: "cors", Tool: "scan-cors", Feed: &Feed{Param: "urls", From: "recon"}},
		{ID: "report", Tool: "example-echo", Needs: []string{"takeover", "cors"}},
	}}
	plan, err := p.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if plan[1].FeedFrom != "recon" || plan[2].FeedFrom != "recon" {
		t.Errorf("takeover/cors devem alimentar de recon: %v / %v", plan[1], plan[2])
	}
	if len(plan[3].Deps) != 2 {
		t.Errorf("report deps = %v (quer takeover+cors)", plan[3].Deps)
	}
}

func TestPlanErrors(t *testing.T) {
	// id duplicado
	if _, err := (Pipeline{Steps: []Step{{ID: "x", Tool: "a"}, {ID: "x", Tool: "b"}}}).Plan(); err == nil {
		t.Error("id duplicado deveria falhar")
	}
	// feed.from inexistente
	if _, err := (Pipeline{Steps: []Step{{Tool: "a"}, {Tool: "b", Feed: &Feed{Param: "p", From: "nope"}}}}).Plan(); err == nil {
		t.Error("feed.from inexistente deveria falhar")
	}
	// needs inexistente
	if _, err := (Pipeline{Steps: []Step{{Tool: "a"}, {Tool: "b", Needs: []string{"ghost"}}}}).Plan(); err == nil {
		t.Error("needs inexistente deveria falhar")
	}
	// ciclo
	if _, err := (Pipeline{Steps: []Step{
		{ID: "a", Tool: "t", Needs: []string{"b"}},
		{ID: "b", Tool: "t", Needs: []string{"a"}},
	}}).Plan(); err == nil {
		t.Error("ciclo deveria falhar")
	}
	// primeiro step com feed sem from
	if _, err := (Pipeline{Steps: []Step{{Tool: "a", Feed: &Feed{Param: "p"}}}}).Plan(); err == nil {
		t.Error("step 0 com feed sem from deveria falhar")
	}
}
