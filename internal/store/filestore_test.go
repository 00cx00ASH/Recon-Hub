package store

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAddFindingDedup(t *testing.T) {
	fs, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	mk := func(sev string) *Finding {
		return &Finding{
			ID: "x", JobID: "j1", Tool: "scan-x", Program: "acme",
			Type: "takeover", Title: "t", Asset: "a.acme.com", Severity: sev,
			CreatedAt: time.Now().UTC(),
		}
	}

	isNew, err := fs.AddFinding(mk("high"))
	if err != nil || !isNew {
		t.Fatalf("1ª vez deveria ser nova: new=%v err=%v", isNew, err)
	}
	isNew, _ = fs.AddFinding(mk("high"))
	if isNew {
		t.Fatal("2ª vez (mesma Key) não deveria ser nova")
	}
	isNew, _ = fs.AddFinding(mk("high"))
	if isNew {
		t.Fatal("3ª vez não deveria ser nova")
	}

	list, _ := fs.ListFindings(FindingFilter{})
	if len(list) != 1 {
		t.Fatalf("esperava 1 finding deduplicado, veio %d", len(list))
	}
	if list[0].Count != 3 {
		t.Fatalf("Count = %d, quer 3", list[0].Count)
	}

	// program diferente = finding diferente
	f := mk("high")
	f.Program = "other"
	isNew, _ = fs.AddFinding(f)
	if !isNew {
		t.Fatal("programa diferente deveria ser finding novo")
	}
	if got, _ := fs.ListFindings(FindingFilter{Program: "acme"}); len(got) != 1 {
		t.Fatalf("filtro program=acme: %d", len(got))
	}
}

func TestSetFindingTriage(t *testing.T) {
	fs, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	f := &Finding{ID: "f1", JobID: "j1", Tool: "scan-x", Type: "takeover", Title: "t", Asset: "a.acme.com", Severity: "high", CreatedAt: time.Now().UTC()}
	if _, err := fs.AddFinding(f); err != nil {
		t.Fatal(err)
	}

	got, err := fs.SetFindingTriage("f1", "confirmed")
	if err != nil {
		t.Fatal(err)
	}
	if got.Triage != "confirmed" || got.TriagedAt == nil {
		t.Fatalf("triage não aplicado: %+v", got)
	}

	list, _ := fs.ListFindings(FindingFilter{})
	if len(list) != 1 || list[0].Triage != "confirmed" {
		t.Fatalf("triage não persistiu: %+v", list)
	}

	if _, err := fs.SetFindingTriage("ghost", "confirmed"); err == nil {
		t.Fatal("esperava erro para finding inexistente")
	}
}

func TestGetFinding(t *testing.T) {
	fs, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	f := &Finding{ID: "f1", JobID: "j1", Tool: "scan-x", Type: "takeover", Title: "t", Asset: "a.acme.com", Severity: "high", CreatedAt: time.Now().UTC()}
	if _, err := fs.AddFinding(f); err != nil {
		t.Fatal(err)
	}

	got, ok := fs.GetFinding("f1")
	if !ok || got.Title != "t" || got.Asset != "a.acme.com" {
		t.Fatalf("GetFinding: ok=%v got=%+v", ok, got)
	}

	if _, ok := fs.GetFinding("ghost"); ok {
		t.Fatal("esperava ok=false para finding inexistente")
	}
}

func TestAssetMetaSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	fs, _ := Open(dir)
	a := &Asset{JobID: "j", Tool: "recon-web-enum", Kind: "url", Value: "https://a.acme.com/admin",
		Meta: json.RawMessage(`{"http_status":403,"confirmed":false}`), CreatedAt: time.Now().UTC()}
	if _, err := fs.AddAsset(a); err != nil {
		t.Fatal(err)
	}
	fs.Close()

	fs2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs2.Close()
	list, _ := fs2.ListAssets(AssetFilter{})
	if len(list) != 1 {
		t.Fatalf("após reabrir: %d assets", len(list))
	}
	var meta struct {
		HTTPStatus int  `json:"http_status"`
		Confirmed  bool `json:"confirmed"`
	}
	if err := json.Unmarshal(list[0].Meta, &meta); err != nil {
		t.Fatalf("meta não voltou como JSON válido: %v (raw: %s)", err, list[0].Meta)
	}
	if meta.HTTPStatus != 403 || meta.Confirmed {
		t.Errorf("meta do asset não bateu após reabrir: %+v", meta)
	}
}

func TestAddFindingDedupSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	fs, _ := Open(dir)
	base := &Finding{JobID: "j", Tool: "t", Type: "x", Title: "y", Asset: "a", CreatedAt: time.Now().UTC()}
	fs.AddFinding(base)
	fs.AddFinding(base)
	fs.Close()

	fs2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs2.Close()
	list, _ := fs2.ListFindings(FindingFilter{})
	if len(list) != 1 || list[0].Count != 2 {
		t.Fatalf("após reabrir: %d findings, count=%v", len(list), list[0].Count)
	}
}
