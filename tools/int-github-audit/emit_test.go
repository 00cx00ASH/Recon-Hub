package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
)

// TestEmitTagsFindingsAsPublicSource verifies every finding this tool emits
// gets meta.source="public" — everything it looks at (repos/gists/workflows)
// is public GitHub data, and most bug-bounty programs explicitly exclude
// "leaked credentials found via public sources" as out-of-scope noise. The
// UI reads this tag to let an operator filter/exclude these per program.
func TestEmitTagsFindingsAsPublicSource(t *testing.T) {
	var buf bytes.Buffer
	orig := out
	out = bufio.NewWriter(&buf)
	defer func() { out = orig }()

	emit(ev{Type: "finding", Severity: "high", FindingType: "github-repo-secret", Title: "t"})
	emit(ev{Type: "finding", Severity: "medium", FindingType: "github-sensitive-file", Title: "t2",
		Meta: map[string]any{"repo": "acme/app"}})
	emit(ev{Type: "asset", Kind: "url", Value: "https://github.com/acme"})

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("esperava 3 linhas, veio %d: %s", len(lines), buf.String())
	}

	var f1, f2, a1 map[string]any
	if err := json.Unmarshal(lines[0], &f1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &f2); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[2], &a1); err != nil {
		t.Fatal(err)
	}

	meta1, _ := f1["meta"].(map[string]any)
	if meta1["source"] != "public" {
		t.Errorf("finding sem meta prévio: source = %v, quer \"public\"", meta1["source"])
	}

	meta2, _ := f2["meta"].(map[string]any)
	if meta2["source"] != "public" {
		t.Errorf("finding com meta prévio: source = %v, quer \"public\"", meta2["source"])
	}
	if meta2["repo"] != "acme/app" {
		t.Errorf("meta prévio (repo) foi perdido: %v", meta2)
	}

	if _, has := a1["meta"]; has {
		t.Errorf("evento asset não deveria ganhar meta.source: %v", a1)
	}
}
