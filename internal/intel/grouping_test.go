package intel

import (
	"testing"

	"reconhub/internal/store"
)

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://a.acme.com/admin/x?y=1": "a.acme.com",
		"http://a.acme.com:8080/login":   "a.acme.com:8080",
		"a.acme.com":                     "a.acme.com",
		"a.acme.com:9000":                "a.acme.com",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestGroupSimilarCollapsesSamePattern(t *testing.T) {
	mk := func(asset, title string) *store.Finding {
		return &store.Finding{ID: asset, Tool: "scan-fuzz", Type: "sensitive-file-exposed", Severity: "medium", Asset: asset, Title: title}
	}
	findings := []*store.Finding{
		mk("https://a.acme.com/admin/x", "arquivo sensível: /admin/x"),
		mk("https://a.acme.com/admin/y", "arquivo sensível: /admin/y"),
		mk("https://a.acme.com/admin/z", "arquivo sensível: /admin/z"),
		mk("https://b.acme.com/config", "arquivo sensível: /config"), // host diferente, grupo separado (sozinho)
	}
	groups := GroupSimilar(findings)
	if len(groups) != 1 {
		t.Fatalf("groups = %d, quer 1 (b.acme.com fica sozinho, não vira grupo)", len(groups))
	}
	g := groups[0]
	if g.Host != "a.acme.com" || g.Total != 3 {
		t.Fatalf("group = %+v", g)
	}
	if len(g.FindingIDs) != 3 {
		t.Fatalf("finding_ids = %v", g.FindingIDs)
	}
}

func TestGroupSimilarDifferentTypeStaysSeparate(t *testing.T) {
	findings := []*store.Finding{
		{ID: "1", Tool: "scan-cors", Type: "cors-wildcard", Severity: "low", Asset: "https://a.com/api"},
		{ID: "2", Tool: "scan-cors", Type: "cors-reflect-credentials", Severity: "critical", Asset: "https://a.com/api"},
	}
	if groups := GroupSimilar(findings); len(groups) != 0 {
		t.Fatalf("tipos diferentes não deveriam agrupar: %+v", groups)
	}
}

func TestGroupSimilarSeverityIsWorstInGroup(t *testing.T) {
	findings := []*store.Finding{
		{ID: "1", Tool: "js-secret-hunter", Type: "secret", Severity: "low", Asset: "https://a.com/x.js", Title: "t1"},
		{ID: "2", Tool: "js-secret-hunter", Type: "secret", Severity: "critical", Asset: "https://a.com/y.js", Title: "t2"},
	}
	groups := GroupSimilar(findings)
	if len(groups) != 1 || groups[0].Severity != "critical" {
		t.Fatalf("groups = %+v, esperava severidade critical (a pior do grupo)", groups)
	}
}

func TestGroupSimilarSortedMostSevereFirst(t *testing.T) {
	dup := func(id, tool, sev string) *store.Finding {
		return &store.Finding{ID: id, Tool: tool, Type: "x", Severity: sev, Asset: "https://a.com/" + id}
	}
	findings := []*store.Finding{
		dup("1", "toollow", "low"), dup("2", "toollow", "low"),
		dup("3", "toolcrit", "critical"), dup("4", "toolcrit", "critical"),
	}
	groups := GroupSimilar(findings)
	if len(groups) != 2 || groups[0].Severity != "critical" || groups[1].Severity != "low" {
		t.Fatalf("groups = %+v, esperava critical antes de low", groups)
	}
}
