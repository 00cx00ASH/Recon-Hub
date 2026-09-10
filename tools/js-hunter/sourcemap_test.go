package main

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestMapCandidates(t *testing.T) {
	js := "console.log(1)\n//# sourceMappingURL=app.min.js.map\n"
	got := mapCandidates("https://x.com/static/app.min.js", js)
	want := map[string]bool{
		"https://x.com/static/app.min.js.map": true,
	}
	for _, g := range got {
		delete(want, g)
	}
	if len(want) != 0 {
		t.Errorf("faltou candidato, got %v", got)
	}
	// o palpite <js>.map também entra
	found := false
	for _, g := range got {
		if g == "https://x.com/static/app.min.js.map" {
			found = true
		}
	}
	if !found {
		t.Error("faltou o .map resolvido")
	}
}

func TestParseSourceMap(t *testing.T) {
	sm := map[string]any{
		"version":        3,
		"sources":        []string{"webpack://app/src/api.js", "webpack://app/src/empty.js"},
		"sourcesContent": []string{"export const API='/api/v1';", ""},
		"sourceRoot":     "",
	}
	b, _ := json.Marshal(sm)
	files, err := parseSourceMap(string(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %d", len(files))
	}
	if files[0].Path != "app/src/api.js" || files[0].Content == "" {
		t.Errorf("file0 = %+v", files[0])
	}
	if files[1].Content != "" {
		t.Errorf("file1 deveria estar sem conteúdo: %+v", files[1])
	}
}

func TestExtractEndpoints(t *testing.T) {
	code := `
	fetch("/api/v1/users?page=1").then(r=>r.json());
	axios.post("/api/v1/login", body);
	const cfg = { baseURL: "https://api.example.com/v2", url: "/internal/flags" };
	xhr.open("GET", "/admin/metrics");
	import("./chunk.js");
	fetch("/static/logo.png");
	const doc = "https://cdn.jsdelivr.net/npm/x/y.js";
	call("/graphql");
	`
	eps := extractEndpoints(code)
	refs := map[string][]string{}
	for _, e := range eps {
		refs[e.Ref] = append(refs[e.Ref], e.Method)
	}
	for _, want := range []string{"/api/v1/users?page=1", "/api/v1/login", "/internal/flags", "/admin/metrics", "/graphql", "https://api.example.com/v2"} {
		if _, ok := refs[want]; !ok {
			t.Errorf("faltou %q em %v", want, mapKeys(refs))
		}
	}
	if _, bad := refs["/static/logo.png"]; bad {
		t.Error("asset estático não deveria entrar")
	}
	if _, bad := refs["./chunk.js"]; bad {
		t.Error("import relativo de .js não deveria entrar")
	}
	if _, bad := refs["https://cdn.jsdelivr.net/npm/x/y.js"]; bad {
		t.Error("CDN não deveria entrar")
	}
	if !contains(refs["/api/v1/login"], "POST") {
		t.Errorf("método POST de /api/v1/login ausente: %v", refs["/api/v1/login"])
	}
}

func TestInterestingEndpoint(t *testing.T) {
	yes := []string{"/admin/users", "/api/graphql", "/internal/config", "/actuator/env", "/v1/oauth/token", "/export/csv"}
	for _, r := range yes {
		if ok, _ := interestingEndpoint(r); !ok {
			t.Errorf("%q deveria ser interessante", r)
		}
	}
	if ok, _ := interestingEndpoint("/api/v1/products"); ok {
		t.Error("/api/v1/products não é sensível por si só")
	}
}

func TestCdnHost(t *testing.T) {
	if !cdnHost("https://cdnjs.cloudflare.com/x") || !cdnHost("https://fonts.googleapis.com/css") {
		t.Error("CDNs conhecidas")
	}
	if cdnHost("https://api.example.com/v1") {
		t.Error("host da app não é CDN")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func mapKeys(m map[string][]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var _ = reflect.DeepEqual
