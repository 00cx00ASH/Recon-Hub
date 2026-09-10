package main

import (
	"reflect"
	"sort"
	"testing"
)

func names(ds []dep) []string {
	var n []string
	for _, d := range ds {
		n = append(n, d.Name)
	}
	sort.Strings(n)
	return n
}

func TestParseNPM(t *testing.T) {
	m := `{
	  "name": "app",
	  "dependencies": {
	    "lodash": "^4.17.21",
	    "@acme/ui": "1.2.3",
	    "left-pad": "1.0.0",
	    "local-tool": "file:../local-tool",
	    "forked": "github:me/forked",
	    "tardep": "https://example.com/x.tgz"
	  },
	  "devDependencies": { "jest": "^29" }
	}`
	got := names(parseManifest("npm", m))
	want := []string{"@acme/ui", "jest", "left-pad", "lodash"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
}

func TestParsePyPI(t *testing.T) {
	req := "# comment\nDjango==4.2\nrequests>=2.0\nPyYAML\nsome_pkg[extra]==1.0\n-r other.txt\ngit+https://x/y.git\nhttps://example.com/pkg.whl\nnumpy ; python_version < '3.9'\n"
	got := names(parseManifest("pypi", req))
	want := []string{"django", "numpy", "pyyaml", "requests", "some-pkg"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
}

func TestParsePyprojectArray(t *testing.T) {
	py := "[project]\nname = \"x\"\ndependencies = [\n  \"httpx>=0.27\",\n  \"pydantic\",\n]\n"
	got := names(parseManifest("pypi", py))
	want := []string{"httpx", "pydantic"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
}

func TestParseCargo(t *testing.T) {
	c := "[package]\nname = \"x\"\n\n[dependencies]\nserde = \"1.0\"\ntokio = { version = \"1\", features = [\"full\"] }\nmylib = { path = \"../mylib\" }\nrenamed = { version = \"2\", package = \"real-crate\" }\n\n[dev-dependencies]\ncriterion = \"0.5\"\n"
	got := names(parseManifest("cargo", c))
	want := []string{"criterion", "real-crate", "serde", "tokio"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
}

func TestParseComposer(t *testing.T) {
	c := `{"require":{"php":">=8.1","ext-json":"*","monolog/monolog":"^3.0","acme/private-lib":"^1"},"require-dev":{"phpunit/phpunit":"^10"}}`
	got := names(parseManifest("composer", c))
	want := []string{"acme/private-lib", "monolog/monolog", "phpunit/phpunit"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
}

func TestSniffEcosystem(t *testing.T) {
	cases := map[string]string{
		`{"dependencies":{"a":"1"}}`:                "npm",
		`{"require":{"a/b":"1"},"dependencies":{}}`: "composer",
		"[dependencies]\nserde = \"1\"":             "cargo",
		"requests==2.0\nflask>=1":                   "pypi",
	}
	for in, want := range cases {
		if got := sniffEcosystem(in); got != want {
			t.Errorf("sniff(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestClassifyResult(t *testing.T) {
	bare := dep{Name: "left-pad", Ecosystem: "npm"}
	if v, hit := classifyResult(bare, "unclaimed", false); !hit || v.severity != "high" {
		t.Errorf("bare unclaimed → %+v hit=%v, quer high", v, hit)
	}
	if _, hit := classifyResult(bare, "claimed", false); hit {
		t.Error("claimed não deveria virar finding")
	}
	scoped := dep{Name: "@acme/ui", Ecosystem: "npm"}
	if v, _ := classifyResult(scoped, "unclaimed", false); v.severity != "medium" {
		t.Errorf("scoped w/ scope → %s, quer medium", v.severity)
	}
	if v, _ := classifyResult(scoped, "unclaimed", true); v.severity != "high" {
		t.Errorf("scoped w/ empty scope → %s, quer high", v.severity)
	}
	comp := dep{Name: "acme/lib", Ecosystem: "composer"}
	if v, _ := classifyResult(comp, "unclaimed", false); v.severity != "medium" {
		t.Errorf("composer → %s, quer medium", v.severity)
	}
}

func TestPkgFromSpecifier(t *testing.T) {
	cases := map[string]string{
		"lodash":           "lodash",
		"lodash/fp/get":    "lodash",
		"@acme/ui":         "@acme/ui",
		"@acme/ui/button":  "@acme/ui",
		"./local":          "",
		"../up":            "",
		"/abs":             "",
		"https://cdn/x.js": "",
		"node:fs":          "",
		"@acme":            "",
	}
	for in, want := range cases {
		if got := pkgFromSpecifier(in); got != want {
			t.Errorf("pkgFromSpecifier(%q) = %q, quer %q", in, got, want)
		}
	}
}
