package main

import (
	"sort"
	"strings"
	"testing"
)

func TestSearchRequest(t *testing.T) {
	s := searchRequest("exemplo.com", 10)
	for _, want := range []string{`"queryText":"exemplo.com"`, `"domain":"public"`, `"size":10`, `"path":"/search-all"`} {
		if !strings.Contains(s, want) {
			t.Errorf("faltou %s em %s", want, s)
		}
	}
}

func TestParseSearch(t *testing.T) {
	body := `{"data":[
	  {"document":{"entityType":"collection","id":"111-aaa","name":"ACME API","publisherName":"acme","publisherHandle":"acme-team","workspaceName":"Prod","workspaceSlug":"prod","description":"internal"}},
	  {"document":{"entityType":"workspace","id":"222","name":"ACME WS","publisherHandle":"acme-team","workspaces":[{"slug":"team-ws","name":"Team WS"}]}},
	  {"document":{"name":"no type or id"}}
	]}`
	hits, err := parseSearch(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("hits = %d (%+v)", len(hits), hits)
	}
	if hits[0].Type != "collection" || hits[0].ID != "111-aaa" || hits[0].WSSlug != "prod" {
		t.Errorf("hit0 = %+v", hits[0])
	}
	if hits[0].publicURL() != "https://www.postman.com/acme-team/prod/collection/111-aaa" {
		t.Errorf("url0 = %s", hits[0].publicURL())
	}
	if hits[1].WSSlug != "team-ws" { // veio do array workspaces
		t.Errorf("hit1 wsslug = %q", hits[1].WSSlug)
	}
}

func TestParseSearchBadJSON(t *testing.T) {
	if _, err := parseSearch("not json"); err == nil {
		t.Error("json inválido deveria falhar")
	}
}

func TestScanSecrets(t *testing.T) {
	tok := "yptZNpce7QlUcqDQSW5N0DJei4LPid1oOTgUKb9H2QvsWqvz"
	text := `{
	  "key":"` + "AKIA" + `J7QK4PLM2NXR6WZ3",
	  "url":"https://user:sup3rP4ssw0rd@internal.acme.com/api",
	  "auth":"Bearer ` + tok + `",
	  "x-api-key":"` + tok + `",
	  "placeholder":"your_api_key_here_xxxx"
	}`
	hs := scanSecrets(text)
	kinds := map[string]bool{}
	for _, h := range hs {
		kinds[h.Kind] = true
	}
	for _, want := range []string{"aws-access-key-id", "basic-auth-url", "bearer-token", "generic-api-key"} {
		if !kinds[want] {
			t.Errorf("faltou %s em %v", want, kinds)
		}
	}
	// placeholder não deve virar generic-api-key
	for _, h := range hs {
		if strings.Contains(h.Value, "your_") {
			t.Errorf("placeholder vazou: %+v", h)
		}
	}
}

func TestInternalHosts(t *testing.T) {
	text := `
	"https://api.acme.com/v1"
	"http://jenkins.internal.acme.com"
	"https://staging-admin.acme.com/login"
	"https://10.0.3.14:8080/health"
	"https://www.google.com"
	"https://schema.getpostman.com/x"
	`
	got := internalHosts(text, "acme.com")
	sort.Strings(got)
	// acme.com subdomains + internal/staging + rfc1918; NOT google, NOT postman schema
	if !contains(got, "api.acme.com") || !contains(got, "jenkins.internal.acme.com") ||
		!contains(got, "staging-admin.acme.com") || !contains(got, "10.0.3.14") {
		t.Errorf("got %v", got)
	}
	if contains(got, "www.google.com") || contains(got, "schema.getpostman.com") {
		t.Errorf("host público vazou: %v", got)
	}
}

func TestLooksDomain(t *testing.T) {
	if !looksDomain("exemplo.com") || !looksDomain("api.acme.co.uk") {
		t.Error("domínios válidos")
	}
	if looksDomain("ACME Corp") || looksDomain("https://x.com/y") {
		t.Error("não-domínios")
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
