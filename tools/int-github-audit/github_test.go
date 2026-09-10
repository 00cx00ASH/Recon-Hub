package main

import (
	"strings"
	"testing"
)

func TestIsRiskyFile(t *testing.T) {
	yes := []string{
		".env", "config/.env.production", "deploy/id_rsa", "app/.npmrc",
		"certs/server.pem", "terraform.tfstate", "infra/prod.tfvars",
		"src/secrets.yaml", "serviceaccount-prod.json", "wp-config.php",
	}
	for _, p := range yes {
		if !isRiskyFile(p) {
			t.Errorf("%q deveria ser risky", p)
		}
	}
	no := []string{
		"README.md", "src/main.go", "node_modules/x/.env", "vendor/y/id_rsa",
		"test/testdata/fixture.pem", "package-lock.json",
	}
	for _, p := range no {
		if isRiskyFile(p) {
			t.Errorf("%q NÃO deveria ser risky", p)
		}
	}
}

func TestIsWorkflow(t *testing.T) {
	if !isWorkflow(".github/workflows/ci.yml") || !isWorkflow(".github/workflows/deploy.yaml") {
		t.Error("workflows válidos")
	}
	if isWorkflow(".github/dependabot.yml") || isWorkflow("workflows/ci.yml") {
		t.Error("não são workflows de Actions")
	}
}

func TestAnalyzeWorkflowPwnRequest(t *testing.T) {
	wf := `
name: pr
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
`
	fs := analyzeWorkflow(wf)
	if !hasKind(fs, "github-pwn-request") {
		t.Fatalf("faltou pwn-request: %+v", fs)
	}
	for _, f := range fs {
		if f.kind == "github-pwn-request" && f.sev != "high" {
			t.Errorf("pwn-request com checkout do head deveria ser high: %+v", f)
		}
	}
}

func TestAnalyzeWorkflowInjection(t *testing.T) {
	wf := `
on: [issues]
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "title is ${{ github.event.issue.title }}"
          ./build.sh
`
	fs := analyzeWorkflow(wf)
	if !hasKind(fs, "github-actions-injection") {
		t.Fatalf("faltou injection: %+v", fs)
	}
}

func TestAnalyzeWorkflowClean(t *testing.T) {
	wf := `
on: [push]
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make test
`
	if fs := analyzeWorkflow(wf); len(fs) != 0 {
		t.Errorf("workflow limpo não deveria acender nada: %+v", fs)
	}
}

func TestScanSecrets(t *testing.T) {
	tok := "yptZNpce7QlUcqDQSW5N0DJei4LPid1oOTgUKb9H2QvsWqvz"
	text := `
	AWS_ACCESS_KEY_ID=AKIAJ7QK4PLM2NXR6WZ3
	GITHUB_TOKEN=ghp_` + strings.Repeat("a1B2c3D4", 4) + `abcd
	DATABASE_URL=postgres://admin:Sup3rSecret99@db.internal:5432/app
	api_key: "` + tok + `"
	# placeholder line
	SECRET_KEY = "your_secret_key_here_xxxx"
	`
	hs := scanSecrets(text)
	kinds := map[string]bool{}
	for _, h := range hs {
		kinds[h.Kind] = true
	}
	for _, want := range []string{"aws-access-key-id", "github-pat", "db-url-with-pass", "generic-secret"} {
		if !kinds[want] {
			t.Errorf("faltou %s em %v", want, kinds)
		}
	}
	for _, h := range hs {
		if strings.Contains(h.Value, "your_secret") {
			t.Errorf("placeholder vazou: %+v", h)
		}
	}
}

func TestRedact(t *testing.T) {
	if redact("ghp_abcdefghijklmnop") != "ghp_ab…mnop" {
		t.Errorf("redact = %q", redact("ghp_abcdefghijklmnop"))
	}
	if redact("short") != "***" {
		t.Error("curto -> ***")
	}
}

func hasKind(fs []wfFinding, k string) bool {
	for _, f := range fs {
		if f.kind == k {
			return true
		}
	}
	return false
}
