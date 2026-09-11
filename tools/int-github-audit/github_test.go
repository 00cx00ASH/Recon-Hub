package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestHasAmbientConfigFile(t *testing.T) {
	yes := []string{".weblate", ".weblate.ini", "weblate.ini", "app/.npmrc", ".pypirc", "sub/.netrc", ".curlrc", ".wgetrc"}
	for _, p := range yes {
		if !hasAmbientConfigFile([]string{"README.md", p}) {
			t.Errorf("%q deveria ser detectado como config ambiente", p)
		}
	}
	if hasAmbientConfigFile([]string{"README.md", "src/main.go", "package.json"}) {
		t.Error("sem arquivo de config ambiente não deveria detectar nada")
	}
}

func TestAnalyzeWorkflowAmbientConfigSecretRisk(t *testing.T) {
	wf := `
name: sync
on:
  pull_request_target:
    types: [opened]
jobs:
  sync:
    runs-on: ubuntu-latest
    env:
      WLC_KEY: ${{ secrets.WLC_KEY }}
    steps:
      - uses: actions/checkout@v4
      - run: wlc list-projects
`
	// sem arquivo de config ambiente no repo -> não acende esse finding
	if fs := analyzeWorkflow(wf, false); hasKind(fs, "github-ambient-config-secret-risk") {
		t.Fatalf("sem config ambiente no repo não deveria acender: %+v", fs)
	}
	// com arquivo de config ambiente no repo -> acende
	fs := analyzeWorkflow(wf, true)
	if !hasKind(fs, "github-ambient-config-secret-risk") {
		t.Fatalf("esperava github-ambient-config-secret-risk: %+v", fs)
	}
}

func TestAnalyzeWorkflowAmbientConfigNeedsSecretAndUntrustedExec(t *testing.T) {
	// config ambiente presente, mas sem secrets.* nem execução não confiável
	wf := `
on: [push]
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make test
`
	if fs := analyzeWorkflow(wf, true); hasKind(fs, "github-ambient-config-secret-risk") {
		t.Fatalf("sem secrets.*/execução não confiável não deveria acender: %+v", fs)
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
	fs := analyzeWorkflow(wf, false)
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
	fs := analyzeWorkflow(wf, false)
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
	if fs := analyzeWorkflow(wf, false); len(fs) != 0 {
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

// TestGetFallsBackWhenTokenLacksAccess regressão: achado rodando o hub de
// verdade num sandbox onde GITHUB_TOKEN é um PAT fine-grained restrito a UM
// repo específico. Auditar um repo público diferente (ex juice-shop/juice-shop)
// dava 403 e a ferramenta desistia — mesmo o repo sendo perfeitamente
// acessível sem token. O 403 aqui é de permissão, não de rate limit
// (X-RateLimit-Remaining continua > 0), então deve cair pra acesso anônimo.
func TestGetFallsBackWhenTokenLacksAccess(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("X-RateLimit-Remaining", "100") // não é rate limit
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"message":"Resource not accessible by personal access token"}`))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	g := newGH("token-sem-acesso-a-este-repo", 5*time.Second)
	b, status, err := g.get(srv.URL + "/repos/juice-shop/juice-shop")
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 {
		t.Fatalf("status = %d, corpo = %s (deveria ter caído pro acesso anônimo)", status, b)
	}
	if !g.tokenBad {
		t.Error("tokenBad deveria ficar true depois do fallback")
	}
	if calls != 2 {
		t.Fatalf("esperava 2 chamadas (com token + fallback anônimo), veio %d", calls)
	}

	// chamada seguinte já sabe que o token é ruim — vai direto anônima, 1 request só.
	_, status2, _ := g.get(srv.URL + "/repos/juice-shop/juice-shop")
	if status2 != 200 || calls != 3 {
		t.Fatalf("chamada seguinte deveria ir direto anônima (1 request): status=%d calls=%d", status2, calls)
	}
}

// TestGetRealRateLimitStillMarksExhausted garante que o fix não regrediu o
// caso original: 403 com X-RateLimit-Remaining=0 é rate limit de verdade, sem
// token pra tentar de novo, e deve marcar exhausted (não fica em loop).
func TestGetRealRateLimitStillMarksExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(403)
	}))
	defer srv.Close()

	g := newGH("", 5*time.Second)
	_, status, err := g.get(srv.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	if status != 403 {
		t.Fatalf("status = %d", status)
	}
	if !g.exhausted {
		t.Error("deveria marcar exhausted quando remain=0")
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
