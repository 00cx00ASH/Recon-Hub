package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ghClient talks to the GitHub REST API (optionally authenticated).
type ghClient struct {
	http      *http.Client
	token     string
	remain    int
	resetAt   time.Time
	exhausted bool
	tokenBad  bool // token rejeitado por permissão (não por rate limit) — para de usar pro resto da run
}

func newGH(token string, timeout time.Duration) *ghClient {
	return &ghClient{http: &http.Client{Timeout: timeout}, token: token, remain: -1}
}

func (g *ghClient) get(path string) ([]byte, int, error) {
	if g.exhausted {
		return nil, 0, fmt.Errorf("rate limit esgotado (reseta %s)", g.resetAt.Format(time.Kitchen))
	}
	tok := g.token
	if g.tokenBad {
		tok = ""
	}
	b, status, err := g.doGet(path, tok)
	if err != nil {
		return b, status, err
	}
	// Um token presente mas sem escopo pro alvo (comum: PAT fine-grained
	// restrito a outro repo/org) dá 403 sem "esgotar" o rate limit — isso é
	// permissão, não cota. Um repo público costuma ficar acessível sem
	// token, então tenta de novo anônimo antes de desistir, e para de usar
	// esse token pro resto da run (evita repetir o mesmo 403 em toda
	// chamada seguinte).
	if status == 403 && tok != "" && g.remain != 0 {
		g.tokenBad = true
		b, status, err = g.doGet(path, "")
	}
	if status == 403 && g.remain == 0 {
		g.exhausted = true
	}
	return b, status, err
}

func (g *ghClient) doGet(path, token string) ([]byte, int, error) {
	url := path
	if strings.HasPrefix(path, "/") {
		url = "https://api.github.com" + path
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "recon-hub/int-github-audit")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))

	if v := resp.Header.Get("X-RateLimit-Remaining"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			g.remain = n
		}
	}
	if v := resp.Header.Get("X-RateLimit-Reset"); v != "" {
		if n, e := strconv.ParseInt(v, 10, 64); e == nil {
			g.resetAt = time.Unix(n, 0)
		}
	}
	return b, resp.StatusCode, nil
}

// getRaw fetches a file from raw.githubusercontent.com.
func (g *ghClient) getRaw(owner, repo, ref, path string) (string, int, error) {
	url := "https://raw.githubusercontent.com/" + owner + "/" + repo + "/" + ref + "/" + path
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "recon-hub/int-github-audit")
	if g.token != "" && !g.tokenBad {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return string(b), resp.StatusCode, nil
}

// --- models ---

type ghRepo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Fork          bool   `json:"fork"`
	Archived      bool   `json:"archived"`
	DefaultBranch string `json:"default_branch"`
	PushedAt      string `json:"pushed_at"`
	Language      string `json:"language"`
	Size          int    `json:"size"`
	HTMLURL       string `json:"html_url"`
}

type ghTree struct {
	Tree []struct {
		Path string `json:"path"`
		Type string `json:"type"`
		Size int    `json:"size"`
	} `json:"tree"`
	Truncated bool `json:"truncated"`
}

type ghGist struct {
	ID    string `json:"id"`
	HTML  string `json:"html_url"`
	Desc  string `json:"description"`
	Files map[string]struct {
		Filename string `json:"filename"`
		RawURL   string `json:"raw_url"`
		Size     int    `json:"size"`
		Language string `json:"language"`
	} `json:"files"`
}

// --- risky-file heuristics ---

var riskyFileRe = regexp.MustCompile(`(?i)(^|/)(\.env(\.[a-z]+)?|\.envrc|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.npmrc|\.pypirc|\.netrc|\.pgpass|credentials|secrets?\.(ya?ml|json|txt|env)|.*\.pem|.*\.pfx|.*\.p12|.*\.key|.*\.keystore|.*\.jks|.*\.kdbx|.*\.ovpn|terraform\.tfstate(\.backup)?|.*\.tfvars|\.git-credentials|wp-config\.php|config/database\.yml|application\.properties|appsettings\.json|serviceaccount.*\.json)$`)

// isRiskyFile flags a repo path worth fetching + scanning.
func isRiskyFile(path string) bool {
	if strings.HasPrefix(path, "vendor/") || strings.HasPrefix(path, "node_modules/") ||
		strings.Contains(path, "/testdata/") || strings.Contains(path, "/fixtures/") ||
		strings.HasSuffix(strings.ToLower(path), ".md") || strings.HasSuffix(strings.ToLower(path), ".lock") {
		return false
	}
	return riskyFileRe.MatchString(path)
}

func isWorkflow(path string) bool {
	return strings.HasPrefix(path, ".github/workflows/") &&
		(strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml"))
}

// ambientConfigRe matches filenames de config de CLI conhecidas por um
// footgun específico: são descobertas subindo diretórios (ou lidas do repo
// checked-out) e o valor de URL/destino que elas fornecem NÃO é vinculado à
// origem do segredo carregado separadamente (normalmente uma env var). Um
// desses arquivos controlado por PR pode redirecionar pra onde esse segredo
// é enviado — visto num relatório real contra o wlc/Weblate (.weblate
// descoberto subindo diretórios, WLC_KEY sem escopo de origem). .npmrc/
// .pypirc/.netrc já são "risky" por poderem CONTER segredo; aqui o ponto é
// diferente: o arquivo REDIRECIONA um segredo carregado de outro lugar.
var ambientConfigRe = regexp.MustCompile(`(?i)(^|/)(\.weblate|\.weblate\.ini|weblate\.ini|\.npmrc|\.pypirc|\.netrc|\.curlrc|\.wgetrc)$`)

func hasAmbientConfigFile(paths []string) bool {
	for _, p := range paths {
		if ambientConfigRe.MatchString(p) {
			return true
		}
	}
	return false
}

// --- workflow analysis ---

type wfFinding struct {
	kind string
	sev  string
	note string
}

// analyzeWorkflow reports risky patterns in one workflow YAML.
// hasAmbientConfig vem da varredura da árvore do repo inteiro (não dá pra
// saber só olhando o workflow) — indica se existe um arquivo do tipo
// ambientConfigRe versionado no repo.
func analyzeWorkflow(yaml string, hasAmbientConfig bool) []wfFinding {
	var out []wfFinding
	l := strings.ToLower(yaml)
	hasPRTarget := strings.Contains(l, "pull_request_target")
	hasCheckout := regexp.MustCompile(`(?i)uses:\s*actions/checkout`).MatchString(yaml)
	refsHeadRef := strings.Contains(l, "github.event.pull_request.head") ||
		strings.Contains(l, "github.head_ref")
	hasSelfHosted := regexp.MustCompile(`(?i)runs-on:\s*\[?\s*self-hosted`).MatchString(yaml)

	if hasPRTarget && hasCheckout && refsHeadRef {
		out = append(out, wfFinding{"github-pwn-request", "high",
			"pull_request_target + checkout do ref do PR — código de um PR não confiável roda com o token/secrets do repo (pwn request)"})
	} else if hasPRTarget && hasCheckout {
		out = append(out, wfFinding{"github-pwn-request", "medium",
			"pull_request_target + actions/checkout — revise se faz checkout do head do PR (pwn request)"})
	}

	// script injection: ${{ ... }} interpolado direto num bloco run:
	for _, m := range regexp.MustCompile(`(?is)\brun:\s*[|>]?\s*\n?(.*?)(\n\s*-\s|\n\s*\w+:|\z)`).FindAllStringSubmatch(yaml, -1) {
		block := m[1]
		if inj := regexp.MustCompile(`\$\{\{\s*(github\.event\.[a-z_.]*(title|body|head_ref|ref|name|label|comment|description)[a-z_.]*|github\.head_ref)\s*\}\}`).FindString(block); inj != "" {
			out = append(out, wfFinding{"github-actions-injection", "high",
				"interpolação não confiável num run: " + strings.TrimSpace(inj) + " — injeção de shell"})
			break
		}
	}

	// self-hosted runner em repo público → risco de abuso
	if hasSelfHosted {
		out = append(out, wfFinding{"github-self-hosted-runner", "medium",
			"runner self-hosted — se o repo for público, um PR pode executar código no runner"})
	}

	// segredo exposto (secrets.X) + execução sobre conteúdo não confiável
	// (checkout de PR não confiável OU runner self-hosted) + arquivo de
	// config ambiente versionado no repo = uma ferramenta de CLI rodando
	// nesse job pode ter seu destino de requisição redirecionado por esse
	// arquivo, levando o segredo consigo (mesmo sem `${{ }}` interpolado
	// direto num run: — por isso não cai em github-actions-injection).
	hasSecretEnv := regexp.MustCompile(`(?i)\$\{\{\s*secrets\.[a-z0-9_]+\s*\}\}`).MatchString(yaml)
	untrustedExec := (hasPRTarget && hasCheckout) || hasSelfHosted
	if hasAmbientConfig && hasSecretEnv && untrustedExec {
		out = append(out, wfFinding{"github-ambient-config-secret-risk", "high",
			"workflow expõe secrets.* como env var E roda sobre conteúdo não confiável (checkout de PR/pull_request_target ou runner self-hosted), e o repo tem um arquivo de config \"ambiente\" versionado (.weblate/.npmrc/.pypirc/.netrc/.curlrc/.wgetrc) — se a ferramenta de CLI usada nesse job resolve o destino da requisição a partir desse arquivo sem vincular o segredo à origem confiável, um PR malicioso pode redirecionar o segredo pra fora (mesmo padrão de um caso real: wlc/Weblate, .weblate + WLC_KEY)"})
	}
	return out
}

// --- compact secret scan ---

type secHit struct {
	Kind, Severity, Value string
}

var secretRes = []struct {
	kind, sev string
	re        *regexp.Regexp
	group     int
	entropy   float64
}{
	{"aws-access-key-id", "high", regexp.MustCompile(`\b((?:AKIA|ASIA)[A-Z0-9]{16})\b`), 1, 0},
	{"aws-secret-key", "critical", regexp.MustCompile(`(?i)aws(.{0,20})?['"]([A-Za-z0-9/+=]{40})['"]`), 2, 4.0},
	{"github-pat", "critical", regexp.MustCompile(`\b(ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82})\b`), 1, 0},
	{"gitlab-pat", "high", regexp.MustCompile(`\b(glpat-[0-9A-Za-z_\-]{20})\b`), 1, 0},
	{"google-api-key", "high", regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})\b`), 1, 0},
	{"gcp-sa-key", "critical", regexp.MustCompile(`"type"\s*:\s*"service_account"[\s\S]{0,400}?"private_key"`), 0, 0},
	{"slack-token", "high", regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b`), 1, 0},
	{"stripe-live", "critical", regexp.MustCompile(`\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b`), 1, 0},
	{"sendgrid", "high", regexp.MustCompile(`\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})\b`), 1, 0},
	{"twilio-key", "high", regexp.MustCompile(`\b(SK[0-9a-fA-F]{32})\b`), 1, 0},
	{"npm-token", "high", regexp.MustCompile(`\b(npm_[0-9A-Za-z]{36})\b`), 1, 0},
	{"openai", "high", regexp.MustCompile(`\b(sk-(?:proj-)?[0-9A-Za-z_\-]{40,})`), 1, 3.2},
	{"private-key", "critical", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), 0, 0},
	{"jwt", "medium", regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b`), 1, 0},
	{"db-url-with-pass", "high", regexp.MustCompile(`\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]{4,}@[^\s/]+)`), 1, 0},
	{"basic-auth-url", "high", regexp.MustCompile(`\bhttps?://[A-Za-z0-9._%+\-]+:([^@\s/"']{6,})@`), 1, 0},
	{"generic-secret", "medium", regexp.MustCompile(`(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)['"]?\s*[:=]\s*['"]([^'"\s]{16,80})['"]`), 1, 3.6},
}

func scanSecrets(text string) []secHit {
	seen := map[string]bool{}
	var out []secHit
	for _, p := range secretRes {
		for _, m := range p.re.FindAllStringSubmatch(text, -1) {
			v := m[0]
			if p.group > 0 && p.group < len(m) {
				v = m[p.group]
			}
			if p.entropy > 0 && shannon(v) < p.entropy {
				continue
			}
			if looksPlaceholder(v) || seen[p.kind+v] {
				continue
			}
			seen[p.kind+v] = true
			out = append(out, secHit{p.kind, p.sev, redact(v)})
		}
	}
	return out
}

var placeholders = []string{
	"example", "your_", "your-", "xxxx", "0000", "changeme", "placeholder",
	"dummy", "sample", "<your", "insert", "redacted", "test1234", "123456",
	"foobar", "abcdef123", "s3cr3t", "notreal", "fake", "${", "{{",
}

func looksPlaceholder(v string) bool {
	l := strings.ToLower(v)
	for _, w := range placeholders {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var f [256]float64
	for i := 0; i < len(s); i++ {
		f[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range f {
		if c > 0 {
			p := c / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

func redact(s string) string {
	if len(s) <= 12 {
		return "***"
	}
	return s[:6] + "…" + s[len(s)-4:]
}

func decodeJSON(b []byte, v any) error { return json.Unmarshal(b, v) }
