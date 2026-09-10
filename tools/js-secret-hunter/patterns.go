package main

import "regexp"

// secretPattern is one credential/token matcher.
type secretPattern struct {
	Name     string
	Severity string // critical | high | medium | low
	Re       *regexp.Regexp
	// Group is the submatch index to report as the value (0 = whole match).
	Group int
	// Entropy > 0 requires the captured value to have at least this Shannon
	// entropy (bits/char) — used to cut noise on the generic patterns.
	Entropy float64
}

// Curated set. Case-sensitive on purpose (keys have fixed alphabets).
var patterns = []secretPattern{
	{"AWS Access Key ID", "high", regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b`), 1, 0},
	{"AWS Secret Access Key", "critical", regexp.MustCompile(`(?i)aws.{0,20}?['"]([A-Za-z0-9/+=]{40})['"]`), 1, 0},
	{"Google API Key", "medium", regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})\b`), 1, 0},
	{"Google OAuth Access Token", "high", regexp.MustCompile(`\b(ya29\.[0-9A-Za-z_\-]{20,})`), 1, 0},
	{"GCP Service Account", "critical", regexp.MustCompile(`"type"\s*:\s*"service_account"`), 0, 0},
	{"GitHub Token", "high", regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36})\b`), 1, 0},
	{"GitHub Fine-grained PAT", "high", regexp.MustCompile(`\b(github_pat_[0-9A-Za-z_]{82})\b`), 1, 0},
	{"GitLab PAT", "high", regexp.MustCompile(`\b(glpat-[0-9A-Za-z_\-]{20})\b`), 1, 0},
	{"Slack Token", "high", regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b`), 1, 0},
	{"Slack Webhook", "medium", regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]+`), 0, 0},
	{"Stripe Live Secret Key", "critical", regexp.MustCompile(`\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b`), 1, 0},
	{"Stripe Test Secret Key", "medium", regexp.MustCompile(`\b((?:sk|rk)_test_[0-9A-Za-z]{24,})\b`), 1, 0},
	{"Twilio API Key", "high", regexp.MustCompile(`\b(SK[0-9a-fA-F]{32})\b`), 1, 0},
	{"Twilio Account SID", "low", regexp.MustCompile(`\b(AC[0-9a-fA-F]{32})\b`), 1, 0},
	{"SendGrid API Key", "high", regexp.MustCompile(`\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})\b`), 1, 0},
	{"Mailgun API Key", "high", regexp.MustCompile(`\b(key-[0-9a-f]{32})\b`), 1, 0},
	{"npm Token", "high", regexp.MustCompile(`\b(npm_[0-9A-Za-z]{36})\b`), 1, 0},
	{"PyPI Token", "high", regexp.MustCompile(`\b(pypi-AgEIcHlwaS[0-9A-Za-z_\-]{50,})`), 1, 0},
	{"OpenAI API Key", "high", regexp.MustCompile(`\b(sk-(?:proj-)?[0-9A-Za-z_\-]{20,})\b`), 1, 3.0},
	{"Anthropic API Key", "high", regexp.MustCompile(`\b(sk-ant-[0-9A-Za-z_\-]{20,})`), 1, 0},
	{"DigitalOcean Token", "high", regexp.MustCompile(`\b(dop_v1_[0-9a-f]{64})\b`), 1, 0},
	{"Cloudflare API Token", "high", regexp.MustCompile(`(?i)cloudflare.{0,20}?['"]([A-Za-z0-9_\-]{40})['"]`), 1, 3.5},
	{"Heroku API Key", "high", regexp.MustCompile(`(?i)heroku.{0,20}?['"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]`), 1, 0},
	{"Mapbox Secret Token", "high", regexp.MustCompile(`\b(sk\.eyJ[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{20,})`), 1, 0},
	{"Sentry DSN", "low", regexp.MustCompile(`https://[0-9a-f]{32}@[0-9a-z.\-]+/[0-9]+`), 0, 0},
	{"JWT", "medium", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`), 0, 0},
	{"Private Key (PEM)", "critical", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), 0, 0},
	{"Firebase Config apiKey", "medium", regexp.MustCompile(`apiKey['"]?\s*[:=]\s*['"](AIza[0-9A-Za-z_\-]{35})['"]`), 1, 0},
	{"Supabase service_role JWT", "critical", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]*(?:c2VydmljZV9yb2xl|role":"service_role)[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+`), 0, 0},
	{"Postgres URL", "high", regexp.MustCompile(`postgres(?:ql)?://[^\s:@/]+:[^\s:@/]+@[^\s/]+`), 0, 0},
	{"MySQL URL", "high", regexp.MustCompile(`mysql://[^\s:@/]+:[^\s:@/]+@[^\s/]+`), 0, 0},
	{"MongoDB URL", "high", regexp.MustCompile(`mongodb(?:\+srv)?://[^\s:@/]+:[^\s:@/]+@[^\s/]+`), 0, 0},
	{"Basic Auth in URL", "medium", regexp.MustCompile(`https?://[^\s:@/]+:[^\s:@/]{4,}@[^\s/]+`), 0, 0},
	{"Generic Secret Assignment", "low", regexp.MustCompile(`(?i)(?:api[_-]?key|secret|passwd|password|auth[_-]?token|access[_-]?token|client[_-]?secret)['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-\.=+/]{16,64})['"]`), 1, 3.5},
}
