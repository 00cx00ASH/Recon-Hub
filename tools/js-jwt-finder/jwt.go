package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"hash"
	"regexp"
	"sort"
	"strings"
	"time"
)

var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{0,}`)

// findJWTs pulls candidate JWTs out of text, deduplicated, keeping only those
// whose header decodes to a JSON object with an "alg".
func findJWTs(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range jwtRe.FindAllString(text, -1) {
		m = strings.Trim(m, ".")
		if seen[m] {
			continue
		}
		if h, _, _, err := decodeJWT(m); err == nil && h["alg"] != nil {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

func b64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

// decodeJWT returns header, payload and signature bytes (unverified).
func decodeJWT(tok string) (hdr, pl map[string]any, sig []byte, err error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, nil, nil, errBad
	}
	hb, err := b64(parts[0])
	if err != nil {
		return nil, nil, nil, err
	}
	pb, err := b64(parts[1])
	if err != nil {
		return nil, nil, nil, err
	}
	sig, _ = b64(parts[2])
	if err = json.Unmarshal(hb, &hdr); err != nil {
		return nil, nil, nil, err
	}
	if err = json.Unmarshal(pb, &pl); err != nil {
		return nil, nil, nil, err
	}
	return hdr, pl, sig, nil
}

type errString string

func (e errString) Error() string { return string(e) }

const errBad = errString("não é um JWT de 3 partes")

// issue is one problem found in a token.
type issue struct {
	kind     string
	severity string
	detail   string
}

var sensitiveClaims = []string{
	"email", "phone", "role", "roles", "is_admin", "admin", "isadmin",
	"permissions", "scope", "scopes", "groups", "user_metadata",
	"app_metadata", "password", "pwd", "ssn", "user_role", "authorization",
	"account_id", "org_id", "tenant", "internal",
}

// collectSensitiveClaims walks the decoded payload looking for sensitiveClaims
// keys at ANY nesting depth, not just the top level. Several real-world
// issuers (Juice Shop included) wrap the actual user object under a single
// key like "data" or "user" — a top-level-only check misses a password hash
// or role sitting right there one level down. Matches are qualified by their
// dotted path (e.g. "data.password") so a nested hit is as legible as a
// top-level one.
func collectSensitiveClaims(v any, path string) []string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	for k, val := range m {
		full := k
		if path != "" {
			full = path + "." + k
		}
		lk := strings.ToLower(k)
		for _, sk := range sensitiveClaims {
			if lk == sk && val != nil && val != "" {
				out = append(out, full)
				break
			}
		}
		out = append(out, collectSensitiveClaims(val, full)...)
	}
	return out
}

// analyze inspects a decoded token.
func analyze(hdr, pl map[string]any, tok string) []issue {
	var out []issue
	alg, _ := hdr["alg"].(string)
	la := strings.ToLower(alg)

	switch {
	case la == "none" || la == "":
		out = append(out, issue{"jwt-alg-none", "high",
			`header alg="` + alg + `" — assinatura desabilitada; qualquer um forja um token válido`})
	case strings.HasPrefix(la, "hs"):
		out = append(out, issue{"jwt-symmetric", "info",
			"alg " + alg + " é simétrico (HMAC) — se o segredo for fraco, dá pra forjar (ver jwt-weak-secret)"})
	}

	if _, ok := hdr["jku"]; ok {
		out = append(out, issue{"jwt-jku", "medium", "header jku presente — verifique se a URL do JWKS é validada (SSRF/spoof)"})
	}
	if _, ok := hdr["x5u"]; ok {
		out = append(out, issue{"jwt-x5u", "medium", "header x5u presente — verifique a validação da URL do certificado"})
	}

	now := time.Now()
	if exp, ok := numClaim(pl, "exp"); ok {
		t := time.Unix(int64(exp), 0)
		switch {
		case t.Before(now):
			out = append(out, issue{"jwt-expired", "info", "expirou em " + t.UTC().Format("2006-01-02 15:04Z")})
		case t.After(now.AddDate(1, 0, 0)):
			out = append(out, issue{"jwt-long-lived", "low",
				"expira só em " + t.UTC().Format("2006-01-02") + " (> 1 ano) — janela de abuso enorme se vazar"})
		}
	} else {
		out = append(out, issue{"jwt-no-exp", "medium", "sem claim exp — o token nunca expira"})
	}

	leaked := collectSensitiveClaims(pl, "")
	sort.Strings(leaked)
	if len(leaked) > 0 {
		sev := "low"
		for _, k := range leaked {
			last := k
			if i := strings.LastIndexByte(k, '.'); i >= 0 {
				last = k[i+1:]
			}
			if strings.Contains(last, "admin") || last == "password" || last == "pwd" || last == "authorization" {
				sev = "medium"
			}
		}
		out = append(out, issue{"jwt-sensitive-claims", sev,
			"claims sensíveis no payload (lido sem chave): " + strings.Join(leaked, ", ")})
	}

	if iss, _ := pl["iss"].(string); iss != "" {
		if lbl := knownIssuer(iss); lbl != "" {
			out = append(out, issue{"jwt-known-issuer", "info", "emissor: " + lbl + " (" + iss + ")"})
		}
	}
	return out
}

func knownIssuer(iss string) string {
	l := strings.ToLower(iss)
	switch {
	case strings.Contains(l, "supabase"):
		return "Supabase (rode js-supabase-probe)"
	case strings.Contains(l, "securetoken.google.com"), strings.Contains(l, "firebase"):
		return "Firebase Auth (rode js-firebase-enum)"
	case strings.Contains(l, "auth0.com"):
		return "Auth0"
	case strings.Contains(l, "okta"):
		return "Okta"
	case strings.Contains(l, "cognito"):
		return "AWS Cognito (rode scan-cognito)"
	case strings.Contains(l, "vercel"):
		return "Vercel"
	case strings.Contains(l, "accounts.google.com"):
		return "Google"
	}
	return ""
}

func numClaim(m map[string]any, k string) (float64, bool) {
	switch v := m[k].(type) {
	case float64:
		return v, true
	case json.Number:
		f, _ := v.Float64()
		return f, true
	}
	return 0, false
}

// --- HS secret cracking ---

func hmacFor(alg string) func() hash.Hash {
	switch strings.ToUpper(alg) {
	case "HS256":
		return sha256.New
	case "HS384":
		return sha512.New384
	case "HS512":
		return sha512.New
	}
	return nil
}

// crackHS tries each secret against an HS* token. Returns the secret if one
// reproduces the signature.
func crackHS(tok string, secrets []string) (string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", false
	}
	hdr, _, _, err := decodeJWT(tok)
	if err != nil {
		return "", false
	}
	alg, _ := hdr["alg"].(string)
	nh := hmacFor(alg)
	if nh == nil {
		return "", false
	}
	want, err := b64(parts[2])
	if err != nil || len(want) == 0 {
		return "", false
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	for _, s := range secrets {
		mac := hmac.New(nh, []byte(s))
		mac.Write(signingInput)
		if subtle.ConstantTimeCompare(mac.Sum(nil), want) == 1 {
			return s, true
		}
	}
	return "", false
}

// builtinWeakSecrets — classic HS256 secrets that show up in tutorials/boilerplate.
var builtinWeakSecrets = []string{
	"secret", "secretkey", "secret_key", "jwt_secret", "jwtsecret", "jwtSecret",
	"supersecret", "super_secret", "changeme", "change_me", "password", "passw0rd",
	"admin", "test", "test123", "123456", "1234567890", "qwerty", "letmein",
	"your-256-bit-secret", "your_jwt_secret", "your-secret-key", "mysecret",
	"my_secret", "mySecretKey", "s3cr3t", "s3cr3tk3y", "topsecret", "shhhh",
	"key", "privatekey", "private_key", "signingkey", "signing_key", "token",
	"app_secret", "appsecret", "default", "dev", "development", "prod", "production",
	"HS256", "jsonwebtoken", "nodejs", "express", "django-insecure", "supabase",
	"", "null", "undefined", "0", "root", "toor", "hunter2",
}

func mergeSecrets(extra []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, builtinWeakSecrets...), extra...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func redactJWT(tok string) string {
	parts := strings.SplitN(tok, ".", 3)
	if len(parts) < 2 {
		return "***"
	}
	head := parts[0]
	if len(head) > 12 {
		head = head[:12]
	}
	return head + "….<payload>." + tail(parts[len(parts)-1], 6)
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func claimKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
