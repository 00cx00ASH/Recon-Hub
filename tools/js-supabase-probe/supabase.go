package main

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// creds holds a Supabase project URL + anon/service key found in a page.
type creds struct {
	URL string
	Key string
	Ref string
}

func (c creds) empty() bool { return c.URL == "" || c.Key == "" }

var (
	reSupaURL  = regexp.MustCompile(`https://([a-z0-9]{20})\.supabase\.co`)
	reSupaURL2 = regexp.MustCompile(`(?i)(?:supabase_url|VITE_SUPABASE_URL|NEXT_PUBLIC_SUPABASE_URL)["'\s:=]+["'](https://[a-z0-9]{20}\.supabase\.co)["']`)
	// a supabase key is a JWT; grab any that decode to an iss of supabase
	reJWT = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,}`)
)

// extractCreds scrapes a Supabase URL + key from source text.
func extractCreds(body string) creds {
	var c creds
	if m := reSupaURL2.FindStringSubmatch(body); m != nil {
		c.URL = m[1]
	} else if m := reSupaURL.FindStringSubmatch(body); m != nil {
		c.URL = m[0]
	}
	for _, tok := range reJWT.FindAllString(body, -1) {
		claims, err := decodeJWT(tok)
		if err != nil {
			continue
		}
		iss, _ := claims["iss"].(string)
		ref, _ := claims["ref"].(string)
		role, _ := claims["role"].(string)
		if strings.Contains(iss, "supabase") || ref != "" || role == "anon" || role == "service_role" || role == "authenticated" {
			c.Key = tok
			c.Ref = ref
			if c.URL == "" && ref != "" {
				c.URL = "https://" + ref + ".supabase.co"
			}
			// prefer a service_role key if we see one (worse case)
			if role == "service_role" {
				break
			}
		}
	}
	if c.Ref == "" && c.URL != "" {
		if m := reSupaURL.FindStringSubmatch(c.URL); m != nil {
			c.Ref = m[1]
		}
	}
	return c
}

// decodeJWT returns the claims of a JWT without verifying the signature.
func decodeJWT(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errBadJWT
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// tolerate padding
		raw, err = base64.URLEncoding.DecodeString(pad(parts[1]))
		if err != nil {
			return nil, err
		}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func pad(s string) string {
	if m := len(s) % 4; m != 0 {
		return s + strings.Repeat("=", 4-m)
	}
	return s
}

var errBadJWT = jwtErr("token não é um JWT de 3 partes")

type jwtErr string

func (e jwtErr) Error() string { return string(e) }

// keyRole returns the "role" claim, or "" .
func keyRole(token string) string {
	c, err := decodeJWT(token)
	if err != nil {
		return ""
	}
	r, _ := c["role"].(string)
	return r
}

// --- PostgREST responses ---

// parseOpenAPITables extracts table names from the PostgREST root document.
func parseOpenAPITables(body string) []string {
	var doc struct {
		Definitions map[string]json.RawMessage `json:"definitions"`
		Paths       map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal([]byte(body), &doc) != nil {
		return nil
	}
	set := map[string]bool{}
	for name := range doc.Definitions {
		set[name] = true
	}
	for p := range doc.Paths {
		p = strings.Trim(p, "/")
		if p != "" && !strings.HasPrefix(p, "rpc/") {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

type tableVerdict struct {
	kind     string // anon-read | anon-read-empty | rls-enforced | not-found | unknown
	severity string
	rows     int
	cols     []string
	note     string
}

// classifyTable reads a `GET /rest/v1/<table>?select=*&limit=N` response.
func classifyTable(status int, body string) tableVerdict {
	low := strings.ToLower(body)
	switch {
	case status == 200 && strings.HasPrefix(strings.TrimSpace(body), "["):
		var rows []map[string]any
		_ = json.Unmarshal([]byte(body), &rows)
		if len(rows) == 0 {
			return tableVerdict{"anon-read-empty", "medium", 0, nil,
				"leitura anônima permitida (tabela vazia ou RLS filtra tudo)"}
		}
		var cols []string
		for k := range rows[0] {
			cols = append(cols, k)
		}
		sort.Strings(cols)
		return tableVerdict{"anon-read", "high", len(rows), cols,
			"leitura anônima retornou dados"}
	case status == 401 || status == 403 || strings.Contains(low, "permission denied") ||
		strings.Contains(low, `"code":"42501"`) || strings.Contains(low, "row-level security"):
		return tableVerdict{"rls-enforced", "info", 0, nil, "RLS bloqueia leitura anônima (bom)"}
	case status == 404 || strings.Contains(low, "does not exist") || strings.Contains(low, `"code":"42p01"`):
		return tableVerdict{"not-found", "", 0, nil, "tabela não existe / não exposta"}
	default:
		return tableVerdict{"unknown", "", 0, nil, strings.TrimSpace(firstLine(body))}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 180 {
		return s[:180]
	}
	return s
}
