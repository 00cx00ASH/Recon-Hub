package main

import (
	"regexp"
	"strings"
)

// fbConfig is the client-side Firebase config found in a page/bundle.
type fbConfig struct {
	APIKey        string
	AuthDomain    string
	DatabaseURL   string
	ProjectID     string
	StorageBucket string
	AppID         string
	SenderID      string
}

func (c fbConfig) empty() bool {
	return c.APIKey == "" && c.DatabaseURL == "" && c.ProjectID == "" && c.StorageBucket == ""
}

var fbKeyRes = map[string]*regexp.Regexp{
	"apiKey":            regexp.MustCompile(`["']?apiKey["']?\s*[:=]\s*["']([^"']+)["']`),
	"authDomain":        regexp.MustCompile(`["']?authDomain["']?\s*[:=]\s*["']([^"']+)["']`),
	"databaseURL":       regexp.MustCompile(`["']?databaseURL["']?\s*[:=]\s*["']([^"']+)["']`),
	"projectId":         regexp.MustCompile(`["']?projectId["']?\s*[:=]\s*["']([^"']+)["']`),
	"storageBucket":     regexp.MustCompile(`["']?storageBucket["']?\s*[:=]\s*["']([^"']+)["']`),
	"appId":             regexp.MustCompile(`["']?appId["']?\s*[:=]\s*["']([^"']+)["']`),
	"messagingSenderId": regexp.MustCompile(`["']?messagingSenderId["']?\s*[:=]\s*["']([^"']+)["']`),
}

// extractConfig scans source text for a Firebase web config.
func extractConfig(body string) fbConfig {
	pick := func(k string) string {
		if m := fbKeyRes[k].FindStringSubmatch(body); m != nil {
			return strings.TrimSpace(m[1])
		}
		return ""
	}
	c := fbConfig{
		APIKey:        pick("apiKey"),
		AuthDomain:    pick("authDomain"),
		DatabaseURL:   strings.TrimRight(pick("databaseURL"), "/"),
		ProjectID:     pick("projectId"),
		StorageBucket: pick("storageBucket"),
		AppID:         pick("appId"),
		SenderID:      pick("messagingSenderId"),
	}
	if c.ProjectID == "" && c.AuthDomain != "" {
		c.ProjectID = strings.TrimSuffix(c.AuthDomain, ".firebaseapp.com")
	}
	if c.ProjectID == "" && c.DatabaseURL != "" {
		c.ProjectID = rtdbProject(c.DatabaseURL)
	}
	if c.StorageBucket == "" && c.ProjectID != "" {
		c.StorageBucket = c.ProjectID + ".appspot.com"
	}
	return c
}

// merge fills empty fields of a from b.
func (c *fbConfig) merge(b fbConfig) {
	if c.APIKey == "" {
		c.APIKey = b.APIKey
	}
	if c.AuthDomain == "" {
		c.AuthDomain = b.AuthDomain
	}
	if c.DatabaseURL == "" {
		c.DatabaseURL = b.DatabaseURL
	}
	if c.ProjectID == "" {
		c.ProjectID = b.ProjectID
	}
	if c.StorageBucket == "" {
		c.StorageBucket = b.StorageBucket
	}
	if c.AppID == "" {
		c.AppID = b.AppID
	}
	if c.SenderID == "" {
		c.SenderID = b.SenderID
	}
}

var rtdbHostRe = regexp.MustCompile(`^https?://([a-z0-9-]+?)(?:-default-rtdb)?\.(?:[a-z0-9-]+\.)?firebase(?:io|database)\.(?:com|app)`)

func rtdbProject(dbURL string) string {
	if m := rtdbHostRe.FindStringSubmatch(dbURL); m != nil {
		return m[1]
	}
	return ""
}

// candidateRTDBs returns the RTDB base URLs worth probing for a config.
func candidateRTDBs(c fbConfig) []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		u = strings.TrimRight(u, "/")
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	if c.DatabaseURL != "" {
		add(c.DatabaseURL)
	}
	if c.ProjectID != "" {
		add("https://" + c.ProjectID + "-default-rtdb.firebaseio.com")
		add("https://" + c.ProjectID + ".firebaseio.com")
		// common regional endpoints
		add("https://" + c.ProjectID + "-default-rtdb.europe-west1.firebasedatabase.app")
		add("https://" + c.ProjectID + "-default-rtdb.asia-southeast1.firebasedatabase.app")
	}
	return out
}

// rtdbVerdict classifies a GET <db>/.json?shallow=true response.
type rtdbVerdict struct {
	kind     string // open-rtdb-read | rtdb-locked | rtdb-absent | unknown
	severity string
	note     string
}

func classifyRTDB(status int, body string) rtdbVerdict {
	b := strings.TrimSpace(body)
	low := strings.ToLower(b)
	switch {
	case status == 200:
		if b == "null" {
			return rtdbVerdict{"open-rtdb-read", "medium", "leitura anônima permitida (banco vazio no momento)"}
		}
		return rtdbVerdict{"open-rtdb-read", "high", "leitura anônima retornou dados"}
	case status == 401 || status == 403 || strings.Contains(low, "permission denied"):
		return rtdbVerdict{"rtdb-locked", "info", "existe mas exige auth (regras fechadas)"}
	case status == 404:
		return rtdbVerdict{"rtdb-absent", "", "não existe"}
	case status == 423 || strings.Contains(low, "database has been deactivated") || strings.Contains(low, "not been created"):
		return rtdbVerdict{"rtdb-absent", "", "desativado / não criado"}
	default:
		return rtdbVerdict{"unknown", "", ""}
	}
}

// firestoreCollections are cheap guesses for an unauthenticated Firestore read.
var firestoreCollections = []string{
	"users", "user", "config", "configs", "settings", "messages", "chats",
	"posts", "orders", "customers", "accounts", "profiles", "data", "admin",
	"logs", "notifications", "transactions", "products",
}

// classifyFirestore classifies a documents.list REST response.
func classifyFirestore(status int, body string) (kind, severity, note string) {
	low := strings.ToLower(body)
	switch {
	case status == 200 && strings.Contains(low, "\"documents\""):
		return "open-firestore-read", "high", "listagem anônima de documentos permitida"
	case status == 200:
		return "open-firestore-read", "medium", "coleção acessível anonimamente (vazia ou sem documentos)"
	case status == 403 || strings.Contains(low, "permission_denied") || strings.Contains(low, "missing or insufficient permissions"):
		return "firestore-locked", "info", "Firestore existe mas as regras estão fechadas"
	case status == 401 || strings.Contains(low, "api key not valid"):
		return "", "", "apiKey inválida/again"
	default:
		return "unknown", "", ""
	}
}

// classifyStorage classifies a Storage list (v0/b/<bucket>/o) response.
func classifyStorage(status int, body string) (kind, severity, note string) {
	low := strings.ToLower(body)
	switch {
	case status == 200 && (strings.Contains(low, "\"items\"") || strings.Contains(low, "\"prefixes\"") || strings.TrimSpace(body) == "{}"):
		if strings.Contains(low, "\"items\"") {
			return "open-storage-list", "high", "listagem anônima de objetos permitida"
		}
		return "open-storage-list", "medium", "bucket lista anonimamente (vazio no momento)"
	case status == 403 || strings.Contains(low, "permission denied"):
		return "storage-locked", "info", "bucket existe mas exige auth"
	case status == 404:
		return "storage-absent", "", "bucket não encontrado"
	default:
		return "unknown", "", ""
	}
}
