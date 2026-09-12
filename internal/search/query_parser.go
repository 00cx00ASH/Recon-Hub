// Fase 8: Intelligent Filtering — parser de query avançada com operadores
package search

import (
	"reconhub/internal/store"
	"strings"
)

type FindingFilter struct {
	Type            []string // type:xss
	Severity        []string // severity:critical
	Tool            []string // tool:scan-xss
	Confirmed       *bool    // confirmed:true
	Host            []string // host:acme.com
	SearchText      string   // full-text search
	ExcludeType     []string // -type:info
	ExcludeSeverity []string
}

// ParseQuery analisa string tipo "type:xss AND severity:critical NOT confirmed"
func ParseQuery(query string) *FindingFilter {
	filter := &FindingFilter{
		Type:            []string{},
		Severity:        []string{},
		Tool:            []string{},
		ExcludeType:     []string{},
		ExcludeSeverity: []string{},
	}

	// Simples tokenizer — separa por espaço e operadores
	tokens := strings.FieldsFunc(query, func(r rune) bool {
		return r == ' ' || r == '\t'
	})

	for _, token := range tokens {
		if token == "AND" || token == "OR" || token == "NOT" {
			continue
		}

		if strings.HasPrefix(token, "-") {
			// Exclusão: -type:info
			token = strings.TrimPrefix(token, "-")
			if strings.Contains(token, ":") {
				parts := strings.SplitN(token, ":", 2)
				key, val := parts[0], parts[1]
				if key == "type" {
					filter.ExcludeType = append(filter.ExcludeType, val)
				} else if key == "severity" {
					filter.ExcludeSeverity = append(filter.ExcludeSeverity, val)
				}
			}
		} else if strings.Contains(token, ":") {
			// Operador estruturado: type:xss
			parts := strings.SplitN(token, ":", 2)
			key, val := parts[0], parts[1]

			switch key {
			case "type":
				filter.Type = append(filter.Type, val)
			case "severity":
				filter.Severity = append(filter.Severity, val)
			case "tool":
				filter.Tool = append(filter.Tool, val)
			case "host":
				filter.Host = append(filter.Host, val)
			case "confirmed":
				if val == "true" {
					t := true
					filter.Confirmed = &t
				} else if val == "false" {
					f := false
					filter.Confirmed = &f
				}
			}
		} else if token != "confirmed" && token != "unconfirmed" {
			// Full-text search
			filter.SearchText += " " + token
		}

		if token == "confirmed" {
			t := true
			filter.Confirmed = &t
		} else if token == "unconfirmed" {
			f := false
			filter.Confirmed = &f
		}
	}

	filter.SearchText = strings.TrimSpace(filter.SearchText)
	return filter
}

// Matches verifica se um finding passa pelo filtro
func (f *FindingFilter) Matches(finding *store.Finding) bool {
	// Checks de exclusão
	for _, excludeType := range f.ExcludeType {
		if finding.Type == excludeType {
			return false
		}
	}
	for _, excludeSev := range f.ExcludeSeverity {
		if finding.Severity == excludeSev {
			return false
		}
	}

	// Type filter
	if len(f.Type) > 0 {
		found := false
		for _, t := range f.Type {
			if finding.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Severity filter
	if len(f.Severity) > 0 {
		found := false
		for _, s := range f.Severity {
			if finding.Severity == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Tool filter
	if len(f.Tool) > 0 {
		found := false
		for _, tool := range f.Tool {
			if finding.Tool == tool {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Confirmed filter
	if f.Confirmed != nil {
		isConfirmed := finding.Triage == "confirmed"
		if isConfirmed != *f.Confirmed {
			return false
		}
	}

	// Host filter
	if len(f.Host) > 0 {
		found := false
		for _, host := range f.Host {
			if strings.Contains(finding.Target, host) || strings.Contains(finding.Asset, host) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Full-text search
	if f.SearchText != "" {
		searchLower := strings.ToLower(f.SearchText)
		if !strings.Contains(strings.ToLower(finding.Evidence), searchLower) &&
			!strings.Contains(strings.ToLower(finding.Asset), searchLower) &&
			!strings.Contains(strings.ToLower(finding.Target), searchLower) {
			return false
		}
	}

	return true
}
