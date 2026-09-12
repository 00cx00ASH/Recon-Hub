// Fase 9: Automated Triage — sistema sugere confirmação/rejeição baseado em padrões
package triage

import (
	"reconhub/internal/intel"
	"reconhub/internal/store"
	"strings"
)

type TriageSuggestion struct {
	FindingID      string  `json:"finding_id"`
	Action         string  `json:"action"`           // "confirm" | "likely_false_positive" | "investigate"
	Confidence     int     `json:"confidence"`       // 0-100
	Reason         string  `json:"reason"`
	SuggestedSeverity string `json:"suggested_severity,omitempty"` // se diferente da atual
	HistoricalMatch string  `json:"historical_match,omitempty"`    // "mesmo type foi confirmado 7x antes"
}

// SuggestTriage analisa um finding e sugere confirmação/rejeição
func SuggestTriage(finding *store.Finding, allFindings []*store.Finding) *TriageSuggestion {
	suggestion := &TriageSuggestion{
		FindingID: finding.ID,
		Action:    "investigate",
		Confidence: 50,
	}

	// Padrão 1: Evidence muito genérica = falso positivo provável
	if isTooGenericEvidence(finding.Evidence) {
		suggestion.Action = "likely_false_positive"
		suggestion.Confidence = 75
		suggestion.Reason = "Evidence muito genérica (valor, palavra-chave comum, ou padrão conhecido de falso positivo)"
		return suggestion
	}

	// Padrão 2: Já foi confirmado esse tipo de finding antes? Aumenta confiança
	historicalMatch := checkHistoricalPattern(finding, allFindings)
	if historicalMatch != "" {
		suggestion.Action = "confirm"
		suggestion.Confidence = 80
		suggestion.Reason = historicalMatch
		return suggestion
	}

	// Padrão 3: Está em uma chain detectada? Aumenta severidade e confiança
	chains := intel.DetectChains(allFindings)
	for _, chain := range chains {
		for _, fid := range chain.FindingIDs {
			if fid == finding.ID {
				suggestion.Action = "confirm"
				suggestion.Confidence = 85
				suggestion.SuggestedSeverity = chain.Severity
				suggestion.Reason = "Este finding faz parte de uma chain de vulnerabilidade: " + chain.Title
				return suggestion
			}
		}
	}

	// Padrão 4: Heurística por tipo de vuln
	suggestion = applyVulnTypeHeuristics(finding, suggestion)

	return suggestion
}

// isTooGenericEvidence detecta evidência vaga/genérica = falso positivo provável
func isTooGenericEvidence(evidence string) bool {
	vaguePhrases := []string{
		"payload appeared",
		"input was returned",
		"script tag found",
		"redirect works",
		"not found",
		"loaded successfully",
		"response changed",
		"detected in response",
		"found in header",
	}

	lower := strings.ToLower(evidence)
	for _, phrase := range vaguePhrases {
		if strings.Contains(lower, phrase) && len(evidence) < 50 {
			return true
		}
	}
	return false
}

// checkHistoricalPattern verifica se esse tipo de finding foi confirmado antes
func checkHistoricalPattern(finding *store.Finding, allFindings []*store.Finding) string {
	sameType := 0
	confirmed := 0

	for _, f := range allFindings {
		if f.Type == finding.Type {
			sameType++
			if f.Triage == "confirmed" {
				confirmed++
			}
		}
	}

	if sameType >= 3 && confirmed >= 2 {
		return "Este tipo de finding foi encontrado " + pluralize(sameType, "vez") +
			" antes, confirmado em " + pluralize(confirmed, "caso") + " — altamente provável de ser válido"
	}
	return ""
}

// applyVulnTypeHeuristics aplica heurística específica por tipo de vuln
func applyVulnTypeHeuristics(f *store.Finding, s *TriageSuggestion) *TriageSuggestion {
	switch f.Type {
	case "xss-reflected", "xss-stored":
		if strings.Contains(strings.ToLower(f.Evidence), "alert") ||
			strings.Contains(strings.ToLower(f.Evidence), "script") {
			s.Action = "confirm"
			s.Confidence = 90
			s.Reason = "Evidence contém técnica de validação confiável (alert/script)"
		}

	case "sql-injection":
		if strings.Contains(strings.ToLower(f.Evidence), "error") ||
			strings.Contains(strings.ToLower(f.Evidence), "syntax") {
			s.Action = "confirm"
			s.Confidence = 85
			s.Reason = "Error-based SQLi com erro de banco visível"
		}

	case "idor-horizontal":
		if strings.Contains(strings.ToLower(f.Evidence), "forbidden") ||
			strings.Contains(strings.ToLower(f.Evidence), "401") ||
			strings.Contains(strings.ToLower(f.Evidence), "403") {
			s.Action = "likely_false_positive"
			s.Confidence = 80
			s.Reason = "IDOR reportado mas retorna 403 — provavelmente apenas auth check, não IDOR"
		} else if strings.Contains(strings.ToLower(f.Evidence), "user") ||
			strings.Contains(strings.ToLower(f.Evidence), "token") ||
			strings.Contains(strings.ToLower(f.Evidence), "key") {
			s.Action = "confirm"
			s.Confidence = 85
			s.Reason = "IDOR com acesso a dados sensíveis (user/token/key)"
		}

	case "ssrf-confirmed":
		if strings.Contains(strings.ToLower(f.Evidence), "metadata") ||
			strings.Contains(strings.ToLower(f.Evidence), "169.254") {
			s.Action = "confirm"
			s.Confidence = 95
			s.Reason = "SSRF atingiu endpoint de metadata cloud — crítico"
			s.SuggestedSeverity = "critical"
		}

	case "open-redirect":
		if strings.Contains(strings.ToLower(f.Asset), "logout") ||
			strings.Contains(strings.ToLower(f.Asset), "return") {
			s.Action = "likely_false_positive"
			s.Confidence = 70
			s.Reason = "Open redirect em logout/return flow — pode ser by-design"
		}
	}

	return s
}

func pluralize(count int, word string) string {
	if count == 1 {
		return "1 " + word
	}
	return string(rune('0'+count)) + " " + word + "s"
}
