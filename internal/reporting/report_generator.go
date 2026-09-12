// Fase 11: Smart Reporting — relatórios automáticos e exports estruturados
package reporting

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"reconhub/internal/store"
)

type ReportData struct {
	Program            string           `json:"program"`
	GeneratedAt        time.Time        `json:"generated_at"`
	Summary            ReportSummary    `json:"summary"`
	FindingsByType     map[string]int   `json:"findings_by_type"`
	FindingsBySeverity map[string]int   `json:"findings_by_severity"`
	ConfirmedFindings  int              `json:"confirmed_findings"`
	RejectedFindings   int              `json:"rejected_findings"`
	AssetsDiscovered   int              `json:"assets_discovered"`
	Findings           []FindingSummary `json:"findings"`
}

type ReportSummary struct {
	TotalFindings int `json:"total_findings"`
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`
	InfoCount     int `json:"info_count"`
}

type FindingSummary struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Severity     string `json:"severity"`
	Target       string `json:"target"`
	Asset        string `json:"asset,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
	Triage       string `json:"triage,omitempty"`
	TriageReason string `json:"triage_reason,omitempty"`
}

// GenerateReport cria um relatório estruturado de um programa
func GenerateReport(program string, findings []*store.Finding, assets []*store.Asset) *ReportData {
	report := &ReportData{
		Program:            program,
		GeneratedAt:        time.Now(),
		FindingsByType:     make(map[string]int),
		FindingsBySeverity: make(map[string]int),
	}

	// Contar findings por tipo e severidade
	for _, f := range findings {
		report.FindingsByType[f.Type]++
		report.FindingsBySeverity[f.Severity]++

		switch f.Severity {
		case "critical":
			report.Summary.CriticalCount++
		case "high":
			report.Summary.HighCount++
		case "medium":
			report.Summary.MediumCount++
		case "low":
			report.Summary.LowCount++
		case "info":
			report.Summary.InfoCount++
		}

		if f.Triage == "confirmed" {
			report.ConfirmedFindings++
		} else if f.Triage == "false_positive" {
			report.RejectedFindings++
		}
	}

	report.Summary.TotalFindings = len(findings)
	report.AssetsDiscovered = len(assets)

	// Adicionar findings confirmados ao relatório
	for _, f := range findings {
		if f.Triage == "confirmed" || f.Triage == "" {
			report.Findings = append(report.Findings, FindingSummary{
				ID:           f.ID,
				Type:         f.Type,
				Severity:     f.Severity,
				Target:       f.Target,
				Asset:        f.Asset,
				Evidence:     f.Evidence,
				Triage:       f.Triage,
				TriageReason: f.TriageReason,
			})
		}
	}

	return report
}

// GenerateMarkdownReport cria um relatório em Markdown pronto pra enviar
func GenerateMarkdownReport(program string, findings []*store.Finding, assets []*store.Asset) string {
	report := GenerateReport(program, findings, assets)

	md := strings.Builder{}
	md.WriteString("# Relatório de Segurança — " + program + "\n\n")
	md.WriteString(fmt.Sprintf("**Gerado em:** %s\n\n", report.GeneratedAt.Format("2006-01-02 15:04:05")))

	// Sumário executivo
	md.WriteString("## Sumário Executivo\n\n")
	md.WriteString(fmt.Sprintf("- **Total de achados:** %d\n", report.Summary.TotalFindings))
	md.WriteString(fmt.Sprintf("- **Críticos:** %d 🔴\n", report.Summary.CriticalCount))
	md.WriteString(fmt.Sprintf("- **Altos:** %d 🟠\n", report.Summary.HighCount))
	md.WriteString(fmt.Sprintf("- **Médios:** %d 🟡\n", report.Summary.MediumCount))
	md.WriteString(fmt.Sprintf("- **Confirmados:** %d ✓\n", report.ConfirmedFindings))
	md.WriteString(fmt.Sprintf("- **Assets descobertos:** %d\n\n", report.AssetsDiscovered))

	// Achados por tipo
	if len(report.FindingsByType) > 0 {
		md.WriteString("## Achados por Tipo\n\n")
		for t, count := range report.FindingsByType {
			md.WriteString(fmt.Sprintf("- %s: %d\n", t, count))
		}
		md.WriteString("\n")
	}

	// Listagem de findings confirmados
	if len(report.Findings) > 0 {
		md.WriteString("## Achados Confirmados\n\n")
		for i, f := range report.Findings {
			md.WriteString(fmt.Sprintf("### %d. %s [%s]\n", i+1, f.Type, f.Severity))
			md.WriteString(fmt.Sprintf("- **Alvo:** %s\n", f.Target))
			if f.Asset != "" {
				md.WriteString(fmt.Sprintf("- **Asset:** %s\n", f.Asset))
			}
			md.WriteString(fmt.Sprintf("- **Evidência:** %s\n", f.Evidence))
			if f.TriageReason != "" {
				md.WriteString(fmt.Sprintf("- **Notas:** %s\n", f.TriageReason))
			}
			md.WriteString("\n")
		}
	}

	md.WriteString("---\n")
	md.WriteString("*Relatório gerado automaticamente pelo Recon-Hub*\n")

	return md.String()
}

// GenerateJSONReport cria export em JSON estruturado
func GenerateJSONReport(program string, findings []*store.Finding, assets []*store.Asset) []byte {
	report := GenerateReport(program, findings, assets)
	data, _ := json.MarshalIndent(report, "", "  ")
	return data
}
