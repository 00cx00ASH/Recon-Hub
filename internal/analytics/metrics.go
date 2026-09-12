// Fase 7: Analytics & Trends — agregações de dados e métricas de produtividade
package analytics

import (
	"reconhub/internal/store"
	"sort"
)

type MetricsSummary struct {
	TotalFindings      int                       `json:"total_findings"`
	CriticalCount      int                       `json:"critical_count"`
	HighCount          int                       `json:"high_count"`
	MediumCount        int                       `json:"medium_count"`
	ConfirmedCount     int                       `json:"confirmed_count"`
	FindingsByType     map[string]int            `json:"findings_by_type"`
	ToolProductivity   []ToolMetric              `json:"tool_productivity"`
	TrendByDay         []DailyTrend              `json:"trend_by_day"`
	AverageJobTime     float64                   `json:"average_job_time_minutes"`
	MostUsedTool       string                    `json:"most_used_tool"`
}

type ToolMetric struct {
	Tool              string  `json:"tool"`
	JobsRun           int     `json:"jobs_run"`
	FindingsGenerated int     `json:"findings_generated"`
	ConfirmedCount    int     `json:"confirmed_count"`
	AvgTimeMinutes    float64 `json:"avg_time_minutes"`
	CriticalRate      float64 `json:"critical_rate"` // % de críticos gerados por esse tool
}

type DailyTrend struct {
	Date         string `json:"date"`       // YYYY-MM-DD
	FindingsNew  int    `json:"findings_new"`
	Confirmed    int    `json:"confirmed"`
	Rejected     int    `json:"rejected"`
	JobsRun      int    `json:"jobs_run"`
}

// CalculateMetrics agrega estatísticas de findings, jobs e assets de um programa
func CalculateMetrics(jobs []*store.Job, findings []*store.Finding, assets []*store.Asset) *MetricsSummary {
	metrics := &MetricsSummary{
		FindingsByType:   make(map[string]int),
		ToolProductivity: []ToolMetric{},
		TrendByDay:       []DailyTrend{},
	}

	// Contar findings por severidade e tipo
	toolStats := make(map[string]*ToolMetric)
	dailyStats := make(map[string]*DailyTrend)

	for _, f := range findings {
		metrics.TotalFindings++

		// Por severidade
		switch f.Severity {
		case "critical":
			metrics.CriticalCount++
		case "high":
			metrics.HighCount++
		case "medium":
			metrics.MediumCount++
		}

		if f.Triage == "confirmed" {
			metrics.ConfirmedCount++
		}

		// Por tipo
		metrics.FindingsByType[f.Type]++

		// Por tool
		if _, ok := toolStats[f.Tool]; !ok {
			toolStats[f.Tool] = &ToolMetric{Tool: f.Tool}
		}
		ts := toolStats[f.Tool]
		ts.FindingsGenerated++
		if f.Triage == "confirmed" {
			ts.ConfirmedCount++
		}
		if f.Severity == "critical" {
			ts.CriticalRate += 1.0
		}

		// Por dia
		dayKey := f.CreatedAt.Format("2006-01-02")
		if _, ok := dailyStats[dayKey]; !ok {
			dailyStats[dayKey] = &DailyTrend{Date: dayKey}
		}
		dailyStats[dayKey].FindingsNew++
		if f.Triage == "confirmed" {
			dailyStats[dayKey].Confirmed++
		}
	}

	// Calcular job time médio e contadores por tool
	var totalJobTime int64
	jobCount := len(jobs)

	for _, job := range jobs {
		var duration int64
		if job.EndedAt != nil {
			duration = job.EndedAt.Unix() - job.CreatedAt.Unix()
		}
		totalJobTime += duration

		// Registrar job em daily stats
		dayKey := job.CreatedAt.Format("2006-01-02")
		if _, ok := dailyStats[dayKey]; !ok {
			dailyStats[dayKey] = &DailyTrend{Date: dayKey}
		}
		dailyStats[dayKey].JobsRun++

		// Incrementar jobs_run do tool
		if ts, ok := toolStats[job.Tool]; ok {
			ts.JobsRun++
			if jobCount > 0 {
				ts.AvgTimeMinutes = float64(totalJobTime) / float64(jobCount) / 60.0
			}
		}
	}

	if jobCount > 0 {
		metrics.AverageJobTime = float64(totalJobTime) / float64(jobCount) / 60.0
	}

	// Normalizar critical rate (0-100)
	for _, ts := range toolStats {
		if ts.FindingsGenerated > 0 {
			ts.CriticalRate = (ts.CriticalRate / float64(ts.FindingsGenerated)) * 100
		}
	}

	// Ordenar tools por produtividade (confirmed + critical)
	for _, ts := range toolStats {
		metrics.ToolProductivity = append(metrics.ToolProductivity, *ts)
	}
	sort.Slice(metrics.ToolProductivity, func(i, j int) bool {
		scoreI := float64(metrics.ToolProductivity[i].ConfirmedCount)*10 + metrics.ToolProductivity[i].CriticalRate
		scoreJ := float64(metrics.ToolProductivity[j].ConfirmedCount)*10 + metrics.ToolProductivity[j].CriticalRate
		return scoreI > scoreJ
	})

	if len(metrics.ToolProductivity) > 0 {
		metrics.MostUsedTool = metrics.ToolProductivity[0].Tool
	}

	// Ordenar trend por data
	for _, trend := range dailyStats {
		metrics.TrendByDay = append(metrics.TrendByDay, *trend)
	}
	sort.Slice(metrics.TrendByDay, func(i, j int) bool {
		return metrics.TrendByDay[i].Date < metrics.TrendByDay[j].Date
	})

	return metrics
}
