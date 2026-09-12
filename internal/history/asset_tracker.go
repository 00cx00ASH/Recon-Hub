// Fase 12: Performance & Asset History — rastreamento e cache de resultados
package history

import (
	"reconhub/internal/store"
	"time"
)

type AssetHistory struct {
	Asset        string              `json:"asset"`
	Kind         string              `json:"kind"`
	FirstSeen    time.Time           `json:"first_seen"`
	LastSeen     time.Time           `json:"last_seen"`
	TotalRuns    int                 `json:"total_runs"`
	DetectionRate float64            `json:"detection_rate"` // % de vezes que foi encontrado
	Detections   []DetectionRecord   `json:"detections"`
	Status       string              `json:"status"`         // "active", "inactive", "unstable"
}

type DetectionRecord struct {
	JobID     string    `json:"job_id"`
	Tool      string    `json:"tool"`
	Timestamp time.Time `json:"timestamp"`
	Confirmed bool      `json:"confirmed"`
}

type RunComparison struct {
	OldRunID         string           `json:"old_run_id"`
	NewRunID         string           `json:"new_run_id"`
	NewAssets        []*store.Asset   `json:"new_assets"`
	RemovedAssets    []*store.Asset   `json:"removed_assets"`
	NewFindings      []*store.Finding `json:"new_findings"`
	ResolvedFindings []*store.Finding `json:"resolved_findings"`
	Summary          ComparisonSummary `json:"summary"`
}

type ComparisonSummary struct {
	NewAssetsCount      int `json:"new_assets_count"`
	RemovedAssetsCount  int `json:"removed_assets_count"`
	NewFindingsCount    int `json:"new_findings_count"`
	ResolvedFindingsCount int `json:"resolved_findings_count"`
}

// TrackAssetHistory cria histórico de um asset ao longo de múltiplos runs
func TrackAssetHistory(asset string, allAssets []*store.Asset) *AssetHistory {
	history := &AssetHistory{
		Asset:      asset,
		Detections: []DetectionRecord{},
	}

	matchCount := 0
	for _, a := range allAssets {
		if a.Value == asset {
			matchCount++
			history.Kind = a.Kind
			if history.FirstSeen.IsZero() || a.CreatedAt.Before(history.FirstSeen) {
				history.FirstSeen = a.CreatedAt
			}
			if a.CreatedAt.After(history.LastSeen) {
				history.LastSeen = a.CreatedAt
			}
		}
	}

	// Estimar taxa de detecção (simplificado: se apareceu em mais de 70% dos últimos runs, é "active")
	if matchCount > 0 {
		history.TotalRuns = matchCount
		history.DetectionRate = float64(matchCount) / float64(len(allAssets)) * 100

		if history.DetectionRate >= 70 {
			history.Status = "active"
		} else if history.DetectionRate >= 30 {
			history.Status = "unstable"
		} else {
			history.Status = "inactive"
		}
	}

	return history
}

// ComparePipelineRuns faz diff entre dois runs
func ComparePipelineRuns(oldAssets []*store.Asset, newAssets []*store.Asset,
	oldFindings []*store.Finding, newFindings []*store.Finding) *RunComparison {
	comparison := &RunComparison{
		Summary: ComparisonSummary{},
	}

	// Encontrar assets novos
	oldAssetMap := make(map[string]bool)
	for _, a := range oldAssets {
		oldAssetMap[a.Value] = true
	}

	for _, a := range newAssets {
		if !oldAssetMap[a.Value] {
			comparison.NewAssets = append(comparison.NewAssets, a)
		}
	}

	// Encontrar assets removidos
	newAssetMap := make(map[string]bool)
	for _, a := range newAssets {
		newAssetMap[a.Value] = true
	}

	for _, a := range oldAssets {
		if !newAssetMap[a.Value] {
			comparison.RemovedAssets = append(comparison.RemovedAssets, a)
		}
	}

	// Encontrar findings novos
	oldFindingMap := make(map[string]bool)
	for _, f := range oldFindings {
		oldFindingMap[f.ID] = true
	}

	for _, f := range newFindings {
		if !oldFindingMap[f.ID] {
			comparison.NewFindings = append(comparison.NewFindings, f)
		}
	}

	// Encontrar findings resolvidos
	newFindingMap := make(map[string]bool)
	for _, f := range newFindings {
		newFindingMap[f.ID] = true
	}

	for _, f := range oldFindings {
		if !newFindingMap[f.ID] {
			comparison.ResolvedFindings = append(comparison.ResolvedFindings, f)
		}
	}

	// Preencher sumário
	comparison.Summary.NewAssetsCount = len(comparison.NewAssets)
	comparison.Summary.RemovedAssetsCount = len(comparison.RemovedAssets)
	comparison.Summary.NewFindingsCount = len(comparison.NewFindings)
	comparison.Summary.ResolvedFindingsCount = len(comparison.ResolvedFindings)

	return comparison
}

// CacheableReconTools lista ferramentas de recon passivo que beneficiam de cache (não mudam frequente)
var CacheableReconTools = map[string]bool{
	"recon-crtsh":        true,  // Certificate transparency — muda pouco
	"recon-passive-enum": true,  // Passive — muda pouco
	"recon-tech-cve":     true,  // Tech scan — muda pouco
	"int-github-audit":   true,  // GitHub audit — muda pouco
}

// ShouldCacheResult verifica se um resultado de ferramenta deve ser cacheado
func ShouldCacheResult(tool string) bool {
	return CacheableReconTools[tool]
}

// CacheTTL retorna quanto tempo um resultado deve ficar em cache (em horas)
func CacheTTL(tool string) int {
	ttls := map[string]int{
		"recon-crtsh":        168, // 1 semana
		"recon-passive-enum": 168,
		"recon-tech-cve":     72,  // 3 dias
		"int-github-audit":   168,
	}
	if ttl, ok := ttls[tool]; ok {
		return ttl
	}
	return 0 // Sem cache
}

// DetectionTrend mostra se um asset é estável (encontrado sempre) ou intermitente
func DetectionTrend(history *AssetHistory) string {
	if history.DetectionRate >= 90 {
		return "rock-solid"     // Sempre encontrado
	} else if history.DetectionRate >= 70 {
		return "stable"         // Quase sempre
	} else if history.DetectionRate >= 50 {
		return "intermittent"   // De vez em quando
	} else {
		return "rare"           // Raramente
	}
}
