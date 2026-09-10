package monitor

import (
	"fmt"
	"math"
)

const (
	// anomalyMinSamples is the minimum prior runs needed before "normal" for
	// this watch means anything — too little history to have a baseline.
	anomalyMinSamples = 3
	// anomalyHistoryCap bounds how many recent runs a watch remembers.
	anomalyHistoryCap = 12
	// anomalyZThreshold is how many standard deviations away from the mean
	// counts as "off" — 2σ catches a real swing without firing on ordinary
	// run-to-run noise.
	anomalyZThreshold = 2.0
)

// Anomaly describes how the current run's finding volume compares to this
// watch's own recent history. It answers a different question than "is
// there a new finding": a target that reports ~40 findings every night and
// suddenly reports 2 (site down? WAF now blocking the scanner?) or 400 (new
// exposure, or a scan gone wrong) is worth a look even when none of the
// individual findings are technically new by key.
type Anomaly struct {
	Detected   bool    `json:"detected"`
	Reason     string  `json:"reason,omitempty"`
	Mean       float64 `json:"mean,omitempty"`
	StdDev     float64 `json:"stddev,omitempty"`
	Current    int     `json:"current"`
	SampleSize int     `json:"sample_size"`
}

// detectAnomaly compares total (this run's finding count) against history
// (prior runs of the same watch, oldest first — the run being evaluated is
// NOT in it yet). Says nothing until there are anomalyMinSamples prior runs.
func detectAnomaly(history []RunStat, total int) Anomaly {
	if len(history) < anomalyMinSamples {
		return Anomaly{Current: total, SampleSize: len(history)}
	}
	mean, stddev := meanStddev(history)
	floor := stddev
	if floor < 1 {
		floor = 1 // variância naturalmente ~0 não pode fazer 1 finding a mais parecer um desvio de 1000σ
	}
	a := Anomaly{Current: total, Mean: mean, StdDev: stddev, SampleSize: len(history)}
	z := math.Abs(float64(total)-mean) / floor
	if z >= anomalyZThreshold {
		a.Detected = true
		dir := "subiu"
		if float64(total) < mean {
			dir = "caiu"
		}
		a.Reason = fmt.Sprintf("volume de findings %s do padrão: %d agora vs. média %.1f (±%.1f) das últimas %d execuções",
			dir, total, mean, stddev, len(history))
	}
	return a
}

func meanStddev(history []RunStat) (mean, stddev float64) {
	n := float64(len(history))
	var sum float64
	for _, h := range history {
		sum += float64(h.Total)
	}
	mean = sum / n
	var sq float64
	for _, h := range history {
		d := float64(h.Total) - mean
		sq += d * d
	}
	return mean, math.Sqrt(sq / n)
}
