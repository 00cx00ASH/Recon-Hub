package monitor

import "testing"

func mkHistory(totals ...int) []RunStat {
	out := make([]RunStat, len(totals))
	for i, n := range totals {
		out[i] = RunStat{Total: n}
	}
	return out
}

func TestDetectAnomalyNeedsMinSamples(t *testing.T) {
	a := detectAnomaly(mkHistory(10, 11), 500) // só 2 amostras, precisa de 3
	if a.Detected {
		t.Fatalf("não deveria detectar com histórico curto: %+v", a)
	}
	if a.SampleSize != 2 {
		t.Errorf("sample_size = %d", a.SampleSize)
	}
}

func TestDetectAnomalyStableHistoryNoAlert(t *testing.T) {
	a := detectAnomaly(mkHistory(10, 11, 9, 10, 12, 10), 11)
	if a.Detected {
		t.Fatalf("11 dentro do padrão (~10) não deveria disparar: %+v", a)
	}
}

func TestDetectAnomalySpikeDetected(t *testing.T) {
	a := detectAnomaly(mkHistory(10, 11, 9, 10, 12, 10), 80)
	if !a.Detected {
		t.Fatal("80 vs média ~10 deveria disparar anomalia")
	}
	if a.Reason == "" {
		t.Error("esperava razão preenchida")
	}
}

func TestDetectAnomalyDropDetected(t *testing.T) {
	a := detectAnomaly(mkHistory(40, 38, 42, 41, 39, 40), 2)
	if !a.Detected {
		t.Fatal("queda de ~40 pra 2 deveria disparar anomalia (alvo pode ter saído do ar)")
	}
}

func TestDetectAnomalyZeroVarianceHasFloor(t *testing.T) {
	// histórico sempre exatamente 5 (stddev=0) — sem o piso de stddev, 1
	// finding a mais já pareceria um desvio de infinitos sigmas.
	a := detectAnomaly(mkHistory(5, 5, 5, 5, 5), 6)
	if a.Detected {
		t.Fatalf("desvio de 1 com stddev histórico 0 não deveria disparar (piso de sensibilidade): %+v", a)
	}
	a2 := detectAnomaly(mkHistory(5, 5, 5, 5, 5), 20)
	if !a2.Detected {
		t.Fatal("desvio de 15 deveria disparar mesmo com stddev histórico 0")
	}
}
