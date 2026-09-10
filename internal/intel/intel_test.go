package intel

import (
	"testing"

	"reconhub/internal/store"
)

func TestValidVerdict(t *testing.T) {
	for _, v := range []string{VerdictConfirmed, VerdictFalsePositive, VerdictIgnored} {
		if !ValidVerdict(v) {
			t.Errorf("%q deveria ser válido", v)
		}
	}
	if ValidVerdict("qualquer-coisa") {
		t.Error("verdict desconhecido não deveria ser válido")
	}
}

func TestAssessKnownTypeNoHistory(t *testing.T) {
	f := &store.Finding{ID: "f1", Tool: "scan-mongodb", Type: "mongodb-no-auth", Severity: "critical"}
	a := Assess(f, History{})
	if a.SampleSize != 0 {
		t.Fatalf("sem triagem própria: sample=%d", a.SampleSize)
	}
	// prior de 0.95 pra mongodb-no-auth deveria puxar o score bem alto mesmo sem histórico.
	if a.Score < 85 {
		t.Errorf("score = %d, esperava alto pra um tipo crítico conhecido", a.Score)
	}
	if a.Action != "reportar agora" {
		t.Errorf("action = %q", a.Action)
	}
	if a.Advice == "" {
		t.Error("esperava advice pra um tipo conhecido")
	}
}

func TestAssessUnknownTypeIsNeutral(t *testing.T) {
	f := &store.Finding{ID: "f1", Tool: "custom-tool", Type: "algo-nunca-visto", Severity: "medium"}
	a := Assess(f, History{})
	if a.Confidence != 0.5 {
		t.Errorf("confidence = %v, esperava 0.5 (neutro) pra tipo desconhecido", a.Confidence)
	}
	if a.Advice != "" {
		t.Errorf("não deveria ter advice pra tipo desconhecido: %q", a.Advice)
	}
}

func TestAssessLowPriorType(t *testing.T) {
	// cors-wildcard tem prior baixo (0.20) — mesmo com severidade alta reportada
	// pela ferramenta, o score não deveria bater no teto.
	f := &store.Finding{ID: "f1", Tool: "scan-cors", Type: "cors-wildcard", Severity: "high"}
	a := Assess(f, History{})
	if a.Score >= 80 {
		t.Errorf("score = %d, esperava moderado pra um tipo de baixo prior", a.Score)
	}
}

func TestBuildHistoryAggregates(t *testing.T) {
	findings := []*store.Finding{
		{Tool: "scan-cors", Type: "cors-wildcard", Triage: VerdictConfirmed},
		{Tool: "scan-cors", Type: "cors-wildcard", Triage: VerdictConfirmed},
		{Tool: "scan-cors", Type: "cors-wildcard", Triage: VerdictFalsePositive},
		{Tool: "scan-cors", Type: "cors-wildcard", Triage: ""}, // sem triagem, ignorado
		{Tool: "scan-fuzz", Type: "sensitive-file-exposed", Triage: VerdictIgnored},
	}
	h := BuildHistory(findings)
	s := h[historyKey("scan-cors", "cors-wildcard")]
	if s.Total != 3 || s.Confirmed != 2 || s.FalsePositive != 1 {
		t.Fatalf("stats = %+v", s)
	}
	s2 := h[historyKey("scan-fuzz", "sensitive-file-exposed")]
	if s2.Total != 1 || s2.Ignored != 1 {
		t.Fatalf("stats2 = %+v", s2)
	}
}

func TestAssessLearnsFromOperatorFeedback(t *testing.T) {
	// cors-wildcard tem prior baixo (0.20), mas se ESSE ambiente confirma
	// repetidamente que é real, o score efetivo deve subir bem acima do
	// baseline genérico conforme o histórico cresce.
	f := &store.Finding{ID: "f1", Tool: "scan-cors", Type: "cors-wildcard", Severity: "high"}
	baseline := Assess(f, History{})

	heavyHistory := History{
		historyKey("scan-cors", "cors-wildcard"): {Confirmed: 18, FalsePositive: 2, Total: 20},
	}
	learned := Assess(f, heavyHistory)

	if learned.Score <= baseline.Score {
		t.Fatalf("score deveria subir com histórico majoritariamente confirmado: baseline=%d aprendido=%d",
			baseline.Score, learned.Score)
	}
	if learned.Confidence <= baseline.Confidence {
		t.Fatalf("confidence deveria subir: baseline=%v aprendido=%v", baseline.Confidence, learned.Confidence)
	}
}

func TestAssessLearnsNegativeFeedbackToo(t *testing.T) {
	// subdomain-takeover tem prior alto (0.90), mas se esse ambiente specific
	// vem marcando esses achados como falso positivo repetidamente (ex: um
	// fingerprint ruidoso), o score deve cair.
	f := &store.Finding{ID: "f1", Tool: "scan-subdomain-takeover", Type: "subdomain-takeover", Severity: "high"}
	baseline := Assess(f, History{})

	badHistory := History{
		historyKey("scan-subdomain-takeover", "subdomain-takeover"): {Confirmed: 1, FalsePositive: 19, Total: 20},
	}
	learned := Assess(f, badHistory)

	if learned.Score >= baseline.Score {
		t.Fatalf("score deveria cair com histórico majoritariamente falso-positivo: baseline=%d aprendido=%d",
			baseline.Score, learned.Score)
	}
}

func TestAssessAllSortsDescending(t *testing.T) {
	items := []*store.Finding{
		{ID: "low", Tool: "t", Type: "cors-wildcard", Severity: "low"},
		{ID: "crit", Tool: "t", Type: "mongodb-no-auth", Severity: "critical"},
		{ID: "med", Tool: "t", Type: "open-redirect", Severity: "medium"},
	}
	out := AssessAll(items, History{})
	if len(out) != 3 {
		t.Fatalf("len = %d", len(out))
	}
	for i := 1; i < len(out); i++ {
		if out[i].Score > out[i-1].Score {
			t.Fatalf("não está ordenado desc: %+v", out)
		}
	}
	if out[0].FindingID != "crit" {
		t.Errorf("esperava 'crit' primeiro, veio %q", out[0].FindingID)
	}
}
