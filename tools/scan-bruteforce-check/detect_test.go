package main

import "testing"

func attempts(n int, status, length int, latencyMs int64) []attemptResult {
	rs := make([]attemptResult, n)
	for i := 0; i < n; i++ {
		rs[i] = attemptResult{idx: i + 1, status: status, length: length, latencyMs: latencyMs}
	}
	return rs
}

func TestClassifyNoProtection(t *testing.T) {
	rs := attempts(5, 401, 120, 50)
	v := classifyAttempts(rs, 25, 3)
	if v.blocked {
		t.Fatalf("esperava não-bloqueado (mesma resposta em todas as tentativas), veio: %+v", v)
	}
}

func TestClassify429(t *testing.T) {
	rs := attempts(5, 401, 120, 50)
	rs[2].status = 429
	rs[2].idx = 3
	v := classifyAttempts(rs, 25, 3)
	if !v.blocked || v.atAttempt != 3 {
		t.Fatalf("esperava bloqueado na tentativa 3 por 429, veio: %+v", v)
	}
}

func TestClassifyRetryAfterOnFirstAttempt(t *testing.T) {
	rs := attempts(3, 401, 120, 50)
	rs[0].retryAfter = true
	v := classifyAttempts(rs, 25, 3)
	if !v.blocked || v.atAttempt != 1 {
		t.Fatalf("esperava bloqueado já na tentativa 1 (Retry-After), veio: %+v", v)
	}
}

func TestClassifyBlockKeyword(t *testing.T) {
	rs := attempts(4, 401, 120, 50)
	rs[3].blockKeyword = "captcha"
	v := classifyAttempts(rs, 25, 3)
	if !v.blocked || v.atAttempt != 4 {
		t.Fatalf("esperava bloqueado na tentativa 4 por keyword, veio: %+v", v)
	}
}

func TestClassifyStatusDrift(t *testing.T) {
	rs := attempts(4, 401, 120, 50)
	rs[3].status = 403
	v := classifyAttempts(rs, 25, 3)
	if !v.blocked || v.atAttempt != 4 {
		t.Fatalf("esperava bloqueado por mudança de status, veio: %+v", v)
	}
}

func TestClassifyLengthDriftWithinTolerance(t *testing.T) {
	rs := attempts(4, 401, 1000, 50)
	rs[3].length = 1100 // 10% — dentro da tolerância de 25%
	v := classifyAttempts(rs, 25, 3)
	if v.blocked {
		t.Fatalf("10%% de diferença deveria estar dentro da tolerância de 25%%, veio: %+v", v)
	}
}

func TestClassifyLengthDriftBeyondTolerance(t *testing.T) {
	rs := attempts(4, 401, 1000, 50)
	rs[3].length = 1400 // 40% — além da tolerância de 25%
	v := classifyAttempts(rs, 25, 3)
	if !v.blocked || v.atAttempt != 4 {
		t.Fatalf("40%% de diferença deveria estourar a tolerância de 25%%, veio: %+v", v)
	}
}

func TestClassifyLatencyEscalation(t *testing.T) {
	rs := attempts(4, 401, 120, 50)
	rs[3].latencyMs = 400 // 8x a latência da tentativa 1
	v := classifyAttempts(rs, 25, 3)
	if !v.blocked || v.atAttempt != 4 {
		t.Fatalf("esperava bloqueado por escalada de latência, veio: %+v", v)
	}
}

func TestClassifyLatencyWithinMultiplier(t *testing.T) {
	rs := attempts(4, 401, 120, 50)
	rs[3].latencyMs = 140 // menos de 3x
	v := classifyAttempts(rs, 25, 3)
	if v.blocked {
		t.Fatalf("latência 2.8x não deveria disparar com multiplicador 3x, veio: %+v", v)
	}
}

func TestClassifyIgnoresTinyBaselineLatency(t *testing.T) {
	rs := attempts(4, 401, 120, 5) // baseline de 5ms é ruído, não deveria disparar por multiplicador
	rs[3].latencyMs = 50
	v := classifyAttempts(rs, 25, 3)
	if v.blocked {
		t.Fatalf("baseline de latência muito pequeno deveria ser ignorado no check de escalada, veio: %+v", v)
	}
}

func TestFindBlockKeyword(t *testing.T) {
	if kw := findBlockKeyword("erro: usuário ou senha inválidos"); kw != "" {
		t.Fatalf("mensagem normal de erro não deveria casar palavra de bloqueio, veio %q", kw)
	}
	if kw := findBlockKeyword("please complete the captcha to continue"); kw != "captcha" {
		t.Fatalf("esperava achar 'captcha', veio %q", kw)
	}
	if kw := findBlockKeyword("muitas tentativas, tente novamente mais tarde"); kw == "" {
		t.Fatal("esperava achar palavra de bloqueio em pt-br")
	}
}

func TestClassifyEmpty(t *testing.T) {
	v := classifyAttempts(nil, 25, 3)
	if v.blocked {
		t.Fatal("lista vazia não deveria ser classificada como bloqueada")
	}
}
