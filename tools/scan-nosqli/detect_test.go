package main

import "testing"

func TestConfirmsWhenTruthyDivergesFromStableFalse(t *testing.T) {
	// baseline falso estável (login falho, pequeno); operador sempre-verdadeiro
	// vira sucesso (redirect/corpo maior) — NoSQLi confirmada.
	falseA := probe{status: 401, length: 120}
	falseB := probe{status: 401, length: 118}
	truthy := probe{status: 200, length: 4800}
	ok, reason := classifyBoolean(falseA, falseB, truthy, 15)
	if !ok {
		t.Fatalf("status divergente com baseline estável deveria confirmar; reason=%s", reason)
	}
}

func TestConfirmsOnSizeDivergenceSameStatus(t *testing.T) {
	// mesmo status 200, mas o operador devolve MUITO mais (listou todos os
	// registros em vez de zero) — diverge em tamanho.
	falseA := probe{status: 200, length: 300}
	falseB := probe{status: 200, length: 310}
	truthy := probe{status: 200, length: 9000}
	if ok, _ := classifyBoolean(falseA, falseB, truthy, 15); !ok {
		t.Fatal("divergência de tamanho com baseline estável deveria confirmar")
	}
}

func TestRejectsUnstableBaseline(t *testing.T) {
	// página dinâmica: dois controles falsos já divergem entre si — não dá pra
	// atribuir a divergência do truthy ao operador (evita FP).
	falseA := probe{status: 200, length: 1000}
	falseB := probe{status: 200, length: 4000}
	truthy := probe{status: 200, length: 8000}
	if ok, _ := classifyBoolean(falseA, falseB, truthy, 15); ok {
		t.Fatal("baseline instável não pode confirmar")
	}
}

func TestRejectsWhenTruthyMatchesFalse(t *testing.T) {
	// operador tratado como string literal: responde igual ao baseline falso.
	falseA := probe{status: 200, length: 500}
	falseB := probe{status: 200, length: 505}
	truthy := probe{status: 200, length: 498}
	if ok, _ := classifyBoolean(falseA, falseB, truthy, 15); ok {
		t.Fatal("operador não interpretado (resposta igual ao literal) não é NoSQLi")
	}
}

func TestSimilarTolerance(t *testing.T) {
	if !similar(probe{200, 1000}, probe{200, 1100}, 15) {
		t.Fatal("10% de diferença deveria ser 'similar' sob tolerância 15%")
	}
	if similar(probe{200, 1000}, probe{200, 1300}, 15) {
		t.Fatal("30% de diferença não é similar sob tolerância 15%")
	}
	if similar(probe{200, 100}, probe{302, 100}, 15) {
		t.Fatal("status diferente nunca é similar")
	}
}
