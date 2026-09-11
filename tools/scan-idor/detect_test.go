package main

import "testing"

func TestClassifyCrossConfirmedSameStatusAndSize(t *testing.T) {
	cross := probe{status: 200, length: 1024}
	ownerBaseline := probe{status: 200, length: 1000}
	ok, delta := classifyCross(cross, ownerBaseline, 15)
	if !ok {
		t.Fatalf("esperava confirmado (delta %.1f%% dentro de 15%%), veio ok=false", delta)
	}
}

func TestClassifyCrossNotConfirmedDifferentStatus(t *testing.T) {
	cross := probe{status: 403, length: 50}
	ownerBaseline := probe{status: 200, length: 1000}
	ok, _ := classifyCross(cross, ownerBaseline, 15)
	if ok {
		t.Fatal("status diferente (403 vs 200) não deveria confirmar IDOR")
	}
}

func TestClassifyCrossNotConfirmedCrossIsError(t *testing.T) {
	// cross bateu um status de erro — nunca é "sucesso", mesmo se por acaso
	// bater em algum baseline de erro também.
	cross := probe{status: 500, length: 1000}
	ownerBaseline := probe{status: 500, length: 1000}
	ok, _ := classifyCross(cross, ownerBaseline, 15)
	if ok {
		t.Fatal("status de erro no cross nunca deveria confirmar IDOR, mesmo batendo o baseline")
	}
}

func TestClassifyCrossNotConfirmedSizeTooDifferent(t *testing.T) {
	// mesmo status 200, mas corpo bem menor — provável página de erro
	// "bonita" (200 OK com uma mensagem de acesso negado), não o dado real.
	cross := probe{status: 200, length: 80}
	ownerBaseline := probe{status: 200, length: 1000}
	ok, delta := classifyCross(cross, ownerBaseline, 15)
	if ok {
		t.Fatalf("tamanho muito diferente (delta %.1f%%) não deveria confirmar", delta)
	}
}

func TestClassifyCrossEmptyBaselineNeverConfirms(t *testing.T) {
	cross := probe{status: 200, length: 500}
	ownerBaseline := probe{status: 200, length: 0}
	ok, _ := classifyCross(cross, ownerBaseline, 15)
	if ok {
		t.Fatal("baseline vazio/zerado não é confiável pra comparar — nunca deveria confirmar")
	}
}

func TestClassifyCrossExactToleranceBoundary(t *testing.T) {
	// delta exatamente igual à tolerância deve confirmar (<=, não <).
	cross := probe{status: 200, length: 1150} // 15% acima de 1000
	ownerBaseline := probe{status: 200, length: 1000}
	ok, delta := classifyCross(cross, ownerBaseline, 15)
	if !ok || delta != 15 {
		t.Fatalf("esperava confirmado exatamente na borda de 15%%, veio ok=%v delta=%.2f", ok, delta)
	}
}
