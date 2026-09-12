package main

import "testing"

func TestClassifyPrivescConfirmsWhenLowMatchesHigh(t *testing.T) {
	high := probe{status: 200, length: 5000}
	low := probe{status: 200, length: 5050} // 1% de diferença
	ok, delta := classifyPrivesc(low, high, 15)
	if !ok {
		t.Fatalf("baixa imitando a alta (delta %.1f%%) deveria confirmar escalada", delta)
	}
}

func TestClassifyPrivescRejectsLowBlocked(t *testing.T) {
	high := probe{status: 200, length: 5000}
	// controle de acesso funcionando: a baixa leva 403
	if ok, _ := classifyPrivesc(probe{status: 403, length: 120}, high, 15); ok {
		t.Fatal("403 na sessão baixa NÃO é escalada — controle de acesso funcionou")
	}
	// redirect pro login também não é sucesso
	if ok, _ := classifyPrivesc(probe{status: 302, length: 0}, high, 15); ok {
		t.Fatal("302 (redirect) não é escalada")
	}
}

func TestClassifyPrivescRejectsDifferentSize(t *testing.T) {
	high := probe{status: 200, length: 5000}
	// 2xx mas corpo bem diferente (ex: página de "você não tem permissão" com 200)
	if ok, _ := classifyPrivesc(probe{status: 200, length: 300}, high, 15); ok {
		t.Fatal("200 com corpo muito menor que o baseline admin não é a mesma função")
	}
}

func TestClassifyPrivescRejectsNonOkBaseline(t *testing.T) {
	// se a própria sessão alta não obteve a função (não-2xx), não dá pra
	// provar escalada nenhuma — sem referência de "conteúdo admin".
	if ok, _ := classifyPrivesc(probe{status: 200, length: 5000}, probe{status: 403, length: 5000}, 15); ok {
		t.Fatal("baseline alto não-2xx não pode confirmar nada")
	}
	if ok, _ := classifyPrivesc(probe{status: 200, length: 10}, probe{status: 200, length: 0}, 15); ok {
		t.Fatal("baseline vazio não pode confirmar nada")
	}
}
