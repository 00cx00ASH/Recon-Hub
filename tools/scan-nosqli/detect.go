package main

import "fmt"

// probe é uma resposta HTTP reduzida ao que o classificador precisa — nunca o
// corpo inteiro, pra não guardar dado real (um endpoint de filtro pode
// devolver registros de outros usuários quando o operador passa).
type probe struct {
	status int
	length int
}

// truthyOperator é uma variante de injeção de operador NoSQL que é SEMPRE
// verdadeira (casa com tudo) quando interpretada pelo servidor — e inofensiva
// quando tratada como string literal. name vai no finding (diz qual operador
// passou); é o conjunto de sondas do diferencial booleano.
type truthyOperator struct {
	name string // ex: "$ne", "$regex", "$gt"
	// op descreve como montar o valor; a montagem real (bracket na query ou
	// objeto no JSON) fica no main.go, que conhece o modo.
}

// truthyOperators são testados em ordem; confirma no primeiro que divergir do
// baseline falso estável. $ne de um valor inexistente = "diferente de algo que
// não existe" = casa tudo; $regex ".*" = casa tudo; $gt "" = > string vazia =
// quase tudo. Poucos, de propósito — NoSQLi se confirma por UM diferencial, não
// por extração iterativa (isso seria carga/DoS, fora da filosofia do hub).
var truthyOperators = []truthyOperator{
	{name: "$ne"},
	{name: "$regex"},
	{name: "$gt"},
}

// classifyBoolean decide se a injeção de operador foi INTERPRETADA pelo
// servidor, comparando três respostas:
//   - falseA: valor literal aleatório que não casa (baseline "falso")
//   - falseB: segundo controle sempre-falso (outro literal) — prova que a
//     resposta falsa é ESTÁVEL, não ruído de reflexo/página dinâmica
//   - truthy: operador sempre-verdadeiro ($ne/$regex/$gt) do mesmo valor
//
// Confirma só quando os dois controles falsos batem entre si (baseline estável)
// E o sempre-verdadeiro diverge deles (status diferente OU tamanho fora da
// tolerância). Isso prova que o operador foi interpretado como operador — não
// tratado como string literal, nem só refletido — sem extrair nenhum dado.
func classifyBoolean(falseA, falseB, truthy probe, tolPct int) (ok bool, reason string) {
	if !similar(falseA, falseB, tolPct) {
		return false, "baseline instável (duas requisições sempre-falsas divergiram) — sem como confirmar sem falso positivo"
	}
	if similar(truthy, falseA, tolPct) {
		return false, "operador respondeu igual ao baseline literal — não foi interpretado (tratado como string)"
	}
	if truthy.status != falseA.status {
		return true, fmt.Sprintf("operador respondeu status %d vs %d dos dois controles literais estáveis — operador interpretado, não literal", truthy.status, falseA.status)
	}
	return true, fmt.Sprintf("operador respondeu %d bytes vs ~%d dos dois controles literais estáveis (diferença fora da tolerância) — operador interpretado, não literal", truthy.length, falseA.length)
}

// similar reporta se duas respostas são "a mesma" pra efeito de comparação:
// mesmo status e tamanho de corpo dentro da tolerância percentual.
func similar(a, b probe, tolPct int) bool {
	if a.status != b.status {
		return false
	}
	maxLen := a.length
	if b.length > maxLen {
		maxLen = b.length
	}
	if maxLen == 0 {
		return true // ambos vazios
	}
	diff := a.length - b.length
	if diff < 0 {
		diff = -diff
	}
	return float64(diff)/float64(maxLen)*100 <= float64(tolPct)
}
