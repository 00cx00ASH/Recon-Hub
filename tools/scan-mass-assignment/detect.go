package main

import "encoding/json"

// privilegedFields são nomes de campo que uma aplicação quase nunca deveria
// deixar o cliente setar via bind automático de body (mass assignment /
// over-posting — OWASP API3:2023). Setar qualquer um deles por um campo extra
// no JSON costuma ser escalada de privilégio (role/is_admin), quebra de
// confiança (verified/approved) ou fraude (balance/credit). A lista é o
// conjunto de sondas; cada uma é enviada com um valor SENTINELA ALEATÓRIO —
// nunca "admin"/"true" de verdade. Assim a ferramenta prova que o campo É
// bindável sem NUNCA escalar privilégio de fato (PoC-only): o achado é "o
// servidor aceitou ligar este campo ao objeto", a escalada real é o passo
// manual seguinte.
var privilegedFields = []string{
	"role", "roles", "is_admin", "isAdmin", "admin", "is_staff", "isStaff",
	"is_superuser", "superuser", "is_super", "account_type", "accountType",
	"user_type", "userType", "group", "groups", "permission", "permissions",
	"scope", "scopes", "privilege", "privileges", "access_level", "accessLevel",
	"verified", "is_verified", "isVerified", "email_verified", "emailVerified",
	"kyc_verified", "approved", "is_approved",
	"balance", "credit", "credits", "points", "wallet", "discount",
}

// classifyMassAssignment decide, a partir do corpo da resposta a uma
// requisição que injetou UM campo privilegiado (com valor fieldSentinel) E um
// campo de controle bogus (com valor controlSentinel), se o servidor BINDOU o
// campo privilegiado ao objeto — e não só ecoou o corpo de volta.
//
// A disciplina contra falso positivo (mesma família das lições de confirmação
// do hub) é dupla:
//
//  1. exigir o VALOR sentinela (aleatório, nunca presente no baseline) sob a
//     chave exata no JSON que o servidor serializou — não só o nome do campo
//     aparecendo em algum lugar. Um campo que a app já retorna ("role":"user")
//     não confirma: o valor não bate com o sentinela.
//  2. o campo de CONTROLE (nome bogus aleatório) não pode voltar em lugar
//     nenhum. Se voltar, o endpoint está ecoando o corpo inteiro de volta
//     (mensagem de erro, `{"received": ...}`, etc.) — o campo privilegiado
//     "voltar" nesse caso é reflexo cego, não bind real. Só confirmamos
//     quando o servidor aceitou SELETIVAMENTE um campo privilegiado conhecido
//     enquanto IGNOROU um campo desconhecido — isso não tem como ser eco.
//
// Retorna confirmed (bindou o campo privilegiado), echo (endpoint reflete o
// corpo inteiro — resultado inconclusivo, não reportar) e parsedOK (a resposta
// era JSON; se não for, não dá pra confirmar estruturalmente).
func classifyMassAssignment(respBody []byte, field, fieldSentinel, controlSentinel string) (confirmed, echo, parsedOK bool) {
	var root any
	if err := json.Unmarshal(respBody, &root); err != nil {
		return false, false, false // não-JSON: sem confirmação estrutural possível
	}
	// (2) eco cego? o valor de controle voltou em qualquer lugar.
	if valuePresent(root, controlSentinel) {
		return false, true, true
	}
	// (1) bind real: a chave privilegiada carrega o nosso valor sentinela.
	return keyHasValue(root, field, fieldSentinel), false, true
}

// keyHasValue procura recursivamente, no JSON decodificado, uma chave == key
// cujo valor escalar stringificado == want. É a prova de que o servidor
// serializou o objeto COM o nosso campo ligado ao valor que mandamos.
func keyHasValue(v any, key, want string) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if k == key && scalarEquals(child, want) {
				return true
			}
			if keyHasValue(child, key, want) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if keyHasValue(child, key, want) {
				return true
			}
		}
	}
	return false
}

// valuePresent procura recursivamente qualquer valor escalar stringificado ==
// want, em qualquer chave. Usado pro campo de controle: se o nosso valor bogus
// aparece em qualquer lugar, o endpoint ecoa o corpo inteiro.
func valuePresent(v any, want string) bool {
	switch t := v.(type) {
	case map[string]any:
		for _, child := range t {
			if scalarEquals(child, want) || valuePresent(child, want) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if scalarEquals(child, want) || valuePresent(child, want) {
				return true
			}
		}
	}
	return false
}

// scalarEquals compara um valor escalar do JSON decodificado contra a string
// que enviamos. Só strings batem (o sentinela é sempre uma string aleatória),
// mas tratamos outros escalares por segurança — nunca um map/slice.
func scalarEquals(v any, want string) bool {
	s, ok := v.(string)
	return ok && s == want
}
