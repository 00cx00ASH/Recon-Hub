package main

// probe is one HTTP response reduced to just what classify needs — nunca o
// corpo inteiro, pra não guardar PII de um usuário real dentro do finding.
type probe struct {
	status int
	length int
}

// classifyCross decides whether requesting someone ELSE's resource while
// authenticated as a different identity actually returned that owner's real
// data — never by guessing a generic "not found"/"forbidden" signature (que
// varia demais de app pra app), mas comparando contra o baseline legítimo do
// próprio dono do recurso: mesmo status de sucesso (2xx) E tamanho de corpo
// dentro da tolerância. Se bater os dois, a resposta que o outro usuário
// recebeu é estruturalmente igual à do dono de verdade — evidência forte de
// que os dados vazaram, sem precisar ler/guardar o conteúdo.
func classifyCross(cross, ownerBaseline probe, tolerancePct int) (ok bool, deltaPct float64) {
	if ownerBaseline.length <= 0 {
		return false, 0 // baseline vazio/erro — nada confiável pra comparar
	}
	if cross.status < 200 || cross.status > 299 {
		return false, 0 // não foi nem um "sucesso" — sem chance de ser o dado real
	}
	if cross.status != ownerBaseline.status {
		return false, 0
	}
	delta := cross.length - ownerBaseline.length
	if delta < 0 {
		delta = -delta
	}
	deltaPct = float64(delta) / float64(ownerBaseline.length) * 100
	return deltaPct <= float64(tolerancePct), deltaPct
}
