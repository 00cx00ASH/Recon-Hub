package main

// probe is one HTTP response reduced to just what classify needs — nunca o
// corpo inteiro, pra não guardar dado real (de uma função admin) no finding.
type probe struct {
	status int
	length int
}

// classifyPrivesc decide se uma sessão de MENOR privilégio (ou anônima)
// conseguiu acessar uma função que deveria exigir privilégio maior — nunca por
// uma assinatura genérica de "acesso negado" (que varia demais de app pra
// app), mas comparando a resposta da sessão baixa contra o baseline legítimo
// da sessão ALTA no mesmo endpoint: mesmo status de sucesso (2xx) E tamanho de
// corpo dentro da tolerância. Se bater os dois, a sessão baixa recebeu a mesma
// função administrativa que a alta — broken function level authorization, sem
// precisar ler/guardar o conteúdo. A direção importa: só a baixa imitando a
// alta é escalada; a alta continuar funcionando é o esperado.
func classifyPrivesc(lowPriv, highBaseline probe, tolerancePct int) (ok bool, deltaPct float64) {
	if highBaseline.length <= 0 {
		return false, 0 // baseline vazio/erro — nada confiável pra comparar
	}
	if highBaseline.status < 200 || highBaseline.status > 299 {
		return false, 0 // a própria sessão alta não obteve a função — não dá pra provar escalada
	}
	if lowPriv.status < 200 || lowPriv.status > 299 {
		return false, 0 // baixa não teve nem sucesso — controle de acesso funcionou
	}
	if lowPriv.status != highBaseline.status {
		return false, 0
	}
	delta := lowPriv.length - highBaseline.length
	if delta < 0 {
		delta = -delta
	}
	deltaPct = float64(delta) / float64(highBaseline.length) * 100
	return deltaPct <= float64(tolerancePct), deltaPct
}
