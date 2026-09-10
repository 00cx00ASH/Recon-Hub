package main

import "strings"

// knownVuln descreve "versões desse produto ANTES de FixedIn levam esse
// CVE". É deliberadamente simplificado (um corte "abaixo de X", não faixas
// exatas de versão afetada) — o objetivo é sinalizar "isso não foi
// atualizado há anos, e a última vez que não foi tinha X problema conhecido",
// não substituir uma consulta de CVE de verdade. Curado à mão, sem API
// externa nem feed de CVE — mesmo espírito do internal/intel.knownRisk.
type knownVuln struct {
	Product  string // chave em minúsculas, bate com fingerprint().Product
	FixedIn  string // 1ª versão que já NÃO tem o problema
	CVE      string
	Severity string
	Desc     string
}

var knownVulns = []knownVuln{
	{"apache", "2.4.51", "CVE-2021-41773 / CVE-2021-42013", "critical",
		"Path traversal que vira RCE se mod_cgi estiver habilitado — a exploração mais barulhenta de 2021 em servidores Apache desatualizados."},
	{"nginx", "1.21.0", "CVE-2021-23017", "high",
		"Off-by-one no resolver DNS interno — RCE/corrupção de memória se o nginx usa 'resolver' com um DNS controlável pelo atacante (menos comum, mas grave quando aplicável)."},
	{"wordpress", "5.8.3", "CVE-2022-21661", "high",
		"SQL injection em WP_Query via um parâmetro de meta query malformado — afeta núcleo, não plugin."},
	{"wordpress", "4.7.2", "CVE-2017-1001000", "high",
		"REST API do núcleo permite editar o conteúdo de qualquer post sem autenticação — foi usada em massa pra desfigurar sites."},
	{"drupal", "7.58", "CVE-2018-7600", "critical",
		"\"Drupalgeddon2\" — RCE não autenticado via o sistema de formulários. Se o site não foi atualizado desde 2018, é quase certo que ainda esteja vulnerável."},
	{"jquery", "3.5.0", "CVE-2020-11022 / CVE-2020-11023", "medium",
		"XSS via .html()/.append() quando o HTML passado contém <option> ou tags específicas manipuladas — precisa de um sink que passe input do usuário pro jQuery."},
	{"jquery", "1.9.0", "CVE-2015-9251", "medium",
		"XSS via requisição AJAX cross-domain — jQuery muito antigo, comum em sites legados."},
	{"bootstrap", "4.3.1", "CVE-2019-8331", "medium",
		"XSS no componente tooltip/popover via a opção 'data-template' — precisa de um ponto que aceite HTML controlado pelo atacante nesses componentes."},
	{"php", "7.4.0", "múltiplos (fim de suporte)", "medium",
		"Ramo PHP sem mais patch de segurança desde 2019 (7.x) — qualquer CVE encontrada depois não vai ser corrigida nessa versão. Confirme a versão exata e cruze com a NVD."},
}

// versionLess compara duas versões "1.2.3"-like por componente numérico.
// Sufixos não numéricos (ex "5.7-beta") truncam o componente na parte
// numérica; comparação é best-effort, não semver estrito.
func versionLess(a, b string) bool {
	as, bs := splitVersion(a), splitVersion(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			return av < bv
		}
	}
	return false
}

func splitVersion(v string) []int {
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				break
			}
			n = n*10 + int(ch-'0')
		}
		out = append(out, n)
	}
	return out
}

// vulnMatch pairs a detected (product, version) with the curated entry it
// falls below.
type vulnMatch struct {
	Det  detected
	Vuln knownVuln
}

// matchVulns cruza os (produto, versão) detectados com a tabela curada.
func matchVulns(dets []detected) []vulnMatch {
	var out []vulnMatch
	for _, d := range dets {
		for _, kv := range knownVulns {
			if kv.Product != d.Product {
				continue
			}
			if versionLess(d.Version, kv.FixedIn) {
				out = append(out, vulnMatch{d, kv})
			}
		}
	}
	return out
}
