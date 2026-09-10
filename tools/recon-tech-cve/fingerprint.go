package main

import (
	"net/http"
	"regexp"
	"strings"
)

// detected is one (produto, versão) extraído da resposta, com a evidência
// crua que originou o match — pra quem for confirmar manualmente conseguir
// achar de novo sem re-rodar a ferramenta.
type detected struct {
	Product  string
	Version  string
	Evidence string
}

var (
	// "Servidor/1.2.3" em Server ou X-Powered-By — pega o 1º token de cada
	// header (pode ter vários, ex: "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f").
	serverTokenRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_-]*)/(\d[\d.]*\d|\d)`)

	generatorMetaRe = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	generatorVerRe  = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9 ]*?)\s+(\d[\d.]*\d|\d)`)

	wpAssetVerRe   = regexp.MustCompile(`wp-(?:includes|content|admin)/[^"'\s?]+\?ver=(\d[\d.]*\d|\d)`)
	jqueryVerRe    = regexp.MustCompile(`jquery[.-](\d[\d.]*\d|\d)(?:\.min)?\.js`)
	bootstrapVerRe = regexp.MustCompile(`bootstrap[.-](\d[\d.]*\d|\d)(?:\.min)?\.(?:js|css)`)
)

// fingerprint extrai todo (produto, versão) que a página deixa visível — só
// dessa única resposta, sem sondar caminho nenhum a mais (é passivo, rápido,
// pensado pra rodar logo depois do recon-web-enum).
func fingerprint(resp *http.Response, body string) []detected {
	var out []detected
	add := func(product, version, evidence string) {
		if product == "" || version == "" {
			return
		}
		out = append(out, detected{Product: strings.ToLower(strings.TrimSpace(product)), Version: version, Evidence: evidence})
	}

	for _, h := range []string{"Server", "X-Powered-By"} {
		v := resp.Header.Get(h)
		if v == "" {
			continue
		}
		for _, m := range serverTokenRe.FindAllStringSubmatch(v, -1) {
			add(m[1], m[2], h+": "+v)
		}
	}

	if m := generatorMetaRe.FindStringSubmatch(body); m != nil {
		content := strings.TrimSpace(m[1])
		if vm := generatorVerRe.FindStringSubmatch(content); vm != nil {
			add(vm[1], vm[2], "meta generator: "+content)
		}
	}

	if m := wpAssetVerRe.FindStringSubmatch(body); m != nil {
		add("wordpress", m[1], "asset core do WP com ?ver="+m[1])
	}
	if m := jqueryVerRe.FindStringSubmatch(body); m != nil {
		add("jquery", m[1], "script jquery-"+m[1])
	}
	if m := bootstrapVerRe.FindStringSubmatch(body); m != nil {
		add("bootstrap", m[1], "asset bootstrap "+m[1])
	}

	return dedupe(out)
}

func dedupe(in []detected) []detected {
	seen := map[string]bool{}
	var out []detected
	for _, d := range in {
		k := d.Product + "@" + d.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, d)
	}
	return out
}
