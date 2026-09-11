package main

import (
	"context"
	"os"
	"strings"

	"github.com/chromedp/chromedp"
)

// buildAllocator decide como chegar num navegador de verdade:
//
//  1. chromeURL setado (param chrome_url, ou RECONHUB_CHROME_URL — a
//     engine injeta essa env var quando o sidecar docker/chrome está no
//     ar, mesmo padrão de RECONHUB_PROXY_URL) → conecta remoto via CDP no
//     sidecar compartilhado. Não suporta proxy/Tor por job — o Chrome do
//     sidecar já está rodando, não dá pra trocar --proxy-server dele por
//     requisição sem reiniciar o processo inteiro.
//  2. Senão, sobe um Chrome/Chromium LOCAL (chrome_path, ou detecção
//     automática do chromedp por PATH) — processo novo por job, então
//     PODE aplicar RECONHUB_PROXY_URL como --proxy-server nesse caso.
//
// mode é só texto pro log — não muda comportamento.
func buildAllocator(chromeURL, chromePath string) (context.Context, context.CancelFunc, string) {
	if chromeURL != "" {
		ctx, cancel := chromedp.NewRemoteAllocator(context.Background(), chromeURL)
		return ctx, cancel, "remoto via CDP em " + chromeURL + " (proxy/Tor não suportado nesse modo)"
	}

	opts := append(append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...),
		chromedp.NoSandbox,
		chromedp.DisableGPU,
	)
	if chromePath != "" {
		opts = append(opts, chromedp.ExecPath(chromePath))
	}
	mode := "local"
	if chromePath != "" {
		mode += " (" + chromePath + ")"
	}
	if proxy := strings.TrimSpace(os.Getenv("RECONHUB_PROXY_URL")); proxy != "" {
		// Chrome aceita socks5://host:porta e http(s)://host:porta
		// nativamente no --proxy-server — mesma string que RECONHUB_PROXY_URL
		// já usa pras outras ferramentas, sem tradução nenhuma.
		opts = append(opts, chromedp.Flag("proxy-server", proxy))
		mode += ", proxy=" + proxy
	}
	ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	return ctx, cancel, mode
}
