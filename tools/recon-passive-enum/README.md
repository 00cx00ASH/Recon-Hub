# recon-passive-enum

Enumeração **100% passiva** de subdomínios — **nenhuma requisição ao alvo**.
Consulta 7 fontes gratuitas em paralelo, cada uma degrada sozinha, e o que
sobrar é **mesclado, deduplicado e validado no escopo** do domínio.

Superset do [`recon-crtsh`](../recon-crtsh/) — melhor 1º step de pipeline.

## O que preencher

- **Alvo:** o domínio **raiz** — `exemplo.com`. **Sem** `http://`, **sem**
  `www.`. Um subdomínio profundo funciona como raiz de sub-árvore
  (`api.exemplo.com` traz `*.api.exemplo.com`).
- **Sem wordlist** — não há brute force.

## Fontes

| fonte          | de onde                                                    |
|----------------|-----------------------------------------------------------|
| `crtsh`        | crt.sh — Certificate Transparency (`output=json`, 3 tentativas) |
| `certspotter`  | api.certspotter.com — CT (sem token: limite baixo, 429)   |
| `hackertarget` | api.hackertarget.com/hostsearch — DNS (limite diário por IP)|
| `alienvault`   | otx.alienvault.com — passive DNS                          |
| `anubis`       | jldc.me/anubis — base agregada                            |
| `rapiddns`     | rapiddns.io — scrape da tabela HTML                       |
| `wayback`      | web.archive.org/cdx — hosts extraídos das URLs arquivadas |

`params.sources` (csv) limita quais rodar. Se **todas** falharem, sai com 0
assets e `ok` — não derruba a pipeline.

## Parâmetros

| param        | default | efeito                                             |
|--------------|---------|--------------------------------------------------|
| `sources`    | todas   | csv: `crtsh,certspotter,hackertarget,alienvault,anubis,rapiddns,wayback` |
| `resolve`    | false   | descarta os subdomínios que **não resolvem** em DNS |
| `max`        | 20000   | teto de subdomínios emitidos                     |
| `timeout_ms` | 25000   | timeout por fonte                                |

## Saída

Um **`asset` kind=`subdomain`** por host único. O `done` resume a contagem por
fonte e quantos hosts vieram de **2+ fontes** (mais confiáveis). Não gera
`finding` — é recon.

## Numa pipeline

1º step, no lugar do `recon-crtsh` quando você quer cobertura maior. Alimenta
`scan-subdomain-takeover`, `scan-fuzz`, `js-*`, etc. Ver
`pipelines/passive-takeover.json`.

## Avulso

```bash
echo '{"target":"exemplo.com"}' | go run . -pretty
echo '{"target":"exemplo.com","params":{"sources":"crtsh,certspotter","resolve":true}}' | go run .
```
