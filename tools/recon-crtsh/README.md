# recon-crtsh

Enumeração **passiva** de subdomínios via Certificate Transparency.

## O que preencher

- **Alvo:** o domínio **raiz** — `exemplo.com`. **Sem** `http://`, **sem** `www.`
  (se você põe `www.exemplo.com`, ele só acha subdomínios *de* www, que é quase
  nada). Um subdomínio profundo funciona como raiz de uma sub-árvore:
  `api.exemplo.com` traz `*.api.exemplo.com`.
- **Não tem modo / não usa wordlist.** A fonte são os logs de CT públicos —
  nada de força bruta, nada de tráfego no alvo.

## Fontes

1. **crt.sh** — `?q=%.<domínio>&output=json`. Lento e às vezes cai (404/503);
   tem 4 tentativas com backoff.
2. **certspotter** — `api.certspotter.com/v1/issuances`. Complementar; sem token
   tem limite baixo (429), aí só entra o resultado do crt.sh.

Se **as duas** caírem, sai com 0 assets (sem erro) — não derruba a pipeline.

## Saída

Emite eventos **`asset` kind=`subdomain`** — um por host, deduplicados. **Não
gera `finding`** (é recon, não scan). Veja na aba **Assets** do dashboard, ou
`GET /api/assets?job=<id>`.

## Parâmetros

| param        | default | efeito                                            |
|--------------|---------|--------------------------------------------------|
| `timeout_ms` | 30000   | timeout de cada chamada (crt.sh é lento)          |
| `wildcards`  | false   | incluir entradas `*.x` como `x`                  |
| `max`        | 5000    | teto de subdomínios emitidos                     |

## Numa pipeline

É o **1º step** típico: alimenta `scan-subdomain-takeover` (feed `subdomains`)
ou `js-bucket-scanner` (feed `urls`). Ver `pipelines/crtsh-takeover.json`.

## Avulso

```bash
echo '' | go run . -domain exemplo.com -pretty
echo '{"target":"exemplo.com","params":{"max":2000}}' | go run .
```
