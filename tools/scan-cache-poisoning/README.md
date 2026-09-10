# scan-cache-poisoning

**Web cache poisoning** via entradas **não-chaveadas** — headers que o CDN
encaminha pra origin mas **não** inclui na chave de cache. Se o valor volta
refletido numa resposta **cacheável**, um atacante pode envenenar a versão
cacheada que outros usuários recebem.

## Seguro por construção

Todo teste adiciona `?cb=<aleatório>` **único** na query. A resposta (mesmo se
envenenada) fica presa numa URL que **nenhum usuário real acessa** — a
ferramenta prova a falha sem afetar o cache de produção. O payload é sempre um
**canary inofensivo** (`cachepoison-<rand>.example.com`), nunca conteúdo
malicioso.

## O que preencher

- **Alvo:** uma URL `http`/`https` — a raiz do site ou uma página específica
  (páginas atrás de CDN e com HTML cacheado são as mais interessantes).
- **Sem wordlist.** A lista de 17 entradas é fixa; `params.headers` (csv)
  sobrescreve.

## Entradas testadas

`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`,
`X-Forwarded-Port`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`,
`X-Original-Host`, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL`,
`X-Forwarded-Path`, `X-Forwarded-For`, `True-Client-IP`, `X-Forwarded-Prefix`,
`Accept-Language`, e o param `utm_content`.

## Findings

| finding_type              | sev.   | quando                                                                 |
|---------------------------|--------|----------------------------------------------------------------------|
| `cache-poisoning`         | high   | o canary voltou numa **2ª requisição limpa** à mesma URL cacheada — confirmado |
| `cache-poisoning-likely`  | medium | canary refletido **e** resposta cacheável (`X-Cache`, `Age`, `s-maxage`, `Via: varnish`…), sem confirmar persistência |
| `header-reflection`       | low    | canary refletido sem sinal claro de cache — pode haver cache upstream |

Cada hit sai como **`asset` kind=`url`** (a URL com o cache-buster do teste).

## Parâmetros

| param        | default | efeito                                       |
|--------------|---------|---------------------------------------------|
| `headers`    | (17)    | csv de headers a testar (sobrescreve)       |
| `concurrency`| 4       | hosts testados em paralelo                  |
| `delay_ms`   | 150     | pausa entre requisições ao mesmo host       |
| `timeout_ms` | 10000   | timeout por requisição                      |

## Numa pipeline

`recon-crtsh` → `scan-cache-poisoning` (feed `urls` dos subdomínios) —
`pipelines/cache-poison-sweep.json`.

## Avulso

```bash
echo '{"target":"https://loja.exemplo.com/"}' | go run . -pretty
echo '{"target":"https://x.com","params":{"headers":"X-Forwarded-Host,X-Host"}}' | go run .
```
