# scan-broken-link-hijack

**Broken Link Hijacking (BLH).** Extrai os links e recursos externos de uma
página e checa quais apontam pra algo que **outra pessoa pode registrar** — e aí
esse link/script passa a servir conteúdo do atacante no contexto do alvo.

Só faz `GET` — **não registra nada**, só diz o que é registrável.

## O que preencher

- **Alvo:** a URL de uma página — `https://blog.exemplo.com`. A ferramenta baixa
  o HTML e olha `<a href>`, `<script src>`, `<iframe src>`, `<form action>` (e,
  com `include_subresources`, também `<img>` e `<link>`).
- **Sem wordlist.**

## Modos

| modo     | campo        | o que faz                                |
|----------|--------------|------------------------------------------|
| `single` | Alvo (URL)   | checa os links de uma página             |
| `list`   | `urls`       | várias páginas coladas (uma por linha)   |
| `file`   | `urls_file`  | arquivo no servidor, uma URL por linha   |

## O que ele considera sequestrável

| plataforma                                   | vira finding quando…                              | sev.   |
|----------------------------------------------|--------------------------------------------------|--------|
| **domínio externo** (qualquer host off-site) | o host **não resolve** (NXDOMAIN) → `dangling-dns`| high   |
| GitHub user/org, GitHub Pages (`*.github.io`)| GitHub responde **404** pro usuário               | high   |
| GitHub repo                                  | repo responde 404                                | medium |
| npm (`npmjs.com/package/…`, unpkg, jsDelivr) | pacote **404** no `registry.npmjs.org`           | high   |
| S3 (`*.s3.amazonaws.com`, `s3.*.amazonaws.com/b`) | corpo com `NoSuchBucket`                     | high   |
| Heroku, Netlify, Vercel, Surge, Pages.dev, GitLab Pages, Bitbucket, Webflow, Tilda, Statuspage, Canny, UserVoice, … (20 provedores) | a resposta traz a marca de "site não reclamado" | high |
| redes sociais (twitter/x, instagram, facebook, t.me, medium, tiktok) | handle responde 404 | medium |

Cada hijack sai como **`finding`** (`broken-link-hijack` ou `dangling-dns`) **+
`asset` kind=`url`** com a URL exata do link. Handles/paths reservados de cada
plataforma (`/about`, `/login`, …) são ignorados. Links pro **mesmo domínio
registrável** da página não entram na checagem genérica de DNS.

## Parâmetros

| param                  | default | efeito                                   |
|------------------------|---------|------------------------------------------|
| `include_subresources` | false   | também checar `<img>` e `<link>`         |
| `concurrency`          | 12      | checagens simultâneas                    |
| `timeout_ms`           | 10000   | timeout por requisição                   |

## Numa pipeline

`recon-crtsh` → `scan-broken-link-hijack` (feed `urls` dos subdomínios) —
`pipelines/blh-sweep.json`.

## Avulso

```bash
echo '{"target":"https://blog.exemplo.com"}' | go run . -pretty
echo '{"params":{"urls":"https://a.exemplo.com\nhttps://b.exemplo.com"}}' | go run .
```
