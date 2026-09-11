# recon-web-enum

Recon web **leve** de um site: crawl raso + fingerprint da stack + sondagem de
caminhos administrativos/sensíveis. Sem dependências externas, sem Nuclei.

## O que preencher

- **Alvo:** a **URL raiz** do site — `https://exemplo.com`.
- **Sem wordlist** — a lista de ~67 caminhos é fixa e curada.

## O que ele faz

1. **Crawl same-site** (segue `<a href>`, `<script src>`, `<iframe src>` do
   mesmo domínio registrável), até `depth` níveis e `max_pages` páginas. Cada
   página vira `asset` kind=`url`.
2. **Fingerprint** (`web-tech-detected`, info): `Server`, `X-Powered-By`,
   `X-AspNet-Version`, cookies (`PHPSESSID`→PHP, `JSESSIONID`→Java,
   `laravel_session`, `connect.sid`→Express…), markers no corpo (WordPress,
   Drupal, Joomla, Next.js, Nuxt, Angular, React, Rails, Shopify, Wix,
   Squarespace…), CDN/WAF (Cloudflare, CloudFront, Fastly, Akamai, Sucuri,
   Vercel, Netlify), `<meta name="generator">`.
3. **Formulários** (`web-form` / `web-login-form` se tiver campo `password`) com
   action, método e nomes dos campos.
4. **Parâmetros** vistos (`web-params-observed`, info) — dos query strings e dos
   inputs de formulário.
5. **Sondagem** com **calibração de soft-404** (2 caminhos aleatórios). Cada
   caminho encontrado vira `asset` kind=`url` + finding:
   - `admin-panel-found` (medium/low) — `/admin`, `/wp-admin/`, `/phpmyadmin/`,
     `/manager/html`, `/adminer.php`… (401/403 conta como "existe mas protegido")
   - `sensitive-file-exposed` (high) — `/.env`, `/.git/config`, `/.git/HEAD`,
     `/backup.sql`, `/.htpasswd`… (exige conteúdo que pareça o arquivo, não uma
     página SPA)
   - `debug-endpoint-found` (medium/high) — `/server-status`, `/phpinfo.php`,
     `/actuator`, `/metrics`, `/_debugbar/open`
   - `api-doc-found` (low/medium) — `/swagger.json`, `/openapi.json`,
     `/api-docs`, `/graphql`, `/graphiql`
   - `web-info-file` (info) — `/robots.txt`, `/sitemap.xml`, `security.txt`

## Parâmetros

| param        | default | efeito                                     |
|--------------|---------|-------------------------------------------|
| `depth`      | 2       | profundidade do crawl                     |
| `max_pages`  | 60      | teto de páginas                           |
| `no_probe`   | false   | só crawl + fingerprint                    |
| `concurrency`| 10      | requisições simultâneas na sondagem       |
| `timeout_ms` | 10000   | timeout por requisição                    |

## Numa pipeline

`recon-crtsh` → `recon-web-enum` (feed a raiz de cada subdomínio) —
`pipelines/web-enum-sweep.json`.

## Avulso

```bash
echo '{"target":"https://exemplo.com"}' | go run . -pretty
echo '{"target":"https://exemplo.com","params":{"depth":3,"no_probe":true}}' | go run .
```
