# js-secret-hunter

Baixa a **página**, os **`<script src>`** e os **source maps** (`.js.map`) e
procura **credenciais**: 34 padrões com filtro de **entropia de Shannon** nos
genéricos e **denylist de valores de exemplo**. O valor sai **redigido**
(só as pontas) no finding.

## O que preencher

- **Alvo:** uma URL `http`/`https` — `https://app.exemplo.com`. Sem esquema
  assume **https**. **Não usa wordlist.**
- Modos **lista**/**arquivo** varrem várias URLs de uma vez.

## Modos

| modo     | campo        | o que faz                                  |
|----------|--------------|--------------------------------------------|
| `single` | Alvo (URL)   | varre uma URL                              |
| `list`   | `urls`       | várias URLs coladas (vírgula/linha)        |
| `file`   | `urls_file`  | arquivo no servidor, uma URL por linha     |

## Parâmetros

| param        | default | efeito                                          |
|--------------|---------|------------------------------------------------|
| `js`         | true    | baixar e varrer cada `<script src>`            |
| `maps`       | true    | tentar o `.js.map` de cada script (source map) |
| `timeout_ms` | 12000   | timeout por requisição                         |
| `min_len`    | 12      | tamanho mínimo do valor pra reportar          |

## O que ele detecta

AWS (`AKIA…` + secret key), GCP / API key Google, GitHub (`ghp_`/`gho_`/…),
GitLab, Slack (`xox…`), Stripe (`sk_live_`/`rk_live_`), Twilio, SendGrid,
Mailgun, OpenAI (`sk-…`), Anthropic (`sk-ant-…`), Hugging Face, JWT (`eyJ…`),
chave privada PEM (`-----BEGIN … PRIVATE KEY-----`), Basic-auth em URL,
connection string de banco com senha (`postgres://user:pass@…`), Firebase,
Algolia admin key, Sentry DSN, Cloudflare, DigitalOcean, npm, PyPI, e
**atribuições genéricas** (`api_key = "…"`, `secret: "…"`, `token=…`) que só
passam se a **entropia** for alta e o valor **não** parecer placeholder
(`example`, `your_`, `xxxx`, `changeme`, tudo igual, …).

Saída: **`finding` type `secret`**, severidade conforme o padrão
(AWS secret key / Stripe live / GCP service account = critical; a maioria das
API keys = high; genéricos e SIDs = medium/low).

## Numa pipeline

`recon-crtsh` → `js-secret-hunter` (feed `urls` dos subdomínios) —
`pipelines/secret-sweep.json`. Ou depois de `scan-fuzz`, sobre os caminhos
vivos — `pipelines/deep-web-audit.json`.

## Avulso

```bash
echo '{"target":"https://app.exemplo.com","params":{"maps":true}}' | go run .
echo '' | go run . -target app.exemplo.com -pretty
```
