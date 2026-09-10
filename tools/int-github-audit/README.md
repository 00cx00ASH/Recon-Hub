# int-github-audit

Audita a **superfície pública** de uma conta/org do GitHub (ou um repo): repos,
arquivos sensíveis, segredos versionados, workflows de Actions perigosos e gists.

**Só lê a API pública** — nenhuma escrita. Um `github_token` (read-only) é
opcional e sobe o rate limit de **60 → 5000 req/h**.

## O que preencher

- **Alvo:** o **login** de uma org ou usuário (`acme-corp`), ou `owner/repo`.
- **Sem wordlist.**

## O que ele faz

1. `github-account` (info) — tipo, nº de repos/gists públicos, blog, email.
2. Enumera os repos **não-fork**, mais recentes primeiro (`max_repos`).
3. Pra cada repo: pega a **árvore de arquivos** (`git/trees?recursive=1`) e:
   - **`github-sensitive-file` (medium)** — nomes tipo `.env*`, `*.pem`,
     `id_rsa`, `.npmrc`, `.pgpass`, `*.tfstate`, `*.tfvars`,
     `serviceaccount*.json`, `wp-config.php`, `application.properties`… (ignora
     `vendor/`, `node_modules/`, `testdata/`).
   - baixa esses arquivos (raw, até 12/repo) + os **workflows** e roda um scan
     de **17 padrões de segredo** (AWS, GitHub PAT, GCP SA, Slack, Stripe,
     SendGrid, Twilio, npm, OpenAI, chave privada PEM, JWT, connection string
     com senha, `api_key`/`password` genérica com entropia) → **`github-repo-secret`**
     (sev pelo tipo, até critical).
4. **Workflows do Actions** (`.github/workflows/*.yml`):
   - **`github-pwn-request`** (high/medium) — `pull_request_target` +
     `actions/checkout` (+ checkout do head do PR = high)
   - **`github-actions-injection`** (high) — `${{ github.event.*.title/body/… }}`
     interpolado direto num `run:`
   - **`github-self-hosted-runner`** (medium)
5. **Gists públicos** (a menos que `no_gists`): baixa e varre por segredos →
   `github-gist-secret`.

Para sozinha quando o rate limit acaba (avisa e reporta o que já achou).

## Parâmetros

| param          | default | efeito                                             |
|----------------|---------|-------------------------------------------------|
| `github_token` | —       | PAT read-only (ou env `GITHUB_TOKEN`) — 5000 req/h |
| `max_repos`    | 25      | teto de repos inspecionados                     |
| `no_gists`     | false   | não inspecionar os gists                        |
| `timeout_ms`   | 15000   | timeout por requisição                          |

## Avulso

```bash
echo '{"target":"acme-corp"}' | go run . -pretty
echo '{"target":"acme-corp/webapp","params":{"github_token":"ghp_..."}}' | go run .
```
