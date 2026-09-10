# scan-postman-audit

Auditoria **profunda** de uma collection do Postman que **você aponta** (por id,
URL pública, ou todas as collections de um workspace público). Diferente do
[`scan-postman-net`](../scan-postman-net/) (que **busca** por um termo), aqui
você já sabe qual collection quer dissecar.

Não autentica no Postman — usa o JSON público de `run.pstmn.io`.

## O que preencher

- **Alvo:** um dos três:
  - o **id** da collection (`12345-uuid` ou só o `uuid`)
  - a **URL pública** da collection (`www.postman.com/<handle>/<ws>/collection/<id>`)
  - a **URL de um workspace público** — audita **todas** as collections dele
- `collections` (csv/linha) — vários de uma vez.
- **Sem wordlist.**

## O que ele faz

1. **Inventário** — recorre a árvore de items e emite cada request como
   `asset` kind=`endpoint` (`GET https://…`); resume em
   `postman-collection-inventory` (info).
2. **Segredos** (`postman-secret-in-collection`) — 18 padrões: AWS, GCP,
   GitHub (`ghp_`/`github_pat_`), GitLab, Slack, Stripe, Twilio, SendGrid,
   OpenAI, Anthropic, chave privada PEM, JWT, connection string com senha,
   basic-auth em URL, `api_key`/`secret` genérica (com filtro de entropia).
3. **PII** (`postman-pii-in-collection`) — e-mail, **CPF**, **SSN**, **cartão
   de crédito** (validado por Luhn), **IBAN**, telefone. Valores **redigidos**.
4. **Auth hardcoded** (`postman-hardcoded-auth`) — valores literais nos blocos
   `auth` (`bearer`/`apikey`/`basic`/`oauth2`), ignorando `{{variáveis}}`.
5. **Hosts internos** (`postman-internal-host`, low) — `internal`/`staging`/
   `jenkins`/RFC1918/… ou subdomínios do `match_domain`. Cada um vira
   `asset` kind=`subdomain`.

## Parâmetros

| param          | default | efeito                                       |
|----------------|---------|---------------------------------------------|
| `collections`  | —       | vários ids/URLs (modo list)                 |
| `match_domain` | —       | domínio p/ marcar hosts relacionados        |
| `timeout_ms`   | 15000   | timeout por requisição                       |

## Avulso

```bash
echo '{"target":"12345-abcuuid"}' | go run . -pretty
echo '{"target":"https://www.postman.com/acme/acme-public/collection/12345-uuid","params":{"match_domain":"acme.com"}}' | go run .
```
