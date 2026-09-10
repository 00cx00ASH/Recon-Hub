# scan-postman-net

Busca na **rede pública do Postman** por um termo e varre as **collections
públicas** por segredos e hosts internos. Empresas vazam chaves de API em
workspaces públicos o tempo todo.

Usa a **API pública de busca** do Postman — não autentica, não precisa de conta.

## O que preencher

- **Alvo:** o **termo de busca** — um domínio (`exemplo.com`), o nome da empresa
  (`ACME Corp`), um produto. Se for um domínio, a marcação de **hosts
  relacionados** liga automaticamente.
- **Sem wordlist.**

## O que ele faz

1. `POST www.postman.com/_api/ws/proxy` → `/search-all` no domínio `public`.
2. Cada resultado (collection / workspace / api) vira **`asset` kind=`url`** +
   `postman-public-entity` (**info**) — publisher, workspace, descrição.
3. Pra cada **collection**, baixa o JSON completo de
   `run.pstmn.io/collections/<id>` e varre:
   - **segredos** (`postman-secret-in-collection`): AWS (`AKIA`/secret),
     Google (`AIza`, `ya29.`), GitHub (`ghp_`…), Slack (`xox…`), Stripe
     (`sk_live_`), Twilio, SendGrid, OpenAI, **chave privada PEM**, JWT,
     **basic-auth em URL** (`https://user:senha@…`), `Bearer …`, e
     `api_key`/`client_secret` genérica — com filtro de entropia e denylist de
     `{{variável}}`/placeholder. Severidade pelo tipo.
   - **hosts internos** (`postman-internal-host`, **low**): hostnames com
     `internal`/`staging`/`dev`/`jenkins`/`gitlab`/… ou RFC1918, ou
     subdomínios do `match_domain`. Cada um sai como `asset` kind=`subdomain`.

## Parâmetros

| param          | default | efeito                                            |
|----------------|---------|------------------------------------------------|
| `size`         | 25      | resultados da busca                             |
| `no_deep`      | false   | só listar, não baixar o JSON das collections    |
| `match_domain` | (auto)  | domínio p/ marcar hosts relacionados            |
| `timeout_ms`   | 15000   | timeout por requisição                          |

Se a API do Postman mudar de formato, a ferramenta degrada pra `done` OK com um
`warn` — não quebra a pipeline.

## Avulso

```bash
echo '{"target":"exemplo.com"}' | go run . -pretty
echo '{"target":"ACME Corp","params":{"size":40,"match_domain":"acme.com"}}' | go run .
```
