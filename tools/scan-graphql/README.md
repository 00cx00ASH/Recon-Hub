# scan-graphql

Descobre endpoints **GraphQL**, testa **introspection**, enumera o schema e
checa as misconfigs clássicas. **Só faz queries de leitura** — nenhuma mutation
é executada.

## O que preencher

- **Alvo:** a **URL base** do site (`https://exemplo.com`) — com discovery
  ligado (padrão) ele tenta `/graphql`, `/api/graphql`, `/query`, `/graphiql`,
  `/playground`, … — ou o **endpoint direto** se você já souber.
- **Sem wordlist** (a lista de 16 caminhos é fixa).

## O que ele reporta

| finding_type                    | sev.   | o quê                                                          |
|---------------------------------|--------|------------------------------------------------------------|
| `graphql-endpoint`              | info   | um endpoint que responde a `query{__typename}`               |
| `graphql-introspection-enabled` | medium | `__schema` retorna o schema inteiro (tipos, queries, mutations) |
| `graphql-sensitive-field`       | medium | campo de nome sensível (`password`, `token`, `ssn`, `session`, `credential`…) |
| `graphql-dangerous-mutation`    | medium | mutation com nome perigoso (`delete*`, `impersonate*`, `*Role`, `makeAdmin`, `resetPassword`, `exec`…) |
| `graphql-get-enabled`           | low    | queries funcionam por **GET** — vetor de CSRF em mutations + cache poisoning |
| `graphql-batching-enabled`      | low    | o servidor processa um **array** de operações — brute force / bypass de rate limit / DoS |
| `graphql-field-suggestions`     | low    | o erro traz `"Did you mean …"` — reconstrói o schema mesmo com introspection off |
| `graphql-error-leak`            | medium | mensagem de erro com stack trace / SQL / caminho de arquivo    |

Cada endpoint sai como **`asset` kind=`endpoint`**.

## Parâmetros

| param         | default | efeito                                        |
|---------------|---------|----------------------------------------------|
| `no_discover` | false   | usar o Alvo como está, sem tentar os caminhos |
| `timeout_ms`  | 12000   | timeout por requisição                        |

## Numa pipeline

`recon-crtsh` → `scan-graphql` (feed `urls` dos subdomínios) —
`pipelines/graphql-sweep.json`.

## Avulso

```bash
echo '{"target":"https://exemplo.com"}' | go run . -pretty
echo '{"target":"https://api.exemplo.com/graphql","params":{"no_discover":true}}' | go run .
```
