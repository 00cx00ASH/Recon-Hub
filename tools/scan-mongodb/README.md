# scan-mongodb

Procura **MongoDB acessível sem autenticação**. Fala o **wire protocol
(OP_MSG)** direto — sem driver, sem dependência: handshake `hello`, depois
`listDatabases`. Se `listDatabases` funcionar **sem credenciais**, o banco está
aberto.

**Só leitura.** Nunca escreve. Com `sample`, lê apenas os **nomes de campo** de
um documento — nunca os valores.

## O que preencher

- **Alvo:** um host (IP ou domínio). As portas **27017** e **27018** são
  testadas por padrão — mude em `ports`.
- **Sem wordlist.**

## O que ele faz

1. TCP connect na porta. Fechada → pula em silêncio.
2. `hello` (handshake, sempre funciona) → versão, replica set.
3. `listDatabases`:
   - **funcionou** → **`mongodb-no-auth` (critical)** + lista de bancos. Pra cada
     banco não-sistema: `listCollections` → **`mongodb-database-exposed` (high)**
     com os nomes das coleções.
   - **erro de auth** (código 13/18, "requires authentication") →
     `mongodb-auth-required` (**info**) — porta aberta mas auth ativa (bom).
4. Com **`sample: true`**: um `find(limit 1)` na 1ª coleção do 1º banco, do qual
   extrai só os **nomes de campo** (`_id`, `email`, `password_hash`, …) como
   evidência de que há dados reais.

Endpoints saem como **`asset` kind=`endpoint`** (`mongodb://host:porta` e
`mongodb://host:porta/<db>`).

## Parâmetros

| param        | default        | efeito                                       |
|--------------|----------------|---------------------------------------------|
| `ports`      | `27017,27018`  | portas a testar                              |
| `sample`     | false          | ler os nomes de campo de 1 doc de amostra    |
| `concurrency`| 16             | hosts testados em paralelo                   |
| `timeout_ms` | 6000           | timeout por conexão/comando                  |

## Numa pipeline

`recon-passive-enum` → `scan-mongodb` (feed `hosts` dos subdomínios) —
`pipelines/mongodb-sweep.json`. Faz sentido depois de um recon que produz
hostnames; portas incomuns via `ports`.

## Avulso

```bash
echo '{"target":"10.0.0.5"}' | go run . -pretty
echo '{"params":{"hosts":"db1.exemplo.com,db2.exemplo.com","ports":"27017,27018,28017","sample":true}}' | go run .
```
