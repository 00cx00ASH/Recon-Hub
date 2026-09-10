# js-jwt-finder

Acha **JWTs** no HTML/JS de uma página (ou colados), **decodifica** header e
payload **sem verificar assinatura**, aponta problemas, e pra tokens HS*
**tenta quebrar o segredo**.

Só decodifica localmente — **nenhuma requisição ao emissor**.

## O que preencher

- **Alvo:** a URL de uma página — `https://app.exemplo.com`. Baixa a página + os
  `<script src>` e acha os `eyJ….eyJ….<sig>`.
- Já tem um token? Modo **token**: cole em `params.token` (um ou vários,
  separados por espaço/linha).
- **`wordlist`** (type wordlist): lista de **segredos** pra tentar quebrar
  HS256/384/512, além dos ~55 embutidos. Escolha uma do SecLists
  (`Passwords/…`) pra ir mais fundo.

## O que ele reporta

| finding_type            | sev.     | quando                                                          |
|-------------------------|----------|--------------------------------------------------------------|
| `jwt-found`             | info     | todo JWT achado (header + lista de claims)                     |
| `jwt-alg-none`          | high     | `alg` é `none`/vazio — assinatura desabilitada, forja livre    |
| `jwt-weak-secret`       | critical | um segredo fraco reproduz a assinatura HS* — forja QUALQUER token |
| `jwt-symmetric`         | info     | `alg` HS* (HMAC) — crackável se o segredo for fraco            |
| `jwt-no-exp`            | medium   | sem claim `exp` — o token nunca expira                         |
| `jwt-long-lived`        | low      | `exp` a mais de 1 ano — janela de abuso enorme se vazar        |
| `jwt-expired`           | info     | já expirou                                                     |
| `jwt-sensitive-claims`  | low/med  | `email` / `role` / `is_admin` / `permissions` / … no payload (lido sem chave) |
| `jwt-jku` / `jwt-x5u`   | medium   | header aponta pra URL de chave externa — checar validação (SSRF/spoof) |
| `jwt-known-issuer`      | info     | emissor Supabase / Firebase / Cognito / Auth0 / Okta / Vercel  |

Cada token vira **`asset` kind=`jwt`** (redigido — só o início do header e o fim
da assinatura).

## Parâmetros

| param        | default | efeito                                              |
|--------------|---------|--------------------------------------------------|
| `token`      | —       | JWT(s) colado(s) (modo token)                     |
| `wordlist`   | —       | segredos extra p/ crack HS* (nome resolvido pelo hub) |
| `no_js`      | false   | só o HTML, sem baixar os `<script src>`           |
| `timeout_ms` | 12000   | timeout por requisição                            |

## Numa pipeline

`recon-crtsh` → `js-jwt-finder` (feed `urls` dos subdomínios) —
`pipelines/jwt-sweep.json`.

## Avulso

```bash
echo '{"target":"https://app.exemplo.com"}' | go run . -pretty
echo '{"params":{"token":"eyJ...","wordlist":"builtin/…"}}' | go run .
```
