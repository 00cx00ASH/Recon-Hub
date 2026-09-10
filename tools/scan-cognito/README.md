# scan-cognito

Acha identificadores de **AWS Cognito** no HTML/JS (User Pool ID, Identity Pool
ID, app client IDs, `aws-exports` do Amplify) e testa — **só com leitura** — a
falha clássica: o **Identity Pool entrega credenciais AWS temporárias a quem
não está autenticado**.

## O que preencher

- **Alvo:** a URL da página — `https://app.exemplo.com`. Baixa a página + os
  `<script src>` e extrai os IDs.
- Já tem os IDs? Modo **ids**: `user_pool_id` (`us-east-1_AbC123`) e/ou
  `identity_pool_id` (`us-east-1:uuid`), mais `region` se não estiver no ID.
- **Sem wordlist.**

## O que ele faz (e por que é seguro)

1. **Identity Pool** — `GetId` (anônimo) → se vier um `IdentityId`, chama
   `GetCredentialsForIdentity`. Isso cria só uma **identidade guest efêmera**, que
   é o comportamento normal do SDK do Cognito.
   - Se voltarem **credenciais AWS temporárias** → `open-cognito-identity-pool`
     (**high**). A ferramenta então chama **`sts:GetCallerIdentity`** (assinado
     SigV4, **read-only**) pra confirmar que as credenciais são válidas e mostrar
     o **ARN** e a **conta AWS**. Aí você checa manualmente o que a role
     não autenticada permite (S3, DynamoDB…).
   - `InvalidIdentityPoolConfiguration` / sem role unauth → `cognito-identity-getid-open` (**info**, configuração correta).
   - `NotAuthorizedException` no GetId → `cognito-identity-locked` (**info**).
2. **User Pool** — detectar o pool + client já é um `cognito-identifiers-exposed`
   (**info**). Com **`test_signup: true`** (padrão **off**), manda um `SignUp` com
   **senha inválida** — **não cria conta**, só revela pelo erro se o app client
   aceita cadastro anônimo (`cognito-open-signup`, **medium**) ou não
   (`cognito-signup-disabled`, **info**).

Endpoints testados saem como **`asset` kind=`endpoint`**
(`cognito-identity-pool:…`, `cognito-user-pool:…`).

## Parâmetros

| param             | default | efeito                                                    |
|-------------------|---------|---------------------------------------------------------|
| `user_pool_id`    | —       | pula a extração (modo ids)                              |
| `identity_pool_id`| —       | pula a extração (modo ids)                              |
| `region`          | —       | região AWS, se não estiver embutida no pool id         |
| `test_signup`     | false   | checa SignUp anônimo no app client (não cria conta)     |
| `timeout_ms`      | 12000   | timeout por requisição                                  |

## Numa pipeline

`recon-crtsh` → `scan-cognito` (feed `urls` dos subdomínios) —
`pipelines/cognito-audit.json`.

## Avulso

```bash
echo '{"target":"https://app.exemplo.com"}' | go run . -pretty
echo '{"params":{"identity_pool_id":"us-east-1:1111-....","region":"us-east-1"}}' | go run .
```
