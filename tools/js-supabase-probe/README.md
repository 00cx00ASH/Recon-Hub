# js-supabase-probe

Acha a **URL + a anon key do Supabase** no HTML/JS de uma página e testa — **só
leitura** — a API **PostgREST**: lista as tabelas expostas e checa quais
permitem **leitura anônima** (RLS ausente ou fraca).

## O que preencher

- **Alvo:** a URL da página — `https://app.exemplo.com`. Baixa a página + os
  `<script src>` e extrai `https://<ref>.supabase.co` e a chave (JWT).
- Já tem? Modo **creds**: `supabase_url` + `anon_key`.
- **Sem wordlist** — as tabelas vêm do **próprio PostgREST** (documento raiz
  OpenAPI em `/rest/v1/`).

## O que ele faz

1. **Decodifica o JWT** (sem verificar assinatura) → mostra `role` e `exp`.
   `role: service_role` numa chave de cliente = **`supabase-service-role-key-exposed`
   (critical)** — ignora TODA a RLS, leitura **e** escrita no banco inteiro.
2. `GET /rest/v1/?apikey=…` → lista de tabelas/views → `supabase-rest-enumerable` (info).
3. Pra cada tabela (até `max_tables`): `GET /rest/v1/<t>?select=*&limit=1` →
   - 200 com linhas → **`supabase-anon-table-read` (high)** — mostra as colunas.
   - 200 `[]` → **medium** (lê anonimamente, vazia ou RLS filtra tudo).
   - `permission denied` / código `42501` → RLS OK, contabilizado em
     `supabase-rls-enforced` (info).
4. `GET /auth/v1/settings` → se `disable_signup=false` → `supabase-signup-enabled`
   (low), com os provedores OAuth configurados.

Endpoints tocados saem como **`asset` kind=`endpoint`** (a URL do projeto e
`/rest/v1/<tabela>` de cada tabela aberta). **Nunca escreve.**

## Parâmetros

| param         | default | efeito                                     |
|---------------|---------|-------------------------------------------|
| `supabase_url`| —       | `https://<ref>.supabase.co` (modo creds)  |
| `anon_key`    | —       | anon ou service key (JWT)                 |
| `max_tables`  | 40      | teto de tabelas testadas por projeto     |
| `timeout_ms`  | 12000   | timeout por requisição                    |

## Numa pipeline

`recon-crtsh` → `js-supabase-probe` (feed `urls` dos subdomínios) —
`pipelines/supabase-audit.json`.

## Avulso

```bash
echo '{"target":"https://app.exemplo.com"}' | go run . -pretty
echo '{"params":{"supabase_url":"https://xxxx.supabase.co","anon_key":"eyJ..."}}' | go run .
```
