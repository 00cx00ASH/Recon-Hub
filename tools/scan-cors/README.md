# scan-cors

Testa **CORS mal configurado**. Manda um `GET` com `Origin: <atacante>` e lê
`Access-Control-Allow-Origin` (ACAO) e `Access-Control-Allow-Credentials`
(ACAC) da resposta.

## O que preencher

- **Alvo:** uma URL `http`/`https` — de preferência um **endpoint de API que
  devolve dados** (`https://api.exemplo.com/me`, `/account`, `/v1/user`). CORS
  numa página HTML estática raramente importa.
- **Sem wordlist.**

## Origens testadas (~9 por URL)

`https://evil.example` · `null` · `<alvo>.evil.example` (sufixo) ·
`evil<alvo>` (prefixo colado) · `<sub>-evil.<reg>` (hífen) · `not-<alvo>` ·
`http://<alvo>` (downgrade) · `sub.random-<reg>` · `attacker.<domínio
registrável>` (qualquer subdomínio).

## Findings

| finding_type                 | sev.     | quando                                                             |
|------------------------------|----------|-----------------------------------------------------------------|
| `cors-reflect-credentials`   | critical | ACAO reflete a origem do atacante **e** ACAC: true — leitura autenticada cross-origin |
| `cors-null-origin`           | high     | `ACAO: null` **+** ACAC: true                                     |
| `cors-wildcard-credentials`  | high     | `ACAO: *` **+** ACAC: true (inválido no spec, mas alguns honram)  |
| `cors-reflect-origin`        | medium   | ACAO reflete a origem do atacante, sem credentials                |
| `cors-null-origin`           | medium   | `ACAO: null` sem credentials                                      |
| `cors-wildcard`              | low      | `ACAO: *` no baseline — ok pra API pública, problema se serve dados privados |

Cada URL com finding sai como **`asset` kind=`url`**. A evidência mostra os
headers exatos (`ACAO`, `ACAC`, `Vary`).

## Parâmetros

| param        | default | efeito                     |
|--------------|---------|---------------------------|
| `concurrency`| 8       | URLs testadas em paralelo  |
| `timeout_ms` | 10000   | timeout por requisição     |

## Numa pipeline

`recon-crtsh` → `js-hunter` (acha endpoints de API) → **`scan-cors`** sobre
eles. Ou `recon-crtsh` → `scan-cors` direto. Ver `pipelines/cors-sweep.json`.

## Avulso

```bash
echo '{"target":"https://api.exemplo.com/me"}' | go run . -pretty
```
