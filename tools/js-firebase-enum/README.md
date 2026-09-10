# js-firebase-enum

Acha o **`firebaseConfig`** no HTML/JS de uma página e testa o que dá pra
**ler sem autenticar**. **Só leitura** — nunca escreve, nunca apaga.

## O que preencher

- **Alvo:** a URL da página — `https://app.exemplo.com`. A ferramenta baixa a
  página + os `<script src>` e extrai `apiKey`, `authDomain`, `databaseURL`,
  `projectId`, `storageBucket`. Falta `databaseURL`? Ela deriva os endpoints
  padrão a partir do `projectId`.
- **Sem wordlist.** As coleções do Firestore são uma lista fixa de ~18 nomes
  comuns (`users`, `config`, `messages`, `orders`, …).
- Já tem o config? Modo **config**: cole em `params.config`, deixe o Alvo vazio.

## Modos

| modo     | campo        | o que faz                                    |
|----------|--------------|----------------------------------------------|
| `single` | Alvo (URL)   | extrai o config da página e sonda            |
| `config` | `config`     | você cola o `firebaseConfig`                 |
| `list`   | `urls`       | várias páginas coladas (uma por linha)       |
| `file`   | `urls_file`  | arquivo no servidor, uma URL por linha       |

## O que ele sonda

| alvo                | request                                             | finding (aberto)        | sev.   |
|---------------------|----------------------------------------------------|-------------------------|--------|
| Realtime Database   | `GET <db>/.json?shallow=true` (só as chaves de topo)| `open-rtdb-read`        | high (dados) / medium (vazio) |
| Firestore           | `GET .../documents/<coleção>?pageSize=1&key=<apiKey>`| `open-firestore-read`   | high / medium |
| Storage             | `GET firebasestorage.../v0/b/<bucket>/o?maxResults=10`| `open-storage-list`     | high / medium |

Também emite, sempre: `firebase-config-exposed` (**info** — o config no cliente
é esperado, mas mapeia o projeto). Quando as regras estão **fechadas**, emite
`rtdb-locked` / `firestore-locked` / `storage-locked` (info) — útil pra
inventário. RTDB/Storage/Firestore inexistentes não geram finding.

Endpoints que respondem saem como **`asset` kind=`endpoint`** (`https://…-rtdb…`,
`gs://<bucket>`, `firestore:<proj>/<coleção>`).

## Parâmetros

| param          | default | efeito                        |
|----------------|---------|-------------------------------|
| `no_firestore` | false   | pula a sondagem do Firestore  |
| `no_storage`   | false   | pula a sondagem do Storage    |
| `timeout_ms`   | 12000   | timeout por requisição        |

## Numa pipeline

`recon-crtsh` → `js-firebase-enum` (feed `urls` dos subdomínios) —
`pipelines/firebase-audit.json`.

## Avulso

```bash
echo '{"target":"https://app.exemplo.com"}' | go run . -pretty
echo '{"params":{"config":"{\"apiKey\":\"AIza...\",\"projectId\":\"meu-proj\"}"}}' | go run .
```
