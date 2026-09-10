# js-bucket-scanner

Acha referências a **cloud storage** no HTML/JS/source maps de uma página e
testa cada bucket.

## O que preencher

- **Modo `URL única`** — Alvo = uma URL, ex `https://app.exemplo.com`. Sem
  `http(s)://` ele assume `https://`.
- **Modo `Lista colada`** — cola várias URLs no param `urls` (vírgula ou uma
  por linha). O Alvo ainda é obrigatório (serve de contexto/escopo).
- **Modo `De arquivo`** — `urls_file` = caminho de um arquivo **no servidor**
  (onde o hub roda), uma URL por linha, `#` = comentário.
- **Não usa wordlist.** Ele não adivinha nomes de bucket — só encontra os que a
  página **já referencia** (em `<script src>`, código inline, `.js.map`).

## O que ele detecta

11 provedores (todos falam o protocolo S3, menos GCS/Azure que têm o seu):
**AWS S3, GCS, Azure Blob, Cloudflare R2, DigitalOcean Spaces, Wasabi,
Backblaze B2, Linode, Scaleway, Alibaba OSS, IBM COS**.

Para cada bucket referenciado, um `GET` estilo LIST:

| resultado                              | evento                              | sev    |
|----------------------------------------|-------------------------------------|--------|
| LIST anônimo permitido (200 + listing) | `finding` `open-bucket`             | high   |
| bucket não existe (`NoSuchBucket`/404) | `finding` `bucket-takeover`         | medium |
| existe, LIST negado (403)              | `finding` `bucket-reference`        | info   |

`only_exposed=true` esconde os `info`. Também emite `asset` kind=`bucket` para
cada referência achada.

## Parâmetros

| param          | default | efeito                                     |
|----------------|---------|-------------------------------------------|
| `js`           | true    | baixar e varrer os `<script src>`         |
| `maps`         | true    | tentar os `.js.map` (source maps)         |
| `concurrency`  | 10      | workers do probe                          |
| `timeout_ms`   | 10000   | timeout HTTP                              |
| `only_exposed` | false   | esconder buckets privados                 |

## Avulso

```bash
echo '' | go run . -target https://app.exemplo.com -pretty
go run . -urls-file urls.txt -only-exposed -pretty
```
