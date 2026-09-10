# Contrato de ferramenta — recon-hub

O orquestrador é **poliglota**: cada ferramenta é um processo externo. Não
importa se é Rust, Go, Python, TS ou Bash — o que importa é como ela recebe
entrada e o que imprime no stdout.

## 1. Manifesto — `tools/<nome>/tool.json`

```json
{
  "name": "s3Scan",
  "version": "1.0.0",
  "language": "Go",
  "category": "js",
  "summary": "Scanner de buckets em 8 clouds.",
  "exec": ["./s3scan", "--target", "{target}", "--ndjson"],
  "timeout": "20m",
  "params": [
    { "name": "threads", "type": "int", "required": false, "default": 20, "help": "conexões simultâneas" },
    { "name": "list_only", "type": "bool", "required": false, "default": true }
  ]
}
```

| campo      | obrigatório | notas                                                              |
|------------|-------------|--------------------------------------------------------------------|
| `name`     | não         | default = nome da pasta                                            |
| `exec`     | **sim**     | argv. `{target}` e `{job_id}` são substituídos antes de rodar     |
| `timeout`  | não         | duração Go (`30s`, `20m`, `2h`); default `30m`                     |
| `category` | não         | `recon` \| `js` \| `scan` \| `int` (usado pelo dashboard)        |
| `params`   | não         | tipos: `string`, `int`, `bool`, `wordlist` (dashboard mostra as de `/api/wordlists`; o hub resolve o nome → caminho antes de rodar) |
| `modes`    | não         | presets (`single`/`list`/`file`…): `name`, `label`, `help`, `params` (visíveis só nesse modo), `target_label` |
| `guide`    | não         | 1-2 frases: o que pôr no Alvo, se usa wordlist |

`exec` roda com o **working directory** em `tools/<nome>/`.

## 2. Entrada que a ferramenta recebe

**stdin** — uma linha JSON:

```json
{"target":"exemplo.com","params":{"threads":40},"job_id":"a1b2c3..."}
```

**ambiente** — para quem prefere não parsear JSON:

```
RECONHUB_TARGET=exemplo.com
RECONHUB_JOB_ID=a1b2c3...
RECONHUB_PARAM_THREADS=40        # um por parâmetro, nome em MAIÚSCULAS
```

## 3. Saída — NDJSON no stdout

Uma linha = um objeto JSON. Campo `type` obrigatório.

```jsonc
{"type":"log","level":"info","msg":"resolvendo 1240 hosts"}
{"type":"progress","msg":"420/1240","data":{"pct":34}}
{"type":"finding","severity":"high","finding_type":"takeover",
 "title":"Dangling CNAME em assets.exemplo.com",
 "asset":"assets.exemplo.com",
 "evidence":"CNAME -> bkt.s3.amazonaws.com (NoSuchBucket)",
 "meta":{"provider":"aws-s3"}}
{"type":"asset","kind":"subdomain","value":"api.exemplo.com"}
{"type":"done","ok":true}
```

| type       | campos usados                                                    |
|------------|-----------------------------------------------------------------|
| `log`      | `level` (`info`/`warn`/`error`/`debug`), `msg`                 |
| `progress` | `msg`, `data` (livre; `data.pct` alimenta a barra)            |
| `finding`  | `severity`, `finding_type`, `title`, `asset`, `evidence`, `meta` |
| `asset`    | `kind` (`subdomain`/`url`/`bucket`/`endpoint`/`ip`/…), `value`  |
| `done`     | `ok` (bool), `msg` opcional                                    |
| `error`    | `msg` — erro fatal reportado pela própria ferramenta          |

`asset` é o que a ferramenta **descobre** (não uma vulnerabilidade). O hub
deduplica por `job|kind|value` e as **pipelines** usam esses valores para
alimentar o próximo step (ver README → Pipelines). Uma ferramenta de recon
(enum de subdomínios, extração de URLs…) emite `asset`; uma de scan emite
`finding`. Muitas emitem os dois.

Regras:

- `severity` ∈ `info` `low` `medium` `high` `critical` (default `info`).
- O hub **deduplica** findings por `(program, tool, finding_type, asset, title)`.
  Emitir o mesmo finding de novo (re-rodar, ou uma pipeline que passa pelo mesmo
  host) não cria linha nova: sobe `count` e `last_seen`. Ou seja, re-rodar o
  recon de um programa é idempotente.
- Linhas no stdout que **não** são JSON válido viram um evento `log` — então
  um script que só dá `echo` de resultados ainda funciona, só não gera findings.
- stderr inteiro é capturado como `log` nível `error`.
- **exit code 0** = sucesso. Qualquer outro marca o job como `failed`.
- Emitir `done` é opcional; o fim do processo já encerra o job.

## 4. Como o job termina

| situação                         | status do job |
|----------------------------------|---------------|
| exit 0                           | `succeeded`   |
| exit ≠ 0                         | `failed`      |
| estourou o `timeout`             | `failed`      |
| operador chamou `/cancel`        | `canceled`    |

## 5. Checklist para portar uma ferramenta existente

1. Aceitar alvo por `RECONHUB_TARGET` (ou flag via `{target}` no `exec`).
2. Trocar o formato de saída "bonito" por NDJSON (ou adicionar uma flag `--ndjson`).
3. Mapear cada achado para um `finding` com `severity` + `finding_type`.
4. Sair com código 0 só quando rodou de verdade.
5. Escrever o `tool.json` e jogar a pasta em `tools/`.
