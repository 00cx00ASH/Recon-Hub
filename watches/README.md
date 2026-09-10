# watches/

Cada `watches/<nome>.json` é um **watch**: uma pipeline agendada + alerta de
findings novos. Criados pela API (`POST /api/watches`) ou à mão. Este diretório
é **ignorado pelo git** (`*.json`) porque o hub reescreve o arquivo com o estado
da última execução.

## Formato

```json
{
  "name": "acme-nightly",
  "pipeline": "passive-takeover",
  "target": "acme.com",
  "program": "acme",
  "every": "24h",
  "webhook": "https://discord.com/api/webhooks/…",
  "enabled": true
}
```

| campo      | o quê                                                            |
|------------|----------------------------------------------------------------|
| `pipeline` | nome de uma pipeline registrada                                 |
| `target`   | alvo passado pra pipeline                                       |
| `program`  | (opcional) escopo — filtra o feed entre steps                   |
| `every`    | intervalo (Go duration: `30m`, `6h`, `24h`; mínimo `1m`)        |
| `webhook`  | (opcional) URL que recebe `POST` com os findings **novos**      |
| `enabled`  | `false` = fica registrado mas não roda                          |

Campos preenchidos pelo hub: `last_run_id`, `last_run_at`, `last_new_findings`.

## Como funciona

O scheduler acorda a cada 30 s. Um watch **due** (nunca rodou, ou passou
`every` desde a última) dispara a pipeline. Quando a run termina, o monitor
compara os findings dela (por `Key()` deduplicado) com os da **run anterior do
mesmo watch**; se houver **novos** e `webhook` estiver setado, faz um `POST`:

```json
{
  "content": "**recon-hub** · watch `acme-nightly` · 3 finding(s) novo(s)\n…",
  "watch": "acme-nightly", "pipeline": "passive-takeover", "target": "acme.com",
  "run_id": "…", "new_findings": 3,
  "findings": [ { "severity": "high", "type": "subdomain-takeover", "title": "…", "asset": "…" } ]
}
```

O campo `content` é markdown pronto pro **Discord** (webhook nativo); os demais
campos servem pra qualquer outro consumidor.

## API

| método | rota                          | o quê                                  |
|--------|-------------------------------|--------------------------------------|
| `GET`  | `/api/watches`                | lista                                 |
| `POST` | `/api/watches`                | cria (corpo = o JSON acima)           |
| `GET`  | `/api/watches/{name}`         | o watch + as últimas 20 runs dele     |
| `POST` | `/api/watches/{name}/run`     | roda agora (ignora o schedule)        |
