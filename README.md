# recon-hub

Orquestrador poliglota para o arsenal de recon. Registra ferramentas, dispara
jobs, streama o output ao vivo, normaliza os findings e serve um dashboard —
tudo num binário único, **sem nenhuma dependência externa**.

- **Núcleo:** Go 1.22, biblioteca padrão apenas. O build padrão (`go build
  ./cmd/reconhub`) não puxa **nada** de fora da stdlib.
- **Ferramentas:** processos externos em **qualquer linguagem**, descritos por um
  `tool.json`. Nada de plugin nativo, nada de recompilar o hub para adicionar uma.
- **Persistência:** append-only JSON-lines em `./data/` (padrão, zero deps).
  Backend **SQLite** opcional atrás da tag de build `sqlite` — ver
  [Backend de armazenamento](#backend-de-armazenamento). A interface `store.Store`
  isola os callers dos dois.

> **Novo por aqui?** [`docs/GUIA-DE-USO.md`](docs/GUIA-DE-USO.md) explica como o
> sistema funciona ponta-a-ponta e os fluxos de uso na ordem em que você usaria
> num programa de bug bounty.

---

## Começando (primeiro acesso)

**1. Suba o hub**

```bash
go run ./cmd/reconhub          # local
# ou:  docker compose up -d --build
```

**2. Pegue a URL de acesso no log.** O hub **nasce fechado** e gera um token no
primeiro start. Ele imprime isto (procure a moldura):

```
token gerado e salvo em /home/voce/recon-hub/data/token
┌─────────────────────────────────────────────────────────────
│ abra no navegador:  http://127.0.0.1:7878/#token=e54551cdf7fb79ee...
└─────────────────────────────────────────────────────────────
```

> Com `docker compose`, o log vem de `docker compose logs reconhub`.

**3. Abra essa URL inteira no navegador.** É só copiar e colar — a parte
`#token=...` fica no navegador (não vai pro servidor nem pro log), o dashboard
guarda o token e limpa a barra de endereço. **Você não digita nada.**

Se você abrir `http://127.0.0.1:7878` **sem** o `#token=...`, o dashboard mostra
uma tela **"Como entrar"** com o passo a passo e um campo pra colar o token.
Pra pegar o token manualmente:

```bash
cat data/token                                   # local
docker compose exec reconhub cat /app/data/token # docker
```

**Trocar o token:** `reconhub -regen-token`. **Rodar sem token** (só CI/teste):
`reconhub -no-auth`.

---

## Índice

0. [Começando (primeiro acesso)](#começando-primeiro-acesso)
1. [Visão geral](#visão-geral)
2. [Arquitetura](#arquitetura)
3. [Como a comunicação funciona](#como-a-comunicação-funciona)
4. [Tem conflito?](#tem-conflito)
5. [Como usar](#como-usar)
6. [Pipelines](#pipelines)
7. [Programas e escopo](#programas-e-escopo)
8. [Relatório para bug bounty](#relatório-para-bug-bounty)
9. [Monitoramento (watches)](#monitoramento-watches)
10. [Backend de armazenamento](#backend-de-armazenamento)
11. [Contrato de ferramenta](#contrato-de-ferramenta)
12. [Catálogo das ferramentas](#catálogo-das-ferramentas)
13. [Estrutura de pastas](#estrutura-de-pastas)
14. [MCP](#mcp)
15. [Desenvolvimento](#desenvolvimento)
16. [Roadmap](#roadmap)

---

## Visão geral

O problema: são dezenas de ferramentas de recon, cada uma com CLI própria,
formato de saída próprio e jeito próprio de rodar. O recon-hub põe uma camada só
por cima:

- um **registro** único (`GET /api/tools`) do que existe e como se chama;
- um **disparo** único (`POST /api/jobs`) — mesmo corpo para qualquer ferramenta;
- um **stream** único (SSE) para acompanhar qualquer job ao vivo;
- um **modelo de finding** normalizado (`GET /api/findings`) — severidade, tipo,
  asset, evidência — não importa se veio de um scanner em Rust ou de um script Bash;
- um **dashboard** para operar tudo isso sem decorar `curl`.

A ferramenta continua sendo um binário/script separado. O hub só a **orquestra**.

---

## Arquitetura

```
                              navegador
                                 │
                        ┌────────▼──────────┐
                        │  dashboard (web/) │   HTML + JS, servido em  GET /
                        └────────┬──────────┘
                 REST (fetch)    │    stream (EventSource / SSE)
                        ┌────────▼──────────┐
                        │    API   :7878    │   internal/api
                        │  /api/tools       │
                        │  /api/jobs        │
                        │  /api/findings    │
                        │  /api/docs        │
                        └───┬─────────┬─────┘
                 submit job │         │ subscribe(jobID)
                        ┌───▼─────────▼─────┐        ┌───────────────┐
                        │   engine          │───────▶│   bus (SSE)   │
                        │   fila + limite   │ publish└───────────────┘
                        │   de concorrência │
                        └───┬──────────┬────┘
                   spawn    │          │   append event / finding
             ┌──────────────▼───┐   ┌──▼────────────────────┐
             │   runner         │   │   store  (./data)     │
             │   argv + stdin   │   │   jobs.jsonl          │
             │   parse NDJSON   │   │   findings.jsonl      │
             └───────┬──────────┘   │   events/<jobID>.jsonl │
                     │              └───────────────────────┘
       stdin: JSON   │  + env RECONHUB_*
       stdout: NDJSON│  (log / progress / finding / done)
             ┌───────▼──────────┐
             │   ferramenta     │   processo externo, linguagem livre,
             │   tools/<nome>/  │   descrito por tool.json
             └──────────────────┘
```

| pacote               | responsabilidade                                            |
|----------------------|------------------------------------------------------------|
| `internal/config`    | `config.json` + defaults                                   |
| `internal/registry`  | lê `tools/<nome>/tool.json` e valida                       |
| `internal/runner`    | spawn do processo, injeta entrada, parseia o NDJSON        |
| `internal/engine`    | fila, limite de concorrência, ciclo de vida do job         |
| `internal/bus`       | fan-out em memória dos eventos para os assinantes SSE      |
| `internal/store`     | interface `Store`; `FileStore` (JSON-lines) + SQLite opcional (`-tags sqlite`) |
| `internal/monitor`   | watches — scheduler + diff de findings + webhook           |
| `internal/report`    | monta o relatório de bug bounty (Markdown / HTML)          |
| `internal/api`       | router HTTP, handlers, SSE, serve o `web/`                 |
| `cmd/reconhub`       | entrypoint, config, shutdown gracioso                      |

---

## Como a comunicação funciona

Quatro fronteiras, cada uma com **um** protocolo. Nenhuma delas compartilha
porta, socket ou arquivo com outra.

### 1. ferramenta ⇄ runner — stdin/stdout do processo

O runner faz `exec` do `exec` do manifesto (com `{target}` / `{job_id}`
substituídos) e conversa pelos três fluxos padrão:

- **entrada — stdin:** uma linha JSON
  `{"target":"exemplo.com","params":{...},"job_id":"..."}`
- **entrada — ambiente:** `RECONHUB_TARGET`, `RECONHUB_JOB_ID` e um
  `RECONHUB_PARAM_<NOME>` por parâmetro (para quem não quer parsear JSON).
- **saída — stdout:** **NDJSON**, um objeto por linha
  (`log` · `progress` · `finding` · `asset` · `done`). Linha que não for JSON
  válido vira um evento `log` — então um script que só dá `echo` ainda funciona.
- **saída — stderr:** capturado inteiro como `log` nível `error`.
- **fim:** exit code `0` = sucesso; qualquer outro = `failed`.

O runner **nunca** fala com a ferramenta por rede. Não há porta envolvida.

### 2. runner ⇄ engine — callbacks em processo

O runner recebe três funções e as chama enquanto lê o stdout:

- `emit(Event)` → o engine persiste (`store.AppendEvent`) e publica no bus;
- `onFinding(Finding)` → o engine grava (`store.AddFinding`) e incrementa o contador;
- `onAsset(Asset)` → o engine grava (`store.AddAsset`, deduplicado por `job|kind|value`).

Tudo isso é chamada de função Go dentro do mesmo processo. Sem serialização,
sem IPC.

### 3. engine ⇄ store / bus — em memória

- **store:** append-only. Cada evento ganha um `seq` incremental por job. Cada
  escrita também vai para o arquivo `.jsonl` correspondente.
- **bus:** `map[jobID] → conjunto de canais`. `Publish` faz um envio não-bloqueante
  para cada assinante; assinante lento é pulado, não trava o job.

Ordem de locks (não há deadlock): o `emit` pega o lock do store, **solta**, e só
então pega o lock do bus. O handler SSE faz o inverso — pega o bus, solta, pega o
store. Como nenhum dos dois segura os dois locks ao mesmo tempo, não há ciclo.

### 4. dashboard ⇄ API — HTTP same-origin

O `web/` é servido pelo **mesmo** processo e **mesma** porta da API. Então:

- **REST:** `fetch('/api/...')` — same-origin, sem CORS de verdade (o header
  `Access-Control-Allow-Origin: *` está lá só para permitir `curl`/scripts de fora).
- **stream:** `new EventSource('/api/jobs/<id>/events')`. O `EventSource` não
  manda header, então quando há token ele vai por `?access_token=`. O stream faz
  **replay** dos eventos armazenados (via `Last-Event-ID` / `seq`) e depois emenda
  no vivo, deduplicando por `seq` — reconectar não duplica linha.

---

## Tem conflito?

**Não.** Os três pontos onde daria para colidir estão isolados:

### Rotas

Go 1.22 casa a rota **mais específica** primeiro. `GET /` (o dashboard) é a menos
específica de todas, então qualquer `/api/...` ganha dela.

| método | rota                     | trata                                |
|--------|--------------------------|--------------------------------------|
| GET    | `/api/health`            | ping (sem auth)                      |
| GET    | `/api/tools`             | registro                            |
| GET    | `/api/tools/{name}`      | um manifesto                        |
| POST   | `/api/jobs`              | cria job                            |
| GET    | `/api/jobs`              | lista jobs                         |
| GET    | `/api/jobs/{id}`         | job + eventos                      |
| POST   | `/api/jobs/{id}/cancel`  | cancela                            |
| GET    | `/api/jobs/{id}/events`  | SSE                               |
| GET    | `/api/findings`          | findings (`?program=&tool=&severity=&type=`) |
| GET    | `/api/intel/findings`    | findings + pontuação/ação, ordenados por urgência |
| POST   | `/api/findings/{id}/triage` | registra confirmed/false_positive/ignored     |
| GET    | `/api/assets`            | assets descobertos (`?program=&kind=`) |
| GET    | `/api/programs`          | programas de `./programs`          |
| GET    | `/api/programs/{name}`   | um programa (escopo)              |
| GET    | `/api/programs/{name}/summary` | resumo do projeto (e resincroniza) |
| POST   | `/api/programs/{name}/sync` | resincroniza a pasta do projeto  |
| GET/PUT | `/api/programs/{name}/notes` | notas do projeto              |
| GET    | `/api/pipelines`         | pipelines de `./pipelines`        |
| POST   | `/api/pipeline-runs`     | roda uma pipeline                 |
| GET    | `/api/pipeline-runs`     | lista runs                        |
| GET    | `/api/pipeline-runs/{id}`| run + jobs dos steps              |
| POST   | `/api/pipeline-runs/{id}/cancel` | cancela o step em execução |
| GET    | `/api/pipeline-runs/{id}/events` | SSE da run                 |
| GET    | `/api/docs`              | este README (Markdown)            |
| GET    | `/`                      | dashboard (`web/`)               |

### Nome de ferramenta × rota

Nome de ferramenta **nunca** é segmento de URL. Ele viaja como o campo
`"tool"` no corpo JSON do `POST /api/jobs` e como nome de pasta em `tools/<nome>/`.
Uma ferramenta chamada `jobs` ou `api` **não** criaria rota nenhuma. Ainda assim,
a convenção de nomes abaixo usa prefixo de categoria (`recon-`, `js-`, `scan-`,
`int-`), então nenhum nome coincide com `health`, `tools`, `jobs`, `findings`,
`assets`, `pipelines`, `pipeline-runs`, `events` ou `docs`. Todos são kebab-case,
únicos e URL-safe. Nome de pipeline também viaja no corpo JSON, nunca na URL.

### Portas

Só **uma** porta no sistema: a da API (`7878` por padrão, `-addr` para trocar).
As ferramentas são subprocessos — não abrem porta. Se um dia uma ferramenta
portada quiser subir um listener próprio (ex: um Interactsh local), isso é
problema **dela**, declarado no `tool.json` dela; o hub não reserva porta nenhuma
além da sua.

---

## Como usar

### Rodar

```bash
cd ~/Desktop/recon-hub
go run ./cmd/reconhub                 # http://127.0.0.1:7878
```

Compilando:

```bash
make build && ./reconhub -addr 127.0.0.1:7878
```

### Docker

```bash
docker compose up -d --build
docker compose logs -f reconhub      # pega a URL  http://0.0.0.0:7878/#token=...
```

Abra no host como `http://127.0.0.1:7878/#token=<TOKEN>` (a porta é publicada só
no loopback). O token é gerado no 1º start e persiste no volume `reconhub-data`
(`/app/data/token`); para fixar o seu, `RECONHUB_TOKEN=… docker compose up -d`.

A imagem carrega o toolchain Go porque as ferramentas rodam via `go run .`; o
build já esquenta os caches de módulo/compilação de cada ferramenta, então
`go run` funciona offline em runtime.

**Modo dev** (repo montado, edições sem rebuild):

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
# editar tools/*.go reflete no próximo job; editar cmd/ → docker compose restart reconhub
```

Config opcional: `./reconhub -config config.json` (veja `config.example.json`).

#### Auto-update (deploy sempre no ar, sozinho)

`restart: unless-stopped` no `docker-compose.yml` já garante que o container
volta sozinho se cair ou o host reiniciar — mas isso não puxa código novo.
Pra também atualizar sozinho quando o branch avança (sem você rodar
`docker compose up -d --build` na mão toda vez), agende
`scripts/autoupdate.sh` no cron do host onde o `docker compose` roda:

```bash
crontab -e
# a cada 5 min: se origin/<branch> avançou, dá git pull + rebuild + restart
*/5 * * * * cd /caminho/pro/recon-hub && ./scripts/autoupdate.sh >> data/autoupdate.log 2>&1
```

O script é conservador: se não houver commit novo, não faz nada; se o
checkout local tiver mudança não commitada ou divergir do remoto, o
`git merge --ff-only` falha e ele **para sem sobrescrever nada** (só avisa
no log) — trabalho local nunca é descartado automaticamente. Um `flock`
evita que duas execuções se sobreponham se o rebuild demorar mais que o
intervalo do cron. Só há uma janela curta de indisponibilidade durante o
`docker compose up -d --build` de cada atualização (não é zero-downtime).

Por padrão ele segue o branch atual do checkout; pra fixar um branch
específico independente de qual está com `git checkout` no momento, defina
`RECONHUB_AUTOUPDATE_BRANCH=nome-do-branch` antes da linha do cron.

#### Proxy / Tor (rotear tráfego, trocar de IP após bloqueio)

Cada projeto tem um campo **Proxy** na aba Projetos → Autenticação
compartilhada, ao lado de Cookie/Bearer/Headers. Aceita:

- `http://host:porta` ou `https://host:porta` — proxy HTTP normal (ex:
  Burp Suite/mitmproxy rodando na sua máquina, pra interceptar o tráfego
  das ferramentas manualmente).
- `socks5://host:porta` ou `socks5://usuário:senha@host:porta` — proxy
  SOCKS5, com ou sem autenticação.

Diferente do Cookie/Bearer/Headers (que só valem pra requisições que batem
no host do alvo — nunca vazam credencial pra terceiro), o **Proxy vale pra
toda requisição** da ferramenta nesse projeto — é assim que dá pra trocar
o IP de saída.

**Tor embutido, sem serviço pago:** o repo já traz um sidecar de Tor
(`docker/tor/`) que sobe **sempre junto**, sem flag nenhuma — `docker compose
up -d --build` já inclui o container Tor, sem publicar nada pro host (só é
alcançável de dentro do container do hub). Ele fica disponível o tempo todo,
mas **nenhum tráfego passa por ele até você configurar** — continua opt-in
por programa, de propósito: alguns programas de bug bounty proíbem
explicitamente teste via IP anonimizado, então nada deve ser roteado por Tor
sem você confirmar isso pra aquele programa específico.

Configure o projeto com `socks5://127.0.0.1:9050` no campo Proxy e pronto —
o tráfego daquele projeto passa pela rede Tor.

**Rotação de circuito automática.** Se um alvo bloquear no meio do trabalho
(429/403 repetidos), a ferramenta já pede um circuito novo sozinha — troca o
nó de saída (e portanto o IP) sem você precisar fazer nada. Isso é feito
falando o protocolo de controle do Tor direto (`AUTHENTICATE ""` +
`SIGNAL NEWNYM`, só possível porque o control port nunca sai do namespace de
rede do container), com um limiar de tentativas de bloqueio consecutivas
antes de rotacionar (`RECONHUB_PROXY_BLOCK_THRESHOLD`, default 5) e um
cooldown de 20s entre rotações pra não martelar o control port. O comando
manual continua funcionando como fallback, se você quiser forçar uma
rotação a qualquer momento:

```bash
docker compose exec tor sh -c 'printf "AUTHENTICATE \"\"\r\nSIGNAL NEWNYM\r\nQUIT\r\n" | nc localhost 9051'
```

Hoje isso está implementado em 33 das 37 ferramentas (todas as que falam
HTTP com o alvo). As 4 que ficam de fora, de propósito, porque não usam
`http.Client` — falam TCP cru ou dirigem um navegador: `scan-mongodb` (wire
protocol do MongoDB), `recon-infra-enum` (port scan/banner grab),
`scan-smuggling` (mede timing numa conexão isolada — rotear por Tor
introduziria latência de circuito variável que contaminaria o próprio sinal
que a técnica depende) e `scan-xss-dom` (fala CDP com um navegador headless;
proxy só é suportado no allocator local, nunca no sidecar remoto
compartilhado — ver `docs/TOOL_CONTRACT.md`). O padrão
(`RECONHUB_PROXY_URL`/`RECONHUB_PROXY_CONTROL_URL`, ver `tools/recon-web-enum/proxy.go`)
está documentado em `docs/TOOL_CONTRACT.md` pra ferramentas novas adotarem
desde o início.

#### Chrome headless (XSS DOM-based)

Mesmo padrão de sidecar do Tor, mas sem opt-in: o repo traz um sidecar de
Chrome headless (`docker/chrome/`) que também sobe **sempre junto** no
`docker compose up -d --build`, com o devtools remoto (CDP) só alcançável de
dentro do container do hub em `127.0.0.1:9222` — nada publicado pro host. A
engine já injeta `RECONHUB_CHROME_URL=http://127.0.0.1:9222` no ambiente do
container do hub (ver `docker-compose.yml`), que qualquer ferramenta baseada
em navegador (`scan-xss-dom` por enquanto) lê automaticamente — sem
configuração por programa, porque não é segredo por programa, é infra
compartilhada.

Diferente do Tor, esse sidecar **não suporta proxy/Tor por job**: o Chrome
já está rodando como processo único compartilhado entre jobs, então não dá
pra reconfigurar `--proxy-server` dele por requisição. Se você precisa rotear
`scan-xss-dom` por Tor/proxy pra um projeto específico, passe o parâmetro
`chrome_path` apontando pra um binário Chrome/Chromium local em vez de usar
o sidecar — nesse modo a ferramenta sobe um processo novo por job e aplica
`RECONHUB_PROXY_URL` normalmente (ver `tools/scan-xss-dom/browser.go`).

Fora do `docker compose` (rodando o hub direto com `go run`/binário), sem
`RECONHUB_CHROME_URL` setado a ferramenta cai pro Chrome local — precisa de
um binário instalado no PATH ou do parâmetro `chrome_path` apontando pra um.

### Token de acesso

O hub **nasce fechado**. Toda a API (menos `GET /api/health`) exige
`Authorization: Bearer <token>`.

- **Primeiro start:** se nenhum token foi fornecido, o hub gera um (256 bits),
  salva em `./data/token` (permissão `0600`, já no `.gitignore`) e imprime no log
  a URL pronta:

  ```
  token gerado e salvo em /.../recon-hub/data/token
  abra:  http://127.0.0.1:7878/#token=<TOKEN>
  ```

  Abrir essa URL: o dashboard lê o token do fragmento `#` (que **não** vai para o
  servidor nem para o log), guarda em `localStorage` e limpa a barra de endereço.
- **Fornecer o seu:** precedência `-token <t>` › env `RECONHUB_TOKEN` ›
  `"token"` no config › `./data/token` › gerado. Um token que você forneceu
  nunca é ecoado no log.
- **Trocar:** `./reconhub -regen-token` descarta o salvo e gera outro.
- **Abrir (sem auth):** `./reconhub -no-auth` — só para CI/descartável; loga um aviso.

Comparação do token é constant-time; 401 vem com `WWW-Authenticate: Bearer`.
Só ouve em `127.0.0.1` por padrão.

### Pelo dashboard

Abra a URL do log (`http://127.0.0.1:7878/#token=…`) — ou `http://127.0.0.1:7878`
e cole o token no campo do topo (fica em `localStorage`).

1. **Novo job** (coluna da esquerda): escolha a ferramenta, o alvo, o programa
   (opcional) e os parâmetros (o formulário sai do `tool.json`), **Rodar job**.
2. **Job atual:** pill de status, barra de progresso, stream ao vivo e a tabela
   de findings do job.
3. **Jobs:** histórico. **Findings:** todos os findings, com filtro por programa
   e a coluna `×N` (quantas vezes o mesmo finding reapareceu).
4. **Pipelines:** pipeline + alvo + programa, roda, acompanha os steps ao vivo
   (cada um com link "ver job") e vê o histórico de runs.
5. **Docs:** este README, renderizado.

### Pela API

```bash
TOKEN=$(cat data/token)                 # ou o valor que você definiu
H="Authorization: Bearer $TOKEN"

# o que está registrado
curl -s -H "$H" localhost:7878/api/tools | jq

# dispara o stub de referência
JOB=$(curl -s -H "$H" -XPOST localhost:7878/api/jobs \
  -d '{"tool":"example-echo","target":"exemplo.com","params":{"count":5}}' | jq -r .id)

# acompanha ao vivo (Ctrl-C para sair) — SSE aceita o token na query
curl -N "localhost:7878/api/jobs/$JOB/events?access_token=$TOKEN"

# findings do job
curl -s -H "$H" "localhost:7878/api/findings?job=$JOB" | jq

# cancela um job em execução
curl -s -H "$H" -XPOST localhost:7878/api/jobs/$JOB/cancel
```

Filtros: `/api/jobs?tool=&status=&target=&limit=` ·
`/api/findings?job=&tool=&target=&severity=&type=&limit=`.

### Adicionar uma ferramenta

```bash
mkdir -p tools/scan-open-redirect
$EDITOR tools/scan-open-redirect/tool.json     # ver contrato abaixo
# a ferramenta em si (binário, script, o que for) na mesma pasta
```

O registro relê a pasta no start. Nada de recompilar o hub.

---

## Pipelines

Uma pipeline encadeia ferramentas: o que um step **descobre** vira parâmetro do
próximo. Definição em `pipelines/<nome>.json`:

```json
{
  "name": "crtsh-takeover",
  "description": "enum passivo por CT e, em cima, varredura de takeover",
  "steps": [
    { "tool": "recon-crtsh", "params": { "max": 2000 } },
    {
      "tool": "scan-subdomain-takeover",
      "params": { "concurrency": 25 },
      "feed": { "param": "subdomains", "source": "assets", "kind": "subdomain", "as": "csv" }
    }
  ]
}
```

**`feed`** (num step, descreve como um step **anterior** o alimenta):

| campo    | valores                        | efeito                                             |
|----------|--------------------------------|--------------------------------------------------|
| `param`  | nome de parâmetro              | onde injetar os valores coletados                |
| `from`   | id de um step (default: o step logo antes) | de qual step puxar o output           |
| `source` | `assets` · `findings` · `both` | de onde tirar (default `both`)                   |
| `kind`   | ex. `subdomain`, `bucket`      | quando inclui assets, filtra por esse kind       |
| `as`     | `csv` (default) · `lines`      | como juntar os valores                           |

**Grafo (fan-out).** Cada step pode ter um `id`; `feed.from` e `needs` (lista de
ids, só ordenação) apontam pras dependências. Steps sem dependência pendente
rodam **em paralelo**. Uma pipeline linear (sem `id`, cada step alimentando do
anterior) é só um caso do grafo — se comporta exatamente como antes.

```json
"steps": [
  { "id": "recon", "tool": "recon-crtsh" },
  { "id": "takeover", "tool": "scan-subdomain-takeover",
    "feed": { "param": "subdomains", "from": "recon", "kind": "subdomain", "as": "csv" } },
  { "id": "cors", "tool": "scan-cors",
    "feed": { "param": "urls", "from": "recon", "kind": "subdomain", "as": "lines" } }
]
```

Aqui `takeover` e `cors` rodam **juntos** sobre a saída de `recon`.

Execução (engine): cada step roda como um **job normal** (aparece na lista de
Jobs e tem stream próprio). O engine resolve o grafo, roda cada "onda" de steps
prontos concorrentemente (throttled pelo limite global de jobs), junta os
`asset`/`finding.asset` do step-fonte, deduplica, filtra pelo `kind`/escopo e
injeta no `param`. `"on_fail": "continue"` deixa a pipeline seguir se o step
falhar; sem isso, um step falho **derruba a run** e os steps que dependem dele
(direta ou transitivamente) ficam `skipped` — ramos independentes terminam
normalmente. Ciclo / `from` inválido é rejeitado no carregamento.

```bash
RUN=$(curl -s -H "$H" -XPOST localhost:7878/api/pipeline-runs \
  -d '{"pipeline":"crtsh-takeover","target":"exemplo.com","program":"acme"}' | jq -r .id)
curl -N "localhost:7878/api/pipeline-runs/$RUN/events?access_token=$TOKEN"
curl -s -H "$H" "localhost:7878/api/pipeline-runs/$RUN" | jq   # run + jobs dos steps
```

Pipelines inclusas:

| pipeline         | passos                                                        | acha                          |
|------------------|--------------------------------------------------------------|-------------------------------|
| `crtsh-takeover` | recon-crtsh → scan-subdomain-takeover                       | subdomain takeover            |
| `bucket-hunt`    | recon-crtsh → js-bucket-scanner                             | buckets abertos / takeover    |
| `content-sweep`  | recon-crtsh → scan-fuzz                                     | caminhos/arquivos escondidos  |
| `actuator-sweep` | recon-crtsh → scan-actuator                                 | Spring Boot Actuator exposto  |
| `redirect-hunt`  | recon-crtsh → scan-open-redirect                            | open redirect                 |
| `secret-sweep`   | recon-crtsh → js-secret-hunter                              | segredos no JS/source maps    |
| `deep-web-audit` | recon-crtsh → scan-fuzz → js-secret-hunter                  | segredos nos caminhos vivos   |
| `firebase-audit` | recon-crtsh → js-firebase-enum                              | RTDB/Firestore/Storage abertos |
| `dep-confusion-sweep` | recon-crtsh → scan-dep-confusion (modo site)           | pacotes npm importados sem dono |
| `blh-sweep`      | recon-crtsh → scan-broken-link-hijack                       | links externos registráveis   |
| `cognito-audit`  | recon-crtsh → scan-cognito                                  | Identity Pool aberto a anônimo |
| `passive-takeover` | recon-passive-enum → scan-subdomain-takeover              | subdomain takeover (cobertura ampla) |
| `active-subdomain-sweep` | recon-subdomain-brute → scan-subdomain-takeover       | subdomínio + takeover (achados que CT log nunca revelaria) |
| `gtm-osint`      | recon-crtsh → js-gtm-osint                                  | análise de containers GTM     |
| `cache-poison-sweep` | recon-crtsh → scan-cache-poisoning                      | web cache poisoning           |
| `supabase-audit` | recon-crtsh → js-supabase-probe                             | RLS Supabase ausente          |
| `jwt-sweep`      | recon-crtsh → js-jwt-finder                                 | JWTs fracos / mal configurados |
| `mongodb-sweep`  | recon-passive-enum → scan-mongodb                           | MongoDB sem autenticação      |
| `ai-key-sweep`   | recon-crtsh → js-ai-key-hunter                              | chaves de IA/ML vazadas       |
| `js-recon`       | recon-crtsh → js-hunter                                     | source maps + endpoints de API |
| `postman-recon`  | scan-postman-net                                            | segredos em Postman público   |
| `web-enum-sweep` | recon-crtsh → recon-web-enum                                | crawl + fingerprint + admin/sensíveis |
| `infra-sweep`    | recon-passive-enum → recon-infra-enum                       | portas abertas + serviços sensíveis |
| `infra-mongo`    | recon-passive-enum → recon-infra-enum → scan-mongodb        | MongoDB sem auth (via port scan) |
| `cors-sweep`     | recon-crtsh → scan-cors                                     | CORS mal configurado          |
| `graphql-sweep`  | recon-crtsh → scan-graphql                                  | GraphQL exposto / mal configurado |
| `recon-fanout`   | recon-crtsh → {takeover ∥ cors ∥ js-hunter}                 | fan-out: 3 varreduras em paralelo |
| `js-suite`       | recon-crtsh → {9 ferramentas `js-*` ∥ scan-cors}            | suíte JS/cloud completa (= `js-cloud-suite`) |
| `full-recon`     | recon-passive-enum → {≈18 scans ∥} → recon-infra-enum → scan-mongodb | recon completo em 3 ondas (= `recon-lambda-pipeline`) |
| `demo-echo`      | example-echo → example-echo                                 | (wiring check)                |

---

## Programas e escopo

Um **programa** (`programs/<nome>.json`) descreve o escopo de um alvo de bug
bounty:

```json
{
  "name": "acme",
  "platform": "hackerone",
  "url": "https://hackerone.com/acme",
  "in_scope": ["*.acme.com", "acme.io"],
  "out_of_scope": ["blog.acme.com", "*.internal.acme.com"]
}
```

Padrões: `*.x.com` (o apex e qualquer subdomínio), `.x.com` (só subdomínios),
`x.com` (exato). `out_of_scope` tem precedência.

Passe `"program": "acme"` ao criar um job ou uma pipeline-run. Efeitos:

- **tag** — todo job/asset/finding da execução leva `program: "acme"`; filtre com
  `?program=acme` em `/api/jobs`, `/api/findings`, `/api/assets`, `/api/pipeline-runs`.
- **escopo no feed** — numa pipeline, o feed entre steps só passa hosts
  in-scope (kinds `subdomain`/`url`); os de fora são descartados com um aviso no
  stream. crt.sh devolve muita coisa; você só escaneia o que o programa cobre.
- **dedup por programa** — a chave de dedup do finding inclui o programa, então
  re-rodar o recon de um programa é idempotente (sobe `count`, não duplica).

---

## Projeto (pasta física por alvo)

Todo programa ganha uma pasta própria em `data/projects/<nome>/` — criada
automaticamente ao criar o programa (ou na subida do hub, para os que já
existem em `programs/`) e **mantida em sincronia sozinha** a cada job daquele
programa que termina. Pensado pra quem acompanha vários alvos de bug bounty ao
mesmo tempo: cada um com sua pasta, seu relatório e suas notas, sem precisar
filtrar nada manualmente.

```
data/projects/acme/
├── summary.json    contagens (jobs por status, findings por severidade, assets por tipo, última atividade)
├── report.md       relatório de bounty, já escopado pra este programa
├── assets.json      todos os assets descobertos neste programa
└── notes.md         notas livres suas — nunca sobrescrito automaticamente
```

| método | rota                                | o quê                                             |
|--------|--------------------------------------|----------------------------------------------------|
| GET    | `/api/programs/{nome}/summary`       | contagens atuais (também resincroniza os arquivos) |
| POST   | `/api/programs/{nome}/sync`          | força a resincronização agora                      |
| GET    | `/api/programs/{nome}/notes`         | lê as notas do projeto                              |
| PUT    | `/api/programs/{nome}/notes`         | grava as notas (`{"notes":"..."}`)                  |

```bash
curl -s -H "$H" localhost:7878/api/programs/acme/summary | jq
curl -s -H "$H" -XPUT localhost:7878/api/programs/acme/notes \
  -d '{"notes":"alvo principal: acme.com\ncontato: security@acme.com"}'
```

No dashboard: aba **Projetos** — escolha o programa, veja o resumo, edite as
notas e sincronize manualmente quando quiser (o hub já faz isso sozinho depois
de cada job, mas o botão força na hora). `notes.md` é o único arquivo da pasta
que você edita; os outros são sempre regenerados a partir do que está no
`store` — não edite `summary.json`/`report.md`/`assets.json` à mão, a próxima
sincronização sobrescreve.

---

## Relatório para bug bounty

O hub monta um relatório pronto pra submeter a partir dos findings guardados.
Cada finding vira uma seção com **título, severidade, asset afetado, descrição,
passos para reproduzir** (comandos `curl`/CLI concretos, gerados do `meta` do
finding), **impacto, correção e referências** — de uma base de conhecimento por
tipo (`internal/report/templates.go`), com fallback honesto pra tipos sem
template (usa o título do finding e marca "revisar antes de submeter").

| rota                                   | formato                                    |
|----------------------------------------|--------------------------------------------|
| `GET /api/report`                      | JSON estruturado                           |
| `GET /api/report.md`                   | Markdown (colar no HackerOne/Intigriti)    |
| `GET /api/report.html`                 | página única, escura, imprimível em PDF    |
| `GET /api/programs/{nome}/report.md`   | idem, escopado pra um programa             |

Filtros na query: `program`, `target`, `job`, `tool`, `type`, `severity`,
`include_info=1`. Findings só-informativos sem template são omitidos por padrão.
No dashboard: aba **Findings** → **⬇ relatório .md** / **↗ relatório .html**.

---

## Priorização de findings (intel)

O hub não trata todo finding com o mesmo peso. `internal/intel` calcula, pra
cada um, uma **pontuação de 0 a 100** e uma **ação concreta** — "reportar
agora", "confirmar e reportar", "investigar quando der" ou "revisar em lote /
provável ruído" — combinando dois sinais:

1. **Conhecimento embutido** (`knownRisk` em `internal/intel/intel.go`) — o
   mesmo julgamento de segurança que um revisor experiente aplicaria de
   cara: `mongodb-no-auth` ou `ai-key-valid` já nascem com prior alto
   (quase sempre reais); `open-redirect` isolado ou `cors-wildcard` sem
   credentials nascem com prior baixo (normalmente ruído). Isso já funciona
   num hub **novo em folha**, sem nenhuma triagem sua ainda.
2. **Seu próprio histórico de triagem** — marque um finding como
   confirmado ou falso positivo (`POST /api/findings/{id}/triage`) e esse
   veredito entra numa tabela de frequência por `(ferramenta, tipo)`. A
   pontuação combina o prior embutido com esse histórico por suavização
   bayesiana simples: com pouco ou nenhum feedback seu, o conhecimento
   embutido decide; conforme você triagem mais achados de um mesmo tipo, o
   *seu* ambiente passa a pesar mais que o prior genérico — pra cima ou pra
   baixo, dependendo do que você vem confirmando de verdade.

Não é um modelo treinado — é zero dependências, como o resto do núcleo — mas
é aprendizado real (estatístico, não caixa-preta) que melhora com o uso.

| método | rota                                | o quê                                              |
|--------|---------------------------------------|-----------------------------------------------------|
| GET    | `/api/intel/findings`                 | findings + pontuação/ação, ordenados por urgência (mesmos filtros de `/api/findings`) |
| POST   | `/api/findings/{id}/triage`           | registra seu veredito: `{"verdict":"confirmed"\|"false_positive"\|"ignored"}` |

```bash
curl -s -H "$H" "localhost:7878/api/intel/findings?program=acme&severity=high" | jq
curl -s -H "$H" -XPOST localhost:7878/api/findings/<id>/triage -d '{"verdict":"confirmed"}'
```

No dashboard, a aba **Findings** já usa `/api/intel/findings`: cada linha
mostra a pontuação/ação (passe o mouse pra ver o porquê) e tem botões **✓
confirmar** / **✗ falso positivo** pra você alimentar o histórico direto ali.

---

## Monitoramento (watches)

Um **watch** é uma pipeline **agendada** + alerta de **findings novos**. Vive em
`watches/<nome>.json` (ignorado pelo git — o hub reescreve com o estado da
última run). Detalhes e exemplo em [`watches/README.md`](watches/README.md).

```json
{ "name": "acme-nightly", "pipeline": "passive-takeover", "target": "acme.com",
  "program": "acme", "every": "24h",
  "webhook": "https://discord.com/api/webhooks/…", "enabled": true }
```

O scheduler acorda a cada 30 s. Um watch **due** (nunca rodou, ou passou `every`
desde a última) dispara a pipeline. Quando termina, o monitor compara os
findings dela (por `Key()` deduplicado) com os da **run anterior do mesmo
watch**; se houver **novos** e `webhook` estiver setado, faz um `POST` com o
campo `content` em markdown (nativo do **Discord**) + os findings estruturados.

| método | rota                       | o quê                              |
|--------|----------------------------|-----------------------------------|
| `GET`  | `/api/watches`             | lista                              |
| `POST` | `/api/watches`             | cria                               |
| `GET`  | `/api/watches/{name}`      | o watch + as últimas 20 runs dele  |
| `POST` | `/api/watches/{name}/run`  | roda agora (ignora o schedule)     |

```bash
curl -s -H "$H" -XPOST localhost:7878/api/watches \
  -d '{"name":"acme-nightly","pipeline":"passive-takeover","target":"acme.com","every":"24h","webhook":"https://…","enabled":true}'
```

---

## Backend de armazenamento

Jobs, eventos, findings, assets e runs de pipeline passam todos por uma interface
única — `store.Store` (`internal/store/store.go`). Dois backends a implementam:

| backend  | build                                  | o quê                                                        |
|----------|----------------------------------------|-------------------------------------------------------------|
| `files`  | padrão (`go build ./cmd/reconhub`)     | append-only JSON-lines em `./data/`. **Zero dependências.**  |
| `sqlite` | `go build -tags sqlite ./cmd/reconhub` | arquivo SQLite único (`data/reconhub.db`, WAL). Driver `modernc.org/sqlite` — puro Go, sem cgo, mantém `go 1.22`. |

O build padrão **não compila** o código SQLite nem baixa o driver (`//go:build
sqlite` / `//go:build !sqlite`) — o binário segue com stdlib apenas. As deps do
driver ficam em `go.mod` marcadas `// indirect` e só entram no grafo com a tag.

**Escolher o backend** (em ordem de precedência): flag `-store sqlite`, env
`RECONHUB_STORE=sqlite`, ou `"store": "sqlite"` no config. O caminho do arquivo
é `"sqlite_path"` no config (padrão `<data_dir>/reconhub.db`).

```bash
make build-sqlite                              # -> ./reconhub-sqlite
./reconhub-sqlite -store sqlite                # usa data/reconhub.db

# migrar um ./data/ existente (FileStore) para SQLite, uma vez:
./reconhub-sqlite -migrate-store               # recusa se o .db já existe
```

Docker: `docker build --build-arg RECONHUB_SQLITE=sqlite -t reconhub:sqlite .`

`make test-sqlite` (incluído em `make check`) compila com a tag e roda os testes
do backend.

---

## Contrato de ferramenta

Resumo. Versão completa com exemplos: [`docs/TOOL_CONTRACT.md`](docs/TOOL_CONTRACT.md).

**`tools/<nome>/tool.json`**

```json
{
  "name": "scan-subdomain-takeover",
  "version": "1.0.0",
  "language": "Go",
  "category": "scan",
  "summary": "Subdomain takeover por CNAME dangling em 6+ provedores.",
  "exec": ["./takeover", "--target", "{target}", "--ndjson"],
  "timeout": "20m",
  "params": [
    { "name": "threads", "type": "int",  "required": false, "default": 20 },
    { "name": "verify",   "type": "bool", "required": false, "default": true }
  ]
}
```

| campo     | obrigatório | nota                                                        |
|-----------|-------------|------------------------------------------------------------|
| `exec`    | **sim**     | argv. `{target}` e `{job_id}` são substituídos            |
| `name`    | não         | default = nome da pasta                                    |
| `timeout` | não         | duração Go (`30s`, `20m`, `2h`); default `30m`            |
| `category`| não         | `recon` · `js` · `scan` · `int` (agrupa no dashboard)     |
| `params`  | não         | tipos `string` · `int` · `bool`                           |

**Saída — NDJSON no stdout**

```jsonc
{"type":"log","level":"info","msg":"resolvendo 1240 hosts"}
{"type":"progress","msg":"420/1240","data":{"pct":34}}
{"type":"finding","severity":"high","finding_type":"takeover",
 "title":"Dangling CNAME em assets.exemplo.com",
 "asset":"assets.exemplo.com",
 "evidence":"CNAME -> bkt.s3.amazonaws.com (NoSuchBucket)",
 "meta":{"provider":"aws-s3"}}
{"type":"done","ok":true}
```

`severity` ∈ `info` `low` `medium` `high` `critical`.

---

## Catálogo das ferramentas

Nomes padronizados: **`<categoria>-<função>`**, kebab-case, únicos. A coluna
_antes_ é o nome antigo, para transição.

Status: **`pronta`** = existe e roda no hub · **`é o hub`** = a capacidade virou
parte do próprio orquestrador · **`= pipeline`** = entregue como uma pipeline
fan-out que combina as ferramentas · **`coberta`** = a função existe em outra(s)
ferramenta(s) da lista · **`fora de escopo`** = extensão de navegador / plugin de
Burp, não encaixa no contrato de ferramenta CLI.

Hoje: **37 ferramentas prontas**; as 5 restantes do catálogo estão cobertas
pelas categorias acima (nada ficou de fora).

### recon — Plataformas de Recon

| nome                     | antes       | o que faz                                                                 | status    |
|--------------------------|-------------|--------------------------------------------------------------------------|-----------|
| `recon-orchestrator`     | monrust3    | Plataforma full-stack que orquestra as ferramentas, com dashboard e escopo por programa | **é o hub** (`cmd/reconhub`) |
| `recon-monitor`          | monrust     | Monitoramento contínuo: pipelines agendadas, diff de findings entre execuções, alerta no Discord | **é o hub** (`internal/monitor` + `watches/`) |
| `recon-infra-enum`       | enuminfra   | Port scan TCP (connect) + banner grab + fingerprint de serviço. Presets top100 (~120 portas)/top1000/web/db ou csv/ranges. Aceita host, IP ou CIDR (com teto). Marca serviços sensíveis expostos (redis, mongodb, docker API, kube-apiserver, kubelet, etcd, elastic, rdp, vnc, winrm, mssql/mysql/pg, jmx, java-rmi…). Identifica provedor cloud/CDN por host via PTR (+ fallback de CIDR só pro Cloudflare) | **pronta** |
| `recon-web-enum`         | enumrust    | Recon web leve: crawl same-site raso, fingerprint da stack (Server/cookies/markers WordPress/Next/Laravel/… + CDN/WAF), formulários (marca os de login) e parâmetros, e sondagem de ~67 caminhos admin/sensíveis (`/admin`, `/.env`, `/.git/config`, `/server-status`, `/actuator`, `/swagger.json`, `/graphql`…) com calibração de soft-404 | **pronta** |
| `recon-passive-enum`     | nagliEnum   | Enum passivo de subdomínios de 7 fontes grátis em paralelo (crt.sh, certspotter, hackertarget, AlienVault OTX, Anubis/jldc, RapidDNS, Wayback); mescla, deduplica e valida no escopo. Degrada sozinho. Superset do `recon-crtsh` | **pronta** |
| `recon-lambda-pipeline`  | lemma       | Pipeline de recon em fases (subs → HTTP → cloud → fuzz → crawl → vulns → secrets) sobre muitas ferramentas | **= pipeline** `full-recon` (fan-out, 3 ondas, 20 ferramentas) |
| `recon-crtsh`            | — (nova)    | Enum passivo de subdomínios via Certificate Transparency (crt.sh); emite assets `subdomain`. Feita para ser o 1º step de pipelines | **pronta** |
| `recon-subdomain-brute`  | — (nova)    | Enum ATIVA de subdomínio: wordlist (335 prefixos embutidos) + resolução DNS de verdade — acha o que nunca apareceu num CT log. Detecta DNS wildcard (catch-all) sozinho e filtra achado que é só o catch-all respondendo, não gera falso-positivo em massa | **pronta** |
| `recon-tech-cve`         | — (nova)    | Fingerprint passivo de stack (Server, X-Powered-By, meta generator, assets versionados como jQuery/Bootstrap/núcleo do WordPress) cruzado com uma tabela curada e estática de CVEs conhecidas — sem API externa nem feed de CVE. Sinaliza "versão velha o bastante", nunca confirma exploração | **pronta** |

### js — JavaScript, Cloud e Segredos

| nome                     | antes             | o que faz                                                              | status    |
|--------------------------|-------------------|----------------------------------------------------------------------|-----------|
| `js-cloud-suite`         | cloudfinder       | Suíte JS/cloud: buckets, secrets, source maps, GTM, GraphQL, CORS, JWT, Firebase, Supabase | **= pipeline** `js-suite` (fan-out de 9 ferramentas `js-*` + `scan-cors`) |
| `js-ai-key-hunter`       | IAcrawl           | Caça credenciais de IA/ML no HTML + JS + source maps: 28 padrões (OpenAI, Anthropic, Groq, Mistral, HuggingFace, Replicate, Google AI, Azure OpenAI, ElevenLabs, Deepgram, LangSmith, Vertex/GCP, AWS Bedrock…), filtro de entropia + denylist. Validação read-only OPCIONAL (1 GET ao endpoint de metadados) | **pronta** |
| `js-hunter`              | JSSandBox         | Recon de JS: reconstrói o código a partir de source maps (`.js.map` v3, `sourcesContent`) e extrai a superfície de API (`fetch`/`axios`/XHR, chaves `url`/`endpoint`, caminhos `/api` `/graphql` `/internal`…), marcando os sensíveis (`/admin` `/actuator` `/.env` `/token` `/export`…) | **pronta** |
| `js-live-scanner`        | js-realtime       | Extensão Chrome que analisa JS enquanto navega | **fora de escopo** (extensão de navegador); o *scanning* está em `js-secret-hunter`/`js-ai-key-hunter`/`js-hunter` |
| `js-live-scanner-legacy` | jsRealtime        | Geração antiga do analisador em tempo real | **fora de escopo** (legado da extensão) |
| `js-live-server`         | jsrealtime-server | Backend do live scanner: padrões de secret, validação, source maps | **coberta** por `js-secret-hunter` + `js-ai-key-hunter` (validação read-only) + `js-hunter` (maps) |
| `js-jwt-finder`          | jwtextension      | Acha JWTs no HTML/JS, decodifica header/payload sem verificar assinatura, aponta problemas (`alg:none`, sem `exp`, vida > 1 ano, claims sensíveis, `jku`/`x5u`, emissor conhecido) e quebra o segredo HS* com ~55 segredos fracos + wordlist opcional (SecLists) | **pronta** |
| `js-firebase-enum`       | firebaseEx        | Acha o `firebaseConfig` no HTML/JS e testa leitura anônima: Realtime Database (`.json?shallow`), Firestore (documents.list em ~18 coleções, com a apiKey do site) e Storage (listagem do bucket). Só leitura | **pronta** |
| `js-supabase-probe`      | lovableExpl       | Acha URL + anon key do Supabase no HTML/JS, decodifica o JWT (role/exp — `service_role` no cliente = critical), lista as tabelas via PostgREST e testa leitura anônima (RLS ausente) com colunas/linhas; checa se o signup está aberto. Só leitura | **pronta** |
| `js-bucket-scanner`      | s3Scan            | Extrai refs a S3/GCS/Azure Blob/R2/Spaces do HTML/JS/source maps e testa cada bucket: LIST anônimo (`open-bucket`), privado ou inexistente (`bucket-takeover`) | **pronta** |
| `js-gtm-osint`           | crawlGTM          | OSINT de Google Tag Manager: extrai IDs (GTM/GA4/UA/Ads/Floodlight) da página, baixa o container `gtm.js` público e disseca — tipos de tag, HTML customizado (heurística de suspeita), pixels de terceiros, IDs vinculados, segredos hardcoded | **pronta** |
| `js-secret-hunter`       | blob              | Varre a página + JS referenciados + source maps por segredos: 34 padrões (AWS, GCP, GitHub, Stripe, Slack, JWT, chaves privadas…), filtro de entropia de Shannon, denylist de valores de exemplo, valor redigido no finding | **pronta** |

### scan — Scanners Especializados

| nome                        | antes            | o que faz                                                          | status    |
|-----------------------------|------------------|------------------------------------------------------------------|-----------|
| `scan-cors`                 | — (nova)         | CORS mal configurado: manda `Origin: <atacante>` e lê ACAO/ACAC — reflexão de origem + `credentials: true` (crítico), origem `null`, wildcard com credentials, bypasses de regex (sufixo/prefixo/hífen/downgrade/subdomínio arbitrário) | **pronta** |
| `scan-graphql`              | — (nova)         | Descobre endpoints GraphQL (16 caminhos), testa introspection, enumera o schema, marca campos sensíveis e mutations perigosas, e checa misconfigs: queries por GET (CSRF), batching, sugestão de campos, stack trace no erro | **pronta** |
| `scan-actuator`             | actuatoRust      | Spring Boot Actuator exposto sem auth: 33 caminhos (`/actuator/*` + antigos + Jolokia), confirma pelo corpo — `/heapdump` (download do dump), `/env` (com detecção de `password`/`secret`/`token`), `/beans` `/mappings` `/loggers`… | **pronta** |
| `scan-broken-link-hijack`   | blh              | Broken Link Hijacking: extrai os links/recursos externos de uma página e checa quais são registráveis — user/repo GitHub 404, pacote npm publicável, bucket S3 `NoSuchBucket`, subdomínio de Heroku/Netlify/Vercel/Surge/… não reclamado (20 provedores), handle social livre, ou domínio que não resolve | **pronta** |
| `scan-cache-poisoning`      | cache-storm      | Web cache poisoning via 17 entradas não-chaveadas (X-Forwarded-Host/Scheme/Port, X-Original-URL, Forwarded…): injeta um canary e vê se volta refletido numa resposta cacheável; pra headers, confirma a persistência com 2ª requisição limpa. Cada teste isolado por cache-buster único | **pronta** |
| `scan-dep-confusion-npm`    | confussed        | Dependency confusion npm + PoC OOB | **coberta** por `scan-dep-confusion` (npm + PyPI/Cargo/Composer); o passo de *publicar* um pacote-canário é deixado de fora por segurança |
| `scan-dep-confusion`        | dependencyRust   | Dependency confusion npm/PyPI/Cargo/Composer: lê o manifesto (`package.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `composer.json`) ou extrai os `import`/`require` de uma página, e checa cada nome no registro público — ausente = build sequestrável | **pronta** |
| `scan-cognito`              | CrawlCognito     | Acha identificadores AWS Cognito no HTML/JS (User Pool ID, Identity Pool ID, app client IDs, aws-exports) e testa — só leitura — se o Identity Pool entrega credenciais AWS a usuários não autenticados, confirmando via `sts:GetCallerIdentity` (ARN + conta). Opcional: SignUp anônimo (sem criar conta) | **pronta** |
| `scan-open-redirect`        | crawOPENREDIRECT | Open redirect: 22 payloads de bypass (`//`, `\`, `https:/`, userinfo `@` simples e duplo, backslash-antes-do-@ de confusão de parser, sufixo confuso, whitespace/CR/tab/newline, double-URL-encoding, barra unicode fullwidth) em nomes de parâmetro comuns (wordlist), confirma pelo destino real (Location 3xx ou `<meta refresh>` / `location` JS) apontando pro canary `example.com` | **pronta** |
| `scan-subdomain-takeover`   | dnsdangling      | Subdomain takeover (CNAME dangling): cadeia DNS + ~24 fingerprints (S3, Azure, GitHub Pages, Heroku, Netlify, Vercel, Fastly…) + confirmação HTTP | **pronta** |
| `scan-fuzz`                 | fuffing          | Content discovery por wordlist (dir/arquivo) com calibração de soft-404, multi-URL. Usa as wordlists indexadas (embutidas + SecLists). `recursive_depth` opt-in refuza sozinho dentro de todo diretório achado, com teto de diretórios recursados | **pronta** |
| `scan-mongodb`              | mongoDBCRAWL     | MongoDB sem autenticação: fala o wire protocol (OP_MSG) direto — sem driver. Handshake `hello` + `listDatabases`; se abrir, lista bancos e coleções, e com `sample` lê só os nomes de campo de 1 doc (nunca valores). Distingue "exige auth" de "aberto" | **pronta** |
| `scan-postman-net`          | postEvil         | Busca na rede PÚBLICA do Postman por um termo; lista collections/workspaces públicas, baixa o JSON de cada collection (`run.pstmn.io`) e varre por segredos (AWS/Google/GitHub/Slack/Stripe/OpenAI/chave privada/Bearer/basic-auth em URL) e hosts internos/staging | **pronta** |
| `scan-postman-audit`        | postmanSAAS      | Auditoria profunda de uma collection do Postman que você aponta (id/URL/workspace): inventário dos requests, 18 padrões de segredo, PII (e-mail/CPF/SSN/cartão com Luhn/IBAN/telefone, redigidos), auth hardcoded nos blocos `auth`, hosts internos | **pronta** |
| `scan-xss`                  | — (nova)         | XSS refletido: marcador único com aspa/apóstrofo/`<` em parâmetros clássicos (q, search, name, message, callback…), confirma só quando os caracteres voltam sem escapar na resposta real — nunca dispara payload de execução. Distingue quebra de tag HTML (high) de quebra só de atributo/string JS (medium, precisa confirmação manual) | **pronta** |
| `scan-xss-dom`               | — (nova)         | XSS DOM-based via navegador headless real (CDP, não `http.Client`): vetor hash (`location.hash` nunca chega no servidor) e vetor query (JS do cliente relê `location.search` após carregar). Confirma por EXECUÇÃO real — uma propriedade `window` só vira `true` se o navegador tratar o payload como código (via `onerror` de `<img>`), nunca por texto na resposta. Não é XSS armazenado (mesma navegação, sem persistência) | **pronta** |
| `scan-sqli`                  | — (nova)         | SQL injection por vazamento de erro: aspa/aspa-dupla anexada ao valor de parâmetros clássicos (id, page, sort, category…), confirma só quando um erro de banco conhecido (MySQL/Postgres/MSSQL/Oracle/SQLite/ORMs) aparece com o payload e está ausente no baseline sem payload. Nunca time-based/booleana | **pronta** |
| `scan-ssti`                  | — (nova)         | Server-Side Template Injection: expressão matemática (7 sintaxes de engine — Jinja2/Twig, FreeMarker/Thymeleaf, Velocity, ERB, Smarty, Razor .NET, Pug/Jade Node.js) num parâmetro renderizado de volta (name, message, search…), confirma só quando o resultado CALCULADO aparece na resposta, ausente no baseline, E o texto cru do payload NÃO aparece (prova avaliação, não reflexo tipo XSS). Par de fatores aleatório por requisição | **pronta** |
| `scan-ssrf`                  | — (nova)         | Server-Side Request Forgery: injeta URLs de recursos internos/bem-conhecidos (metadata AWS/GCP/Azure/Alibaba/OCI, Kubernetes API server, loopback com variantes decimal/hex, `file:///etc/passwd`) em parâmetros buscados pelo SERVIDOR (webhook, import, proxy, avatar por URL…), só reporta quando o CONTEÚDO da resposta prova que o servidor buscou aquele recurso | **pronta** |
| `scan-auth-flow`             | — (nova)         | SSO/OAuth: descobre o `authorization_endpoint` (`.well-known` ou caminhos comuns), testa bypass de validação de `redirect_uri` (confirmado só pelo destino real da resposta) e inventaria endpoints de metadata SAML encontrados (sem validar assinatura XML) | **pronta** |
| `scan-smuggling`             | — (nova)         | HTTP Request Smuggling (CL.TE/TE.CL) por timing oracle: corpo ambíguo entre Content-Length e Transfer-Encoding numa conexão TCP isolada, mede se o servidor trava esperando dado que nunca chega. Nunca encadeia uma 2ª requisição real pra "provar" o desync — técnica deliberadamente segura | **pronta** |
| `scan-idor`                  | — (nova)         | IDOR horizontal com DUAS sessões de teste do operador: compara a resposta cruzada (sessão A lendo o recurso de B, ou vice-versa) contra o baseline legítimo do dono real — só status+tamanho de corpo, nunca guarda o corpo da resposta (sem PII no finding) | **pronta** |
| `scan-bruteforce-check`      | — (nova)         | Confirma AUSÊNCIA de rate limiting/lockout num endpoint de login/OTP: tentativas de credencial errada travadas (teto rígido de 10) contra uma conta de TESTE descartável do operador, para no 1º sinal de proteção (429/Retry-After/CAPTCHA/mudança de status ou latência) | **pronta** |

### int — Integrações

| nome                | antes               | o que faz                                                    | status    |
|---------------------|---------------------|-----------------------------------------------------------|-----------|
| `int-github-audit`  | github-intelligence | Audita a superfície pública de uma conta/org/repo do GitHub: enumera repos, sinaliza arquivos de nome sensível (`.env`, `*.pem`, `*.tfstate`, `.npmrc`/`.pypirc`/`.netrc`/`.weblate`…), baixa+varre por 17 padrões de segredo, e analisa os workflows do Actions (pwn-request `pull_request_target`+checkout, injeção `${{ github.event.* }}` em `run:`, runner self-hosted, config "ambiente" versionada + `secrets.*` exposto + execução sobre conteúdo não confiável — sinal combinado de possível exfiltração de segredo) + gists. `github_token` opcional (60→5000 req/h). Só leitura | **pronta** |
| `int-burp-mcp`      | mcpBurp             | MCP para dirigir o Burp Suite | **fora de escopo** (plugin do Burp + MCP próprio); o hub já expõe seu próprio MCP em `cmd/reconhub-mcp` |

### referência

| nome           | o que faz                                                              | status |
|----------------|--------------------------------------------------------------------|--------|
| `example-echo` | Stub em Bash: emite `log`/`progress`/`finding`/`asset` de exemplo. Molde mínimo para portar as reais | pronta |

---

## Estrutura de pastas

```
cmd/reconhub/               entrypoint, resolução de token, shutdown
cmd/reconhub-mcp/           servidor MCP (stdio) — expõe o hub p/ o Claude
internal/config/            config.json + defaults
internal/auth/              resolução + verificação do token (constant-time)
internal/store/             interface Store; FileStore (JSON-lines) + sqlite.go (-tags sqlite)
internal/registry/          carrega tools/<nome>/tool.json
internal/pipeline/          carrega pipelines/<nome>.json
internal/scope/             carrega programs/<nome>.json + match de escopo
internal/project/           pasta física por programa (data/projects/<nome>/): notas + snapshot sincronizado
internal/intel/             prioriza findings: conhecimento embutido + aprendizado por triagem
internal/wordlist/          indexa wordlists/ + um checkout do SecLists
internal/monitor/           watches: pipeline agendada + diff de findings + webhook
internal/runner/            spawn do processo + parser NDJSON
internal/bus/               fan-out de eventos p/ SSE
internal/engine/            fila, concorrência, ciclo de vida do job + runPipeline (grafo)
internal/api/               router HTTP + handlers + SSE
tools/example-echo/         ferramenta de referência (Bash, molde mínimo)
tools/scan-subdomain-takeover/  1ª ferramenta real (Go, módulo próprio)
tools/recon-crtsh/          enum passivo via crt.sh (Go, módulo próprio)
tools/js-bucket-scanner/    refs a cloud storage no JS/HTML (Go, módulo próprio)
tools/scan-fuzz/            content discovery por wordlist (Go, módulo próprio)
tools/js-secret-hunter/     segredos na página + JS + source maps (Go, módulo próprio)
tools/scan-actuator/        Spring Boot Actuator exposto (Go, módulo próprio)
tools/scan-open-redirect/   open redirect com bypasses + canary (Go, módulo próprio)
tools/scan-dep-confusion/   dependency confusion npm/PyPI/Cargo/Composer (Go, módulo próprio)
tools/js-firebase-enum/     firebaseConfig → RTDB/Firestore/Storage abertos (Go, módulo próprio)
tools/scan-broken-link-hijack/  links externos registráveis (Go, módulo próprio)
tools/scan-cognito/         Identity Pool AWS entregando creds a anônimo (Go, módulo próprio)
tools/recon-passive-enum/   enum passivo de subdomínios, 7 fontes (Go, módulo próprio)
tools/recon-subdomain-brute/ enum ativa de subdomínio: wordlist + DNS, filtra wildcard (Go, módulo próprio)
tools/js-gtm-osint/         OSINT de Google Tag Manager (Go, módulo próprio)
tools/scan-cache-poisoning/ web cache poisoning por entrada não-chaveada (Go, módulo próprio)
tools/js-supabase-probe/    Supabase: RLS ausente / service_role no cliente (Go, módulo próprio)
tools/js-jwt-finder/        acha, decodifica e quebra JWTs (Go, módulo próprio)
tools/scan-mongodb/         MongoDB sem auth via wire protocol (Go, módulo próprio)
tools/js-ai-key-hunter/     credenciais de provedores de IA/ML (Go, módulo próprio)
tools/js-hunter/            source maps + superfície de API do JS (Go, módulo próprio)
tools/scan-postman-net/     segredos na rede pública do Postman (Go, módulo próprio)
tools/recon-web-enum/       crawl + fingerprint + probe de caminhos (Go, módulo próprio)
tools/recon-infra-enum/     port scan TCP + banner + fingerprint (Go, módulo próprio)
tools/int-github-audit/     auditoria da superfície pública do GitHub (Go, módulo próprio)
tools/scan-cors/            CORS mal configurado (Go, módulo próprio)
tools/scan-graphql/         descoberta + misconfig de GraphQL (Go, módulo próprio)
tools/scan-postman-audit/   auditoria profunda de collection do Postman (Go, módulo próprio)
tools/recon-tech-cve/       fingerprint passivo de stack × tabela curada de CVEs (Go, módulo próprio)
tools/scan-auth-flow/       SSO/OAuth: bypass de redirect_uri + metadata SAML (Go, módulo próprio)
tools/scan-xss/             XSS refletido confirmado por texto, sem navegador (Go, módulo próprio)
tools/scan-xss-dom/         XSS DOM-based confirmado por execução real num navegador headless (Go, módulo próprio)
tools/scan-sqli/            SQL injection por vazamento de erro real (Go, módulo próprio)
tools/scan-ssti/            Server-Side Template Injection confirmado por avaliação real (Go, módulo próprio)
tools/scan-ssrf/            SSRF confirmado pelo conteúdo da resposta (Go, módulo próprio)
tools/scan-smuggling/       request smuggling via timing oracle (Go, módulo próprio)
tools/scan-idor/            IDOR horizontal com duas sessões de teste (Go, módulo próprio)
tools/scan-bruteforce-check/ ausência de rate limiting/lockout em login/OTP (Go, módulo próprio)
internal/report/            findings → relatório .md / .html de bug bounty
internal/scopetemplate/     templates de escopo (out_of_scope/platform) reaproveitáveis
pipelines/                  crtsh-takeover, bucket-hunt, content-sweep,
                            actuator-sweep, redirect-hunt, secret-sweep,
                            deep-web-audit, firebase-audit, dep-confusion-sweep,
                            blh-sweep, cognito-audit, passive-takeover,
                            gtm-osint, cache-poison-sweep, supabase-audit,
                            jwt-sweep, mongodb-sweep, ai-key-sweep, js-recon,
                            postman-recon, web-enum-sweep, infra-sweep,
                            infra-mongo, cors-sweep, graphql-sweep,
                            sqli-sweep, xss-sweep, dom-xss-sweep,
                            recon-fanout, js-suite, full-recon, demo-echo
programs/                   escopo dos alvos (projetos)
scope-templates/            templates de escopo salvos (*.json)
watches/                    pipelines agendadas (*.json no .gitignore — estado mutável)
wordlists/                  wordlists embutidas (+ SecLists via seclists_dir)
web/                        dashboard servido em /
docs/TOOL_CONTRACT.md       contrato de ferramenta (completo)
data/                       runtime: jobs/findings/assets/events/pipeline_runs + token — no .gitignore
data/projects/<nome>/       pasta por programa: notes.md (suas notas), summary.json, report.md, assets.json
```

Cada ferramenta em Go é um **módulo próprio** (`go.mod` na pasta): `go build ./...`
na raiz do hub não desce nelas, então o núcleo do hub segue com zero deps.

---

## MCP

`cmd/reconhub-mcp` é um servidor **Model Context Protocol** (stdio, zero deps) que
expõe o hub para o Claude / qualquer cliente MCP. Ele fala com o hub pela API
HTTP — o hub precisa estar rodando.

Config por env: `RECONHUB_URL` (default `http://127.0.0.1:7878`) e
`RECONHUB_TOKEN` — se não setar, ele lê `./data/token` (rode o MCP na pasta do
hub). Ferramentas MCP expostas:

| ferramenta MCP           | faz                                              |
|--------------------------|-------------------------------------------------|
| `hub_list_tools` / `hub_list_pipelines` / `hub_list_programs` | inventário |
| `hub_run_job`            | dispara uma ferramenta contra um alvo           |
| `hub_get_job` / `hub_list_jobs` / `hub_cancel_job` | acompanha jobs         |
| `hub_run_pipeline` / `hub_get_pipeline_run` / `hub_list_pipeline_runs` | pipelines |
| `hub_compare_pipeline_runs` | diff de findings/ativos entre duas pipeline-runs (mesma pipeline+alvo+programa) — novo/resolvido/persiste |
| `hub_list_findings` / `hub_list_assets` | resultados (com filtros)          |
| `hub_list_chain_candidates` | combinações de findings confirmados que mudam de categoria juntas (open redirect + OAuth no mesmo host, SSRF no endpoint de metadata cloud…) — cross-referencia dados já coletados, nunca escaneia de novo |
| `hub_triage_finding`     | registra veredito (confirmed/false_positive/…) + motivo — alimenta o intel |
| `hub_create_program`     | cria um programa (escopo) só com o `in_scope` que o operador deu |
| `hub_list_scope_templates` / `hub_create_scope_template` | templates de out_of_scope/platform reaproveitáveis, aplicados no create_program |
| `hub_get_lessons` / `hub_add_lesson` | base de conhecimento cross-programa (`data/lessons.md`) — aditiva, nunca sobrescreve |
| `hub_draft_finding` / `hub_program_report` | relatório .md pronto (1 achado, ou o programa inteiro) |

22 tools ao todo (`hub_list_tools` inclusive).

### Passo a passo

**1. Suba o hub** (o MCP é só uma ponte — ele não funciona sem o hub no ar):

```bash
make run          # ou: docker compose up -d
```

**2. Pegue o token** (o MCP precisa dele pra falar com a API):

```bash
cat data/token            # rodando local
# docker: docker compose exec reconhub cat /app/data/token
```

**3. Registre o server no seu cliente MCP.**

- **Claude Code** (terminal, na pasta do projeto): o `.mcp.json` já está no repo.
  Rode `claude`, ele pergunta se quer habilitar o server `reconhub` → aceite.
  Confirme com `/mcp` (deve listar `reconhub` como `connected`). Se o token não
  vier do `./data/token` automaticamente, exporte antes: `export RECONHUB_TOKEN=$(cat data/token)`.
- **Claude Desktop**: `make mcp` (gera `./reconhub-mcp`), depois edite
  `claude_desktop_config.json`:

  ```json
  {
    "mcpServers": {
      "reconhub": {
        "command": "/caminho/absoluto/para/recon-hub/reconhub-mcp",
        "env": {
          "RECONHUB_URL": "http://127.0.0.1:7878",
          "RECONHUB_TOKEN": "cole-o-token-do-passo-2"
        }
      }
    }
  }
  ```

  Reinicie o Desktop. O ícone de ferramentas (🔨) deve mostrar as `hub_*`.

**4. Use em linguagem natural.** Exemplos de pedido:

> "Liste as ferramentas do hub e rode `recon-crtsh` contra `exemplo.com`."
> "Roda a pipeline `deep-web-audit` em `exemplo.com` e me avisa quando acabar."
> "Quais findings `high` ou `critical` apareceram no programa `acme`?"
> "Pega os assets do último job e roda `scan-open-redirect` só nos que são URL."

Nos bastidores isso vira `hub_list_tools` → `hub_run_job` → (polling)
`hub_get_job` → `hub_list_findings`. Você acompanha tudo no dashboard também.

### Como isso te ajuda

- **Um só lugar pra pedir recon.** Em vez de decorar flags de 8 binários, você
  descreve o objetivo e o Claude escolhe a ferramenta, o modo e a wordlist.
- **Encadeia raciocínio + execução.** Ele roda `recon-crtsh`, lê os assets,
  decide quais valem `scan-fuzz`, dispara, lê os findings e resume — sem você
  copiar/colar entre passos.
- **Triagem de findings.** "Tem algum segredo de verdade nesse job ou é tudo
  placeholder?" — ele puxa `hub_list_findings`, olha os valores redigidos e a
  severidade e te dá a lista curta.
- **Escopo respeitado.** Passando `program`, tanto os jobs quanto o feed das
  pipelines filtram pelo `in_scope`/`out_of_scope` do programa.
- **Assíncrono.** `hub_run_job`/`hub_run_pipeline` retornam na hora com o id;
  o Claude faz o acompanhamento e só te chama de volta com o resultado.

Limites: o MCP **não** cria ferramentas nem edita pipelines/programas (isso é
arquivo no repo); ele orquestra o que já existe.

---

## Desenvolvimento

`make help` lista os atalhos. Os principais:

| alvo             | o quê                                                        |
|------------------|------------------------------------------------------------|
| `make run`       | sobe o hub (`go run`)                                       |
| `make check`     | `fmt-check` + `vet` + `test` em **todos** os módulos (é o que o CI roda) |
| `make test-race` | idem com `-race`                                            |
| `make tools-build` | compila cada módulo de ferramenta (valida offline)       |
| `make docker` / `make up` / `make up-dev` | imagem / compose / compose dev       |

**CI** (`.github/workflows/ci.yml`), em todo push e PR:

- **go** (matriz: hub + cada `tools/*` com `go.mod`) — `gofmt -l`, `go vet`,
  `go build`, `go test -race`;
- **shellcheck** — nos `*.sh`;
- **docker build** — builda a imagem, sobe o container e checa que
  `/api/health` responde e que `/api/tools` sem token dá `401`.

`GOTOOLCHAIN=local` em tudo: as deps são fixadas para Go 1.22 de propósito
(`miekg/dns@latest` exige 1.25+; `modernc.org/sqlite` fica em `v1.34.4`, a
última que ainda declara `go 1.22`).

---

## Roadmap

1. ~~1ª ferramenta real~~ — **feito:** `scan-subdomain-takeover` (Go, `miekg/dns`).
2. ~~Pipelines~~ — **feito:** `feed` de assets/findings entre steps; `crtsh-takeover`,
   `bucket-hunt`. Também novas: `recon-crtsh`, `js-bucket-scanner`.
3. ~~Alvos e escopo~~ — **feito:** `programs/<nome>.json`, tag de
   `program` em job/pipeline, dedup de finding por `(program,tool,type,asset,title)`,
   filtro de escopo no feed. `on_fail: continue` no step.
4. ~~Encadeamento mais rico~~ — **feito:** grafo de pipeline com `id` / `feed.from`
   / `needs`, ondas de steps em paralelo, `skipped` para dependentes de um step
   falho. Ver `recon-fanout`.
5. ~~Monitoramento~~ — **feito:** `watches/<nome>.json`, scheduler no hub, diff
   de findings vs a run anterior, `POST` no webhook (Discord). `internal/monitor`,
   API `/api/watches`.
6. ~~SQLite~~ — **feito:** backend opcional atrás da tag de build `sqlite`
   (`modernc.org/sqlite`, puro Go). O build padrão segue zero-deps. Interface
   `store.Store`, `-store sqlite`, `-migrate-store`. Ver
   [Backend de armazenamento](#backend-de-armazenamento).
7. **Auth multiusuário** — hoje é um bearer token único (constant-time, gerado no
   1º start, `data/token`); contas/escopos depois, se precisar.
