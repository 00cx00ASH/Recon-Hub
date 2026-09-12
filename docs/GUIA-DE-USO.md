# Guia de uso — recon-hub

Como o sistema funciona, como as peças conversam, o que existe hoje, e os fluxos
de uso na ordem em que você usaria de verdade num programa de bug bounty.

Referência complementar: [`TOOL_CONTRACT.md`](TOOL_CONTRACT.md) (contrato de
ferramenta) e o [`README.md`](../README.md) (instalação, auth, catálogo completo).

---

## 1. Modelo mental — 3 camadas

```
┌─ CLIENTES ────────────────────────────────────────────────┐
│  dashboard web (/)   ·   API REST+SSE   ·   MCP (Claude)   │
└───────────────────────────┬───────────────────────────────┘
                            │  HTTP same-origin + token
┌─ NÚCLEO (cmd/reconhub) ───┴───────────────────────────────┐
│  api → engine (fila, concorrência) → runner (spawn)        │
│         ├─ store   (jobs/findings/assets/runs)  files|sqlite│
│         ├─ bus     (SSE ao vivo)                            │
│         ├─ pipeline (grafo de steps)                        │
│         ├─ scope   (programs/*.json — in/out of scope)      │
│         ├─ monitor (watches — agendado + webhook)           │
│         ├─ report  (findings → .md/.html de bounty)         │
│         └─ wordlist (wordlists/ + SecLists)                 │
└───────────────────────────┬───────────────────────────────┘
                            │  stdin JSON + env  →  NDJSON stdout
┌─ FERRAMENTAS (tools/<nome>/) ─────────────────────────────┐
│  37 processos externos, cada um módulo Go isolado.         │
│  O hub NÃO depende delas; elas não incham o hub.           │
└───────────────────────────────────────────────────────────┘
```

O ponto central: **o hub não sabe o que cada ferramenta faz**. Ele sabe iniciar
um processo, mandar um alvo + parâmetros, e ler linhas NDJSON de volta. Todo o
resto (dashboard, findings normalizados, pipelines, relatório) é construído em
cima desse contrato.

---

## 2. Como as peças conversam

### O contrato ferramenta ⇄ hub

**Entrada** que a ferramenta recebe ao ser spawnada:

- **stdin**, uma linha:
  `{"target":"acme.com","params":{"max":3000},"job_id":"a1b2…"}`
- **env** (pra quem não quer parsear JSON): `RECONHUB_TARGET`,
  `RECONHUB_JOB_ID`, `RECONHUB_PARAM_MAX=3000`

**Saída** — NDJSON no stdout, uma linha = um evento:

| type       | pra quê                                                              |
|------------|--------------------------------------------------------------------|
| `log`      | mensagem (`level` info/warn/error)                                 |
| `progress` | barra (`data.pct`)                                                 |
| `finding`  | **vulnerabilidade** — `severity`, `finding_type`, `title`, `asset`, `evidence`, `meta` |
| `asset`    | **descoberta** — `kind` (subdomain/url/port/…), `value`            |
| `done` / `error` | fim                                                          |

`finding` = achou algo reportável. `asset` = achou um alvo novo (subdomínio,
URL, porta). Ferramentas de recon cospem `asset`; scanners cospem `finding`;
várias fazem os dois.

### O fluxo de um job

1. `POST /api/jobs {tool, target, program, params}` → engine enfileira.
2. Engine respeita `max_concurrent` (default 4), chama o `runner`.
3. Runner faz `exec` do processo com working-dir em `tools/<nome>/`, injeta
   stdin + env.
4. Cada linha NDJSON → o engine:
   - `finding` → `store.AddFinding` (com **dedup**, ver abaixo)
   - `asset` → `store.AddAsset` (dedup por `job|kind|value`)
   - tudo → `bus` → quem estiver ouvindo `GET /api/jobs/{id}/events` (SSE) vê ao vivo
5. Processo sai com código 0 = sucesso.

### Dedup (é o que torna re-rodar seguro)

Finding é deduplicado por **`(program, tool, finding_type, asset, title)`**.
Re-rodar o mesmo recon, ou uma pipeline que passa 2× pelo mesmo host, **não cria
linha nova** — sobe `count` e `last_seen`. Recon de um programa é idempotente. É
também o que o `monitor` usa pra detectar "finding novo".

---

## 3. O que fica guardado (modelo de dados)

| entidade         | é                                        | onde                                    |
|------------------|------------------------------------------|-----------------------------------------|
| **job**          | uma execução de 1 ferramenta             | `store`                                 |
| **event**        | linha NDJSON de um job (log/progress/…)  | `store`                                 |
| **finding**      | vuln normalizada, deduplicada, com `count` e `triage` (feedback do operador) | `store` |
| **asset**        | descoberta (subdomínio, porta, URL…)     | `store`                                 |
| **pipeline run** | execução de uma pipeline + estado de cada step | `store`                            |
| **program**      | escopo de um alvo (`in_scope`/`out_of_scope` wildcard) | `programs/<nome>.json`     |
| **projeto**      | pasta por programa: notas + snapshot (report/summary/assets) | `data/projects/<nome>/` (auto-sincronizada) |
| **watch**        | pipeline agendada + webhook de alerta    | `watches/<nome>.json` (mutável)         |

`store` = **JSON-lines em `./data/`** por padrão (zero deps), ou **SQLite** se
você compilar com `-tags sqlite`. Mesma interface, os dois.

---

## 4. O que temos hoje

### 38 ferramentas, por grupo

**recon — achar superfície**

| ferramenta          | o que faz                                                              |
|---------------------|----------------------------------------------------------------------|
| `recon-passive-enum` | subdomínios de **7 fontes** grátis em paralelo (CT, DNS datasets…) + resolve |
| `recon-crtsh`        | subdomínios via Certificate Transparency (crt.sh + certspotter, com merge) |
| `recon-subdomain-brute` | subdomínio ATIVO — wordlist + resolução DNS de verdade, detecta e filtra wildcard sozinho |
| `recon-web-enum`     | crawl same-site raso, fingerprint de stack (Server/X-Powered-By/cookies) |
| `recon-infra-enum`   | port scan TCP + banner + fingerprint + identifica provedor cloud/CDN via PTR. Aceita host/IP/CIDR, presets `top100`/… |
| `recon-tech-cve`     | fingerprint passivo de stack × tabela curada de CVEs — sinaliza "versão velha", nunca confirma exploração |

**scan — testar vulnerabilidade**

| ferramenta                | o que faz                                                        |
|---------------------------|---------------------------------------------------------------|
| `scan-subdomain-takeover` | CNAME dangling, ~58 fingerprints, confirmação HTTP             |
| `scan-fuzz`               | content discovery por wordlist, calibra soft-404; `recursive_depth` opt-in refuza dentro de diretório achado |
| `scan-actuator`           | Spring Boot Actuator exposto (`/env`, `/heapdump`, Jolokia…)   |
| `scan-open-redirect`      | 22 payloads de bypass em params comuns, confirma pelo destino real |
| `scan-cors`               | reflexão de origem, `null`, wildcard + credentials             |
| `scan-graphql`            | acha o endpoint, testa introspection, sinaliza mutations perigosas |
| `scan-cache-poisoning`    | headers não-chaveados (X-Forwarded-Host…), confirma com 2ª req limpa |
| `scan-broken-link-hijack` | links externos registráveis (GitHub/npm/S3/20 provedores de PaaS/social) |
| `scan-dep-confusion`      | npm/PyPI/Cargo/Composer — lê manifesto ou extrai imports, checa registro público |
| `scan-cognito`            | acha IDs de AWS Cognito, testa se o Identity Pool dá credencial AWS a anônimo |
| `scan-mongodb`            | MongoDB sem auth — fala OP_MSG direto, lista bancos/coleções (só nomes) |
| `scan-postman-net`        | busca na rede **pública** do Postman por um termo, varre collections por segredo |
| `scan-postman-audit`      | auditoria profunda de uma collection que **você aponta** (segredo, PII c/ Luhn, auth hardcoded) |
| `scan-idor`               | IDOR horizontal com DUAS sessões de teste — compara a resposta cruzada contra o baseline legítimo do dono, só status+tamanho (nunca guarda o corpo) |
| `scan-bruteforce-check`   | confirma ausência de rate limiting/lockout num login/OTP — tentativas erradas travadas (teto 10), para no 1º sinal de proteção |
| `scan-auth-flow`          | SSO/OAuth: descobre o `authorization_endpoint`, testa bypass de `redirect_uri` (confirma pelo destino real), inventaria metadata SAML |
| `scan-xss`                | XSS refletido — marcador único em params clássicos, confirma só quando volta sem escapar (nunca dispara execução) |
| `scan-xss-dom`            | XSS DOM-based — navegador headless real (CDP), vetor hash + query, confirma por EXECUÇÃO (não por texto na resposta); não é XSS armazenado |
| `scan-sqli`               | SQL injection por vazamento de erro real de banco, ausente no baseline sem payload — nunca time-based/booleana |
| `scan-ssti`               | Server-Side Template Injection — resultado calculado aparece e o payload cru NÃO, prova avaliação real (7 sintaxes de engine) |
| `scan-ssrf`               | injeta URLs internas/metadata cloud em params buscados pelo servidor, só confirma pelo CONTEÚDO da resposta |
| `scan-smuggling`          | request smuggling (CL.TE/TE.CL) por timing oracle — nunca encadeia 2ª requisição real pra confirmar |

**js — JavaScript, cloud, segredos** (todas baixam página + `<script src>` + source maps)

| ferramenta          | o que faz                                                              |
|---------------------|--------------------------------------------------------------------|
| `js-secret-hunter`  | ~35 padrões de credencial (AWS/GCP/GitHub/Slack/Stripe/…)          |
| `js-ai-key-hunter`  | chaves de IA (OpenAI sk-proj, Anthropic sk-ant, …), validação read-only |
| `js-bucket-scanner` | referências a cloud storage em 11 provedores                        |
| `js-hunter`         | endpoints/rotas escondidas em JS + reconstrói código de source maps |
| `js-jwt-finder`     | JWTs no HTML/JS, decodifica header + payload, sinaliza `alg:none`/sem-exp/claims sensíveis |
| `js-firebase-enum`  | `firebaseConfig` → testa Realtime DB / Firestore aberto sem auth   |
| `js-supabase-probe` | URL + anon key do Supabase → testa PostgREST (lista tabelas, só leitura) |
| `js-gtm-osint`      | IDs de tracking (GTM/GA4/Ads) + segredos em containers GTM         |

**int — integrações**

| ferramenta         | o que faz                                                              |
|--------------------|--------------------------------------------------------------------|
| `int-github-audit` | superfície pública de uma conta/org: repos, arquivos sensíveis (`.env`/`*.pem`), 17 padrões de segredo, workflows do Actions (pwn-request, injeção), gists |

> `example-echo` (Bash) é o stub de referência — emite eventos de exemplo pra
> testar o hub ponta-a-ponta.

### Subsistemas prontos

- **31 pipelines** — encadeiam ferramentas, passando `asset` de um step como
  `param` do próximo.
- **Pipeline DAG / fan-out** — steps ganham `id`, `feed.from`, `needs`; steps sem
  dependência pendente rodam **em paralelo** (ondas). Step falho marca dependentes
  `skipped`, ramos independentes seguem.
- **Monitor (watches)** — pipeline agendada; ao terminar, compara findings com a
  run anterior do mesmo watch; se tem novo + webhook setado, `POST` estilo Discord.
- **Relatório de bounty** — `/api/report.md` e `.html`: cada finding vira seção
  com título, severidade, asset, **passos de repro** (`curl` gerados do `meta`),
  impacto, correção, refs — de uma base de ~40 templates, com fallback honesto
  ("revisar antes de submeter") pros tipos sem template.
- **Programas / escopo** — `programs/<nome>.json` com wildcard; tag `program` em
  job/finding/asset; filtro de escopo no feed das pipelines.
- **Projeto por alvo** — cada programa ganha uma pasta em `data/projects/<nome>/`
  (notas + snapshot sincronizado sozinho a cada job). Ver seção 6.1.
- **Priorização de findings (intel)** — cada finding recebe pontuação 0-100 +
  ação ("reportar agora"…), combinando conhecimento de segurança embutido com
  o que você mesmo confirma/descarta (`POST /api/findings/{id}/triage`) — o
  hub aprende com o seu feedback, sem depender de nenhum modelo treinado. Ver
  seção 6.2.
- **Wordlists** — embutidas + um checkout do SecLists (`seclists_dir` no config),
  selecionáveis no param `wordlist`.
- **Auth** — bearer token único, hub nasce fechado, gera no 1º start.
- **Proxy/Tor** — campo Proxy por programa (Cookie/Bearer/Headers/Proxy na
  mesma aba); o sidecar de Tor sobe sempre junto do `docker compose`, mas
  só roteia tráfego se o operador configurar explicitamente pra aquele
  programa (opt-in — alguns programas proíbem IP anonimizado). 34 das 38
  ferramentas rotacionam de circuito sozinhas ao detectar bloqueio
  (429/403 repetido). Ver README > Docker > Proxy/Tor.
- **Chrome headless** — sidecar próprio (`docker/chrome/`), também sempre
  no ar, mas SEM opt-in: `scan-xss-dom` usa automaticamente via
  `RECONHUB_CHROME_URL`, sem configuração por programa (é infra
  compartilhada, não segredo por programa). Não suporta proxy/Tor por job
  nesse modo. Ver README > Docker > Chrome headless.
- **MCP** — `cmd/reconhub-mcp`, 22 tools, deixa o Claude dirigir o hub.
- **SQLite opcional** — `-tags sqlite`, `-store sqlite`, `-migrate-store`.
- **Docker + CI** — imagem única, CI com matriz Go + shellcheck + docker smoke +
  job sqlite.

---

## 5. Como usar bem — fluxos concretos

### a) Subir e entrar

```bash
go run ./cmd/reconhub
```

Pega no log a linha `http://127.0.0.1:7878/#token=…` e abre inteira no navegador
(o token fica no fragmento, o dashboard adota e limpa a URL). Pra API/CLI:

```bash
export H="Authorization: Bearer $(cat data/token)"
curl -s -H "$H" localhost:7878/api/tools | python3 -m json.tool
```

### b) Rodar uma ferramenta só

Dashboard: aba **Job atual** → escolhe ferramenta → o form mostra os params (e o
`guide` — o que pôr no Alvo). Ou API:

```bash
curl -s -H "$H" -XPOST localhost:7878/api/jobs \
  -d '{"tool":"js-secret-hunter","target":"https://app.acme.com","program":"acme"}'
```

Acompanha ao vivo: aba do job no dashboard, ou `GET /api/jobs/{id}/events` (SSE).

### c) Criar o programa PRIMEIRO (é o jeito certo pra um alvo real)

Antes de disparar qualquer coisa, cria o escopo. Assim todo finding nasce com
`program:"acme"`, o dedup funciona certo, o filtro de escopo corta subdomínio
fora do alvo no meio da pipeline, e o relatório sai escopado.

Dashboard: **＋ novo projeto**. Ou `POST /api/programs`:

```bash
curl -s -H "$H" -XPOST localhost:7878/api/programs -d '{
  "name":"acme",
  "in_scope":["*.acme.com","acme.io"],
  "out_of_scope":["blog.acme.com","*.dev.acme.com"]
}'
```

### d) Pipelines — o motor de verdade

Rodar:

```bash
curl -s -H "$H" -XPOST localhost:7878/api/pipeline-runs \
  -d '{"pipeline":"full-recon","target":"acme.com","program":"acme"}'
```

As que valem conhecer:

| pipeline             | o que faz                                                                                  | quando                              |
|----------------------|-------------------------------------------------------------------------------------------|-------------------------------------|
| **`full-recon`**     | 3 ondas: enum passiva → **~18 scans em paralelo** sobre os subdomínios → port scan → MongoDB nas portas 27017/8 | primeiro contato com um programa novo |
| **`passive-takeover`** | enum passiva (7 fontes) → subdomain takeover                                            | rápido, alto valor, bom pra watch   |
| **`js-suite`**       | crt.sh → 8 ferramentas js-* + `scan-cors` em paralelo nos mesmos hosts                    | alvo é SPA / muito JavaScript       |
| **`web-enum-sweep`**, `infra-sweep`, `cors-sweep`, `graphql-sweep`, `redirect-hunt`, `secret-sweep`… | um vetor específico, mais fundo                        | quando você já sabe o que quer olhar |

O `feed` é o encadeamento:
`{"param":"urls","from":"recon","kind":"subdomain","as":"lines"}` = "pega os
assets `subdomain` do step `recon` e entrega no param `urls` deste step, um por
linha". `full-recon` mostra fan-out real — 18 steps com `from:"recon"` rodam
juntos.

### e) Findings → relatório

Depois de rodar:

```bash
curl -s -H "$H" "localhost:7878/api/findings?program=acme&severity=high"
# relatório pronto pra colar no HackerOne/Intigriti:
curl -s -H "$H" "localhost:7878/api/report.md?program=acme" -o acme-report.md
# versão HTML imprimível em PDF:
curl -s "localhost:7878/api/report.html?program=acme&access_token=$(cat data/token)"
```

No dashboard: aba **Findings** → **⬇ relatório .md** / **↗ relatório .html**.
Filtros na query: `program`, `target`, `tool`, `type`, `severity`,
`include_info=1`.

### f) Monitoramento contínuo (watches)

Um watch = pipeline + agenda + alerta de finding novo:

```bash
curl -s -H "$H" -XPOST localhost:7878/api/watches -d '{
  "name":"acme-nightly", "pipeline":"passive-takeover",
  "target":"acme.com", "program":"acme", "every":"24h",
  "webhook":"https://discord.com/api/webhooks/…", "enabled":true
}'
```

Scheduler acorda a cada 30s; quando o watch está "due" roda a pipeline; se
aparecer finding que não existia na run anterior **daquele watch** e tiver
webhook, dispara um `POST` (formato nativo do Discord). Bom pra takeover,
dep-confusion, secrets — coisas que mudam sozinhas.

### g) Com o Claude (MCP)

`.mcp.json` já está no repo. Sobe o hub, e o Claude Code pega as 22 tools
(`hub_run_job`, `hub_run_pipeline`, `hub_list_findings`, `hub_triage_finding`,
`hub_draft_finding`, `hub_program_report`, `hub_create_program`…). Aí você
conversa: "roda `full-recon` no acme.com no programa acme e me resume os
findings high". O MCP lê `data/token` sozinho (ou `RECONHUB_URL` /
`RECONHUB_TOKEN`).

### g.1) O agent `bugbounty` — passo a passo

É um subagente do Claude Code (`.claude/agents/bugbounty.md`), não uma
ferramenta do hub — só existe dentro de uma sessão do Claude Code neste
repo, e só age através das 22 tools MCP acima (sem Bash, sem internet
solta — o `tools:` do frontmatter do agente nem lista essas duas). Isso
importa: **todo job/pipeline que ele dispara passa pelo mesmo
enforcement de escopo do servidor** que qualquer outro caminho (UI,
API, CLI) — testado na prática: pedir um alvo fora do
`in_scope`/`out_of_scope` do programa devolve erro do próprio servidor,
não é o agent "se comportando bem", é o hub recusando de verdade.

> **⚠️ Isso só vale garantido se for de fato O AGENTE quem está agindo —
> não a sessão raiz do Claude Code.** A sessão raiz TEM Bash/WebFetch
> normalmente, e nada garante que ela delega automaticamente pro
> subagente só porque seu pedido "parece" bug bounty — principalmente
> em mensagens de continuação soltas ("cava mais fundo nesse finding")
> no meio de uma conversa já em andamento, ou com `auto mode` ligado
> (aprova tool calls sem perguntar — isso NÃO tem relação com decidir
> delegar pro subagente, só facilita a sessão raiz agir sozinha sem
> você perceber). Já aconteceu na prática: a sessão raiz baixou um
> arquivo JS inteiro com `curl` direto pra investigar um segredo
> exposto, contornando toda a redação/enforcement que o hub existe pra
> garantir. Pra evitar isso:
> - Use **`@bugbounty`** explícito no pedido (`@bugbounty cava mais
>   fundo nesse finding`) — garante que É aquele subagente quem trata,
>   não a sessão raiz decidindo sozinha. Repita `@bugbounty` em CADA
>   mensagem de investigação, inclusive follow-ups — não há garantia
>   documentada de que o contexto "continua" dentro do subagente entre
>   turnos sem isso.
> - Pra uma sessão inteira dedicada a testar um programa de verdade,
>   `claude --agent bugbounty` no terminal já sobe a sessão inteira
>   como o agente, do primeiro ao último turno.
> - Não existe hoje um indicador visual confirmado no terminal pra
>   diferenciar "isso rodou no subagente" de "isso rodou na sessão
>   raiz" — na dúvida, prefira sempre `@bugbounty` explícito a confiar
>   na delegação automática.
> - Se quiser bloqueio de verdade (não só convenção), a sessão raiz
>   pode ter Bash desabilitado via `permissions.deny` num
>   `settings.json` — mas isso é uma escolha pra uma sessão dedicada a
>   engajamento, não pro repo inteiro (o próprio desenvolvimento do hub
>   usa Bash o tempo todo pra `gofmt`/`go build`/`go test`).

**Passo 1 — pré-requisito.** Suba o hub (seção "a"). Um programa com
`in_scope` preenchido (seção "c") — sem isso, nada é autorizado. Você
pode criar antes pela UI, ou deixar o agent criar sozinho ("cria o
programa acme com in_scope *.acme.com") — ele usa `hub_create_program`,
mas só com o `in_scope` que você deu, nunca inventando domínio. Se
você sempre exclui os mesmos hosts de ruído (`status.*`, ambientes
internos…), salve um template uma vez com `hub_create_scope_template`
e reaproveite em todo programa novo (`template: "nome"` no
`hub_create_program`) — só mexe em `out_of_scope`/`platform`, nunca em
`in_scope`.

**Passo 2 — chame o agent.** Três jeitos de pedir, cada um muda o
comportamento:

| Você diz (exemplos) | O que ele faz |
|---|---|
| "o que eu faço agora no programa acme?" | **Consultivo.** Olha `hub_list_jobs`/`hub_list_findings`/`hub_list_assets`, recomenda o próximo passo com o porquê. Não roda nada. |
| "roda `xss-sweep` no acme.com, programa acme" | **Ação direta.** Confirma escopo, dispara, avisa o que rodou. Uma coisa por vez, você no controle. |
| "explora o programa acme sozinho, budget de 15 jobs" | **Autônomo.** Encadeia rodadas sem pedir aprovação a cada passo — ver passo 3. |

**Passo 3 — modo autônomo, o que esperar.** Se você não disser um
budget (nº de jobs ou tempo máximo), ele pergunta antes de começar —
não tem "sem limite" de verdade, sempre existe um teto que você definiu.
A partir daí, cada rodada é: olha o que já rodou (nunca repete
ferramenta+alvo já testado) → escolhe UMA ação pela metodologia (recon
passivo → ativo → API/JS → vulnerabilidades → storage/cloud) → dispara
→ espera terminar → avalia → registra uma linha em
`data/projects/<programa>/notes.md` → repete.

**Ele para sozinho** (não só pausa) quando: o budget acaba, acha um
finding com severidade alta e prova real (`score` alto, `meta.confirmed`
verdadeiro — não um 401/403 cru), 2-3 rodadas seguidas sem achar nada
novo, ou uma pergunta de escopo que ele não consegue responder sozinho.
Um achado crítico interrompe o loop **na hora**, não só no relatório
final — é a única trava que sobrevive mesmo com budget alto sobrando.

**Passo 4 — acompanhe.** Três lugares, sem precisar ficar olhando a
conversa:
- `data/projects/<programa>/notes.md` — o diário que ele escreve rodada
  a rodada (alvo, ferramenta, resultado, por que parou onde parou).
- Aba **Findings** do hub — cada achado já vem com `score`/`action`
  calculados (`internal/intel`) e um conselho específico no hover da
  prioridade.
- Aba **Mapa** — pra ver visualmente quais fases da metodologia já têm
  cobertura nesse programa.

**Passo 5 — depois que ele para.** Se parou por achado crítico, decida:
reportar agora (peça o rascunho — "monta o relatório desse finding") ou
mandar continuar ("segue explorando o resto, mesmo budget"). Se parou
por budget, decida se abre mais budget ou encerra a sessão ali.

Exemplo real, ponta a ponta (validado contra um alvo de teste local
antes de virar documentação): pedir pra rodar `scan-xss` num endpoint
vulnerável retornou um finding `high`, `score: 100`,
`action: "reportar agora"` — o agent para o loop exatamente nesse ponto
e devolve pra você decidir, em vez de seguir rodando mais 10 ferramentas
por cima de um achado que já merece atenção.

### h) SQLite — quando trocar

Fica no FileStore enquanto `data/*.jsonl` estiver confortável. Troca quando
quiser query / volume:

```bash
make build-sqlite
./reconhub-sqlite -migrate-store        # importa o ./data/ atual, uma vez
./reconhub-sqlite -store sqlite          # daí em diante
```

Detalhes em [`README.md` → Backend de armazenamento](../README.md#backend-de-armazenamento).

---

## 6. Fluxo recomendado num programa novo

1. **`POST /api/programs`** — cria `acme` com in/out of scope. (sempre primeiro)
2. **`full-recon`** com `program:"acme"` — deixa rodar (é longo; são 3 ondas e
   ~18 scans paralelos).
3. Aba **Findings** filtrando por `severity=high,critical` — triagem.
4. Pros que parecem reais: re-roda a ferramenta específica sozinha naquele host
   pra confirmar (idempotente, só sobe `count`).
5. **`/api/report.md?program=acme`** — gera o rascunho, revisa os passos de
   repro, ajusta, submete.
6. **Cria um watch** `passive-takeover` ou `secret-sweep` diário no programa com
   webhook — pega regressão / superfície nova sem você olhar.
7. `GET /api/programs/acme/export` — bundle JSON com tudo (jobs + runs + findings
   + assets) pro seu arquivo.
8. A pasta `data/projects/acme/` já foi ficando pronta sozinha durante todo esse
   fluxo — abra `report.md` direto do disco, ou escreva em `notes.md` pela aba
   **Projetos** do dashboard (`GET/PUT /api/programs/acme/notes`).

---

## 6.1. Projeto = pasta por alvo

Cada programa que você cria no passo 1 acima já ganha, automaticamente, uma
pasta em `data/projects/<nome>/`. O escopo em si **não é duplicado** aqui —
continua vivendo só em `programs/<nome>.json`, que é a fonte da verdade. O que
tem na pasta é o que só existe ali:

- `summary.json` — contagens (jobs por status, findings por severidade, assets
  por tipo, última atividade) — sempre fresco: toda leitura resincroniza
- `report.md` — o mesmo relatório de bounty, já escopado pra esse programa
- `assets.json` — snapshot de tudo que foi descoberto
- `notes.md` — **o único arquivo que é seu** — o hub nunca sobrescreve

A sincronização é automática: toda vez que um job (ou step de pipeline) daquele
programa termina, a pasta é regravada sozinha (`internal/project`, ligado no
engine via `OnJobDone`). Não precisa rodar nada manualmente — mas o botão
**↻ sincronizar** na aba **Projetos** força na hora, e é o mesmo endpoint que o
hub chama:

```bash
curl -s -H "$H" -XPOST localhost:7878/api/programs/acme/sync
curl -s -H "$H" localhost:7878/api/programs/acme/summary | jq
curl -s -H "$H" -XPUT localhost:7878/api/programs/acme/notes \
  -d '{"notes":"alvo principal: acme.com\ncontato: security@acme.com"}'
```

Se você faz bug bounty em vários alvos ao mesmo tempo, é essa pasta que separa
tudo fisicamente — cada programa com seu relatório, seus assets e suas notas,
sem precisar montar filtro nenhum manualmente.

---

## 6.2. Priorização — "o que fazer com cada achado"

Recon gera muito achado; nem todo achado merece a mesma atenção. `internal/intel`
calcula, pra cada finding, uma pontuação (0-100) e uma ação — sem precisar de
modelo treinado nem GPU, só o núcleo Go de sempre:

1. **Conhecimento embutido** — uma tabela em `internal/intel/intel.go` com o
   mesmo julgamento que um revisor experiente aplicaria de cara: um MongoDB
   sem auth ou uma chave de IA validada já entram com prioridade alta; um
   open redirect isolado ou um CORS wildcard sem credentials já entram
   baixos. Funciona **desde o primeiro finding**, sem nenhuma triagem sua.
2. **Seu histórico** — toda vez que você marca um finding como confirmado ou
   falso positivo, isso entra numa contagem por `(ferramenta, tipo)`. Quanto
   mais você triagem de um tipo, mais o *seu* ambiente pesa sobre o prior
   genérico — pra cima (se você confirma muito) ou pra baixo (se costuma
   descartar). É aprendizado de verdade, só que estatístico e transparente,
   não uma caixa-preta.

```bash
# achados ordenados por urgência, com a ação sugerida
curl -s -H "$H" "localhost:7878/api/intel/findings?program=acme" | jq '.findings[] | {title,score,action,why}'

# alimenta o aprendizado
curl -s -H "$H" -XPOST localhost:7878/api/findings/<id>/triage -d '{"verdict":"confirmed"}'
```

No dashboard: a aba **Findings** já mostra a coluna **prioridade** (pontuação
+ ação; passe o mouse pra ver o porquê) e os botões **✓ / ✗** pra você
confirmar ou marcar falso positivo direto ali — é isso que alimenta o
aprendizado pra próxima vez.

---

## 7. Rotas da API (referência rápida)

| método | rota                                   | o quê                                  |
|--------|----------------------------------------|----------------------------------------|
| GET    | `/api/health`                          | aberto, sem token                      |
| GET    | `/api/tools` · `/api/tools/{name}` · `/api/tools/{name}/readme` | catálogo    |
| POST   | `/api/jobs`                            | dispara 1 ferramenta                   |
| GET    | `/api/jobs` · `/api/jobs/{id}`         | lista / detalhe                        |
| POST   | `/api/jobs/{id}/cancel`                | cancela                                |
| GET    | `/api/jobs/{id}/events`                | SSE ao vivo                            |
| GET    | `/api/findings` · `/api/assets`        | com filtros `?program=…&severity=…`    |
| GET    | `/api/intel/findings`                  | findings + pontuação/ação, por urgência |
| POST   | `/api/findings/{id}/triage`            | confirmed/false_positive/ignored        |
| GET    | `/api/report` · `/api/report.md` · `/api/report.html` | relatório de bounty     |
| GET    | `/api/programs/{name}/report.md` · `.html` | idem, escopado                     |
| GET/POST | `/api/programs` · `/api/programs/{name}` | escopo                            |
| GET    | `/api/programs/{name}/export`          | bundle JSON completo                   |
| GET    | `/api/programs/{name}/summary`         | resumo do projeto (resincroniza)       |
| POST   | `/api/programs/{name}/sync`            | força a resincronização da pasta       |
| GET/PUT | `/api/programs/{name}/notes`          | notas do projeto (`{"notes":"..."}`)   |
| GET/POST | `/api/pipelines` · `/api/pipeline-runs` · `/api/pipeline-runs/{id}[/cancel|/events]` | pipelines |
| GET/POST | `/api/watches` · `/api/watches/{name}[/run]` | monitoramento                 |
| GET    | `/api/wordlists`                       | wordlists indexadas                    |
| GET    | `/api/docs`                            | o README renderizado no dashboard      |

Auth: header `Authorization: Bearer <token>` em tudo (menos `/api/health`). As
rotas baixáveis por link (`report.md`, `report.html`, `export`) também aceitam
`?access_token=<token>`.
