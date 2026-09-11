# agent-runner — exploração autônoma standalone (Claude Agent SDK)

Processo Python separado do Claude Code CLI — pensado pra rodar sem
sessão interativa aberta (cron, systemd timer, `docker run` avulso),
encadeando rodadas do "Modo exploração autônoma" de
`.claude/agents/bugbounty.md` sozinho, até bater um limite de
rodadas/tempo/custo que você configura.

**Isto não substitui `@bugbounty`/`claude --agent bugbounty`** — aquilo
continua sendo o jeito certo de trabalhar interativamente, com você lendo
cada resposta. Use este runner só quando quiser algo rodando sem você
precisar estar na frente, com os limites que só fazem sentido nesse
cenário (orçamento em USD, tempo máximo de execução).

## Por que existe como diretório isolado

O core deste repo (`internal/`, `cmd/`, `tools/<nome>/`) é Go puro, zero
dependência externa fora de casos pontuais em `tools/`. O Claude Agent SDK
só tem pacote oficial em Python/TypeScript — não faz sentido forçar isso
pro Go, então este diretório é um mundo à parte, com seu próprio
`requirements.txt`, que nunca é importado por nada em `internal/`/`tools/`.

## Setup

```bash
cd agent-runner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edite .env: pelo menos AGENT_PROGRAM
```

O hub (`go run ./cmd/reconhub-mcp` via MCP, chamado internamente pelo
script) precisa do recon-hub já rodando (`RECONHUB_URL`, default
`http://127.0.0.1:7878`) e de um token — por padrão lê `../data/token`
igual o MCP server do Claude Code já faz.

## Rodando

```bash
cd agent-runner
source .venv/bin/activate
python3 run.py
```

Roda a partir do checkout do repo (o script resolve `REPO_ROOT` como um
nível acima de si mesmo e usa isso como `cwd` da sessão — não precisa
`cd` pra raiz do repo antes, só ter o checkout intacto). Loga em
`agent-runner/logs/<programa>-<timestamp>.log` além do stdout.

## O que é diferente da persona interativa

- **Só tools `mcp__reconhub__hub_*`** — nem Bash, nem Read/Write/Edit,
  nem WebFetch/WebSearch. Lidas dinamicamente do frontmatter de
  `bugbounty.md` (`discover_allowed_tools()`), então se aquele arquivo
  ganhar uma MCP tool nova o runner acompanha sozinho. `tools=[]` desliga
  TODAS as tools embutidas do Claude Code de saída — `allowed_tools`
  então só reabre exatamente essa lista; `disallowed_tools` repete a
  mesma restrição como cinto-e-suspensório (redundante de propósito, no
  mesmo espírito de escopo checado em mais de uma camada no resto do
  hub).
- **Sem Read** → o passo "leia `data/projects/<nome>/notes.md`" do
  system prompt original não se aplica; o runner usa só
  `hub_list_jobs`/`hub_list_findings`/`hub_list_assets` como estado (o
  próprio bugbounty.md já diz que jobs "nunca mentem", notes.md pode
  estar desatualizado) e `hub_add_lesson` pra conhecimento reaproveitável.
- **Orçamento é enforced em código**, não só prometido no system prompt:
  `AGENT_MAX_ROUNDS`/`AGENT_MAX_RUNTIME_MIN`/`AGENT_MAX_COST_USD` no
  `.env` são checados pelo laço em Python antes de cada rodada. O SDK
  também recebe um `max_budget_usd` por rodada (o que sobrou do teto
  total) e `max_turns` por rodada, como uma segunda trava contra UMA
  rodada individual fugir do controle.
- **Sinal de "terminei sozinho"**: o addendum do system prompt (montado
  em `build_system_prompt()`) instrui o modelo a escrever a linha exata
  `RECONHUB_RUNNER_STOP` no fim da resposta quando decidir parar de vez
  (achado crítico aguardando você, 2-3 rodadas sem nada novo, pergunta de
  escopo que só você responde). O script para assim que vê essa linha, em
  vez de só confiar num campo do SDK.

## Trocar de modelo / pago vs. assinatura

- `AGENT_MODEL` no `.env` — troque livremente entre execuções
  (`claude-opus-5`, `claude-sonnet-5`, `claude-haiku-4-5-20251001`).
  `AGENT_FALLBACK_MODEL` é usado pela própria SDK se o modelo principal
  falhar/estiver sobrecarregado.
- **Pago vs. "de graça" não é uma opção do SDK** — é resolvido do mesmo
  jeito que a CLI do Claude Code já resolve hoje: se `ANTHROPIC_API_KEY`
  estiver setado no ambiente (`.env` ou exportado antes de rodar), a CLI
  usa API paga por token com essa chave; se não estiver, ela cai pro
  login/assinatura já configurado nesta máquina (o mesmo que você já usa
  rodando `claude` no terminal). O script só imprime no log qual dos dois
  modos detectou no início de cada execução — não tem lógica própria de
  billing.
- Trocar de modelo NO MEIO de uma sequência de rodadas já em andamento
  funciona: cada rodada usa `resume=<session_id da rodada anterior>`, e
  `model=` é lido de novo do `.env` a cada rodada — mude o `.env` e mande
  `SIGHUP`/reinicie o processo com o `.env` atualizado entre rodadas se
  quiser trocar no meio de uma sessão longa (o processo não recarrega
  `.env` sozinho enquanto roda).

## Limitação conhecida

`ResultMessage.total_cost_usd` (usado pro teto `AGENT_MAX_COST_USD`) pode
vir `None`/não confiável dependendo do modo de auth (assinatura vs. API
paga) — o script trata `None` como `0.0` pra não travar o loop, mas isso
significa que, no modo assinatura, o teto de custo pode não ser um
enforcement real (o teto de rodadas/tempo continua valendo sempre). Se
isso importa pro seu caso, prefira confiar em `AGENT_MAX_ROUNDS`/
`AGENT_MAX_RUNTIME_MIN` como os limites de verdade.
