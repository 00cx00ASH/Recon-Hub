# recon-hub — notas pra quem (humano ou IA) mexer neste repo

Este arquivo é o "segundo cérebro" do projeto: convenções que não mudam e
lições já aprendidas na marra, pra não serem redescobertas do zero a cada
sessão. O Claude Code carrega isto automaticamente no início de qualquer
sessão neste repositório — é por isso que fica aqui e não num Notion/Obsidian
separado: zero fricção, sempre atualizado junto do código, revisado em PR
como qualquer outra mudança.

**Regra de manutenção:** quando alguma coisa não óbvia quebrar e for
corrigida (bug sutil, gotcha de CI, decisão de design que não é óbvia só
lendo o código), some uma entrada em "Lições aprendidas" abaixo, na mesma
PR do fix. Não deixe pra depois — a lição só vale enquanto está fresca.

## Filosofia do projeto

- **Zero dependência externa no core** (`internal/`, `cmd/`) — só stdlib do
  Go. Cada `tools/<nome>/` é um módulo Go independente (`go.mod` próprio);
  dependência externa só entra ali, e só quando genuinamente necessário
  (ex: `github.com/miekg/dns` no scan-subdomain-takeover). Não adicione
  dependência ao core pra economizar 10 linhas.
- **Toda ferramenta de scan é PoC-only.** Confirma o achado pela resposta
  real (destino de redirect, corpo que prova SSRF, chave de amostra nunca
  o valor, contagem de linha nunca o dado) e para aí — nunca extrai dado
  real, nunca escala privilégio de verdade, nunca é destrutivo, nunca faz
  DoS. Isso é o que mantém o hub dentro do que bug bounty autoriza. Uma
  ferramenta nova que não seguir isso não deveria existir aqui.
- **Escopo é enforced no servidor**, não só sugerido na UI: um job/pipeline
  com `program` setado é rejeitado se o alvo não bater no `in_scope` do
  programa (`internal/scope`). Nunca contorne isso "pra funcionar".
- **Contrato NDJSON é sagrado** — ver `docs/TOOL_CONTRACT.md`. Toda
  ferramenta nova segue o mesmo formato de evento, os mesmos nomes de env
  var, a mesma convenção de severidade/confirmed.
- **O hub ensina enquanto executa — não é só um runner de ferramenta.**
  Quem tá aprendendo bug bounty (ou só não decorou todo finding_type) devia
  entender O QUÊ aconteceu e POR QUE importa sem sair do hub pra pesquisar.
  Isso já é estrutural em vários lugares — mantenha o padrão em tudo que
  for novo:
  - `tool.json.guide` explica o que pôr no alvo e como interpretar; toda
    ferramenta nova precisa de um, não só as que "parecem confusas".
  - `tool.json.validation` mostra um exemplo real de confirmação — o que
    prova que o achado é de verdade, não só "o payload apareceu".
  - `internal/intel.knownRisk[type].Advice` é o "por que isso importa e o
    que fazer" que aparece no hover da prioridade em cada finding — toda
    `finding_type` nova ganha uma entrada aqui, com um conselho específico
    (não genérico tipo "investigue mais").
  - A aba Mapa e o agent `bugbounty.md` existem pra dar contexto de
    metodologia (por que essa fase vem antes daquela), não só listar
    ferramentas. Um recurso novo que adicione uma categoria de vuln
    precisa aparecer nos dois, com a mesma explicação do "por quê".
  - Regra prática: se colar a resposta de UMA finding/UM evento na cara de
    alguém que nunca usou o hub, essa pessoa devia entender o que aconteceu
    sem perguntar "e daí?". Se não, falta uma frase de contexto em algum
    desses lugares.

## Antes de commitar (sempre)

1. `gofmt -l .` na raiz do repo — **primeiro passo do CI**, roda antes de
   qualquer build/vet/test. Editar e esquecer de formatar já quebrou CI
   uma vez (ver lições abaixo). Rode isso ANTES de rodar build/vet/test,
   não depois.
2. `go build ./...` + `go vet ./...` no core, com e sem `-tags sqlite`.
3. `go test -race -count=1 ./...` no core, com e sem `-tags sqlite`.
4. Em cada módulo de ferramenta tocado: `cd tools/<nome> && gofmt -l . &&
   go build ./... && go vet ./... && go test ./...`
5. Mudança de UI (`web/index.html`): sobe um servidor de teste isolado
   (`-addr` numa porta livre, rodando de um diretório separado com
   symlinks pra `tools/`/`pipelines/`/`wordlists`/`web` — nunca contra o
   `data/` real do checkout) e valida com Playwright antes de dar como
   pronto. Testa também em viewport mobile (~390px) — overflow horizontal
   de página é um bug real e recorrente aqui (ver lições).

## Registro de progresso por programa (bug bounty)

"O que já testei, com qual técnica, o que deu" não vai aqui no
`CLAUDE.md` — isso é operacional, específico de cada programa, e já tem
lugar certo: a aba **Projetos → Notas** de cada programa
(`data/projects/<nome>/notes.md`). Convenção pra ficar útil de verdade
(pro agent `bugbounty` e pra você relendo depois):

```
## 2026-09-11 — recon-crtsh + scan-xss (xss-sweep)
Alvo: *.acme.com. 340 subdomínios achados, scan-xss rodou em 210 vivos.
Achado: XSS refletido em app.acme.com/busca?q= (high, tag HTML) — reportado.
Falso positivo descartado: staging.acme.com/contato?msg= (medium, mas o
atributo era só texto de placeholder, não executava nada — confirmei manual).
Próximo passo: full-recon ainda não rodou no domínio inteiro, só o fan-out
de XSS. Fazer isso na próxima sessão.
```

Um parágrafo curto por sessão de teste: alvo, ferramenta/pipeline usada,
o que confirmou, o que descartou e por quê, próximo passo. O
`bugbounty` agent lê `data/projects/<nome>/notes.md` direto (tem acesso
de leitura de arquivo) quando perguntado "o que já testamos aqui" — texto
sem estrutura nenhuma ele ainda entende, mas datado e com "próximo passo"
explícito poupa você de reler tudo pra saber onde parou.

Isso é diferente de `data/lessons.md` (API `GET/POST/PUT /api/lessons`,
MCP `hub_get_lessons`/`hub_add_lesson`): notes.md é por programa
("o que testei aqui"); lessons.md é cross-programa ("padrão que vale
em qualquer programa" — comportamento de WAF, peculiaridade de
plataforma, técnica que funcionou). E nenhum dos dois é a seção
"Lições aprendidas" abaixo, que é sobre desenvolver ESTE repo, não
sobre caçar bugs em programas de terceiros.

## Lições aprendidas

- **CI falha se `gofmt -l .` não estiver limpo, mesmo com build/vet/test
  passando localmente.** O job `go (.)` roda isso como primeiro passo,
  antes de qualquer compilação. Rode `gofmt -l .` explicitamente depois de
  editar Go — `go build` sozinho não garante formatação canônica.
- **Linha `display:flex` sem `flex-wrap:wrap` vaza a página inteira em
  mobile.** `overflow-x:hidden` no body é rede de segurança, mas o certo é
  toda linha de filtros/controles ter `flex-wrap:wrap` desde o início —
  já aconteceu de uma aba ter e outra não (Findings ficou sem, só Assets
  tinha) e ninguém notar até testar em viewport estreito de verdade.
- **`renderMarkdown()` (usado no README das ferramentas/docs) não
  escapava aspas na URL de um link nem checava o esquema** — `[x](javascript:...)`
  virava link clicável, e uma URL com `"` escapava do atributo `href`. Se
  algum dia isso renderizar algo com influência externa (README de
  ferramenta de terceiro), vira XSS de verdade — e o token de acesso vive
  em localStorage. Corrigido: só `http(s)` vira link, aspas escapadas.
  Qualquer lugar novo que gere HTML a partir de texto que não é 100%
  gerado pelo próprio hub merece a mesma pergunta.
- **Handshake de proxy (SOCKS5) sem `SetDeadline` trava a goroutine pra
  sempre** se o proxy aceitar a conexão TCP mas nunca responder — o
  timeout do `http.Client` não alcança essa fase porque o `DialContext`
  já tinha retornado antes. Qualquer I/O de rede feito fora do
  `http.Client` padrão (handshake manual, protocolo cru) precisa do
  próprio deadline.
- **Fan-out de pipeline só funciona pra ferramenta com param `urls`/
  `urls_file`** (ou equivalente que aceite lista). Ferramentas de alvo
  único por natureza (`scan-auth-flow` — descobre `/.well-known/...` de
  UM host; `int-github-audit`/`scan-postman-*` — alvo é conta/collection,
  não domínio) não ganham nada sendo encadeadas num `feed` de
  subdomínios — ficam de fora do `full-recon` de propósito, não por
  esquecimento.
- **Processo de teste em background (servidor local, Playwright) precisa
  rodar isolado do `data/` real do checkout** — subir o binário sem
  `cwd` dedicado escreve em `data/token`, `data/*.jsonl` de verdade.
  Sempre um diretório `/tmp` separado com symlinks pro resto.
- **Subagente com `isolation: "worktree"` parte do branch DEFAULT do repo
  (`main`), não do branch/commit que a sessão principal tem checked out**
  — mesmo com trabalho commitado na sessão atual num branch de feature,
  um subagente em worktree não vê nada disso a menos que esteja também
  em `main`. Isso já causou 3 subagentes em paralelo "não acharem" um
  arquivo de referência que tinha acabado de ser commitado (porque o
  commit foi num branch de feature, e o worktree deles partiu de `main`
  bem mais atrás) — e um deles corrigiu sozinho fazendo `git show
  <branch-da-sessão>:<caminho>` pra ler o conteúdo certo sem tocar no
  branch errado, o que é o jeito certo de lidar com isso quando
  acontece. Pra tarefas que dependem de algo commitado AGORA na sessão
  atual (não em `main`), ou não use `isolation: "worktree"` (deixa o
  subagente operar direto no working dir atual, já no branch certo), ou
  informe explicitamente o branch/commit de origem no prompt.
- **O subagente `bugbounty` só age sem Bash/internet solta se ELE de
  fato tratar o pedido — a sessão raiz do Claude Code tem Bash e pode
  decidir agir sozinha em vez de delegar**, principalmente em mensagens
  de continuação soltas ("cava mais fundo nesse finding") numa conversa
  já em andamento. Não existe garantia documentada de que o contexto
  "continua" dentro do subagente entre turnos, nem indicador visual no
  terminal pra diferenciar quem agiu. Isso já aconteceu na prática: a
  sessão raiz baixou com `curl` direto o arquivo inteiro onde um
  `js-secret-hunter` tinha achado uma chave privada (o scanner do hub
  redige o valor por design; baixar o arquivo cru contorna isso por
  completo). Sempre use `@bugbounty` explícito (repetido em cada
  mensagem de investigação) ou `claude --agent bugbounty` pra garantir
  que é o agente restrito quem age — ver aviso em
  `docs/GUIA-DE-USO.md` seção g.1.
- **`createJob` só checava `req.Target` contra o escopo — `req.Params`
  nunca era olhado, e é exatamente ali que os alvos DE VERDADE viajam em
  todo tool com modo "lista colada"/"arquivo"** (`urls`/`urls_file`,
  `hosts`/`hosts_file`, `subdomains`/`subdomains_file`, mais alvos extra
  de endpoint único como `url_b` do scan-idor, `authorize_url` do
  scan-auth-flow, `supabase_url` do js-supabase-probe — 24+ ferramentas
  no total). Um job com `target=a.programa-em-escopo.com` (que passava
  na checagem) e `params.urls` cheio de hosts de fora do programa
  escaneava tudo sem nenhum bloqueio — "escopo enforced no servidor"
  citado na filosofia deste arquivo era decorativo pra qualquer tool com
  lista. Corrigido em `internal/api/api.go` (`paramsOutOfScope`): além do
  Target, agora valida cada item desses params (inline e lendo o
  `_file` do disco) contra `prog.Contains()`, rejeitando o job inteiro
  com 403 se QUALQUER host estiver fora. Teste de regressão:
  `TestCreateJobRejectsOutOfScopeInParams` em `internal/api/api_test.go`.
  Qualquer parâmetro novo que carregue host/URL adicional (não só o
  `target` principal) precisa entrar num desses três mapas
  (`scopeListParams`/`scopeFileParams`/`scopeSingleParams`) — senão vira
  o mesmo buraco de novo.
