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

- **`agent-runner/run.py` tratava QUALQUER `ClaudeSDKError` como fatal —
  inclusive bater o teto `AGENT_MAX_TURNS_PER_ROUND` no meio de uma
  rodada, que não é uma falha real, é só a rodada ficando sem fôlego.**
  Um programa com superfície razoável (vários `hub_run_job` +
  `hub_get_job` de polling na mesma rodada) esgota 40 turns fácil antes
  de terminar de narrar — e como o loop principal fazia `break`
  incondicional em qualquer `except ClaudeSDKError`, isso encerrava o
  runner inteiro mesmo com 19 de 20 rodadas ainda disponíveis e todo o
  trabalho (jobs/findings) já salvo no hub. Corrigido: o loop agora
  detecta especificamente a mensagem "maximum number of turns" e segue
  pra próxima rodada (sem `resume=`, já que a sessão morreu sem
  terminar limpo — a próxima relê `hub_list_jobs`/`hub_list_findings`
  do zero, do mesmo jeito que já faz por não ter `Read`); qualquer outro
  `ClaudeSDKError` continua fatal, de propósito. Também subimos o
  default de `AGENT_MAX_TURNS_PER_ROUND` de 40 pra 80 no
  `.env.example`, já que 40 se mostrou baixo demais num caso de uso
  real. Lição maior: um teto por-rodada estourado no meio do trabalho
  não é o mesmo tipo de erro que uma falha de auth/config/rede — tratar
  os dois com o mesmo `except` genérico joga fora trabalho útil.
- **CI falha se `gofmt -l .` não estiver limpo, mesmo com build/vet/test
  passando localmente.** O job `go (.)` roda isso como primeiro passo,
  antes de qualquer compilação. Rode `gofmt -l .` explicitamente depois de
  editar Go — `go build` sozinho não garante formatação canônica.
- **Linha `display:flex` sem `flex-wrap:wrap` vaza a página inteira em
  mobile.** `overflow-x:hidden` no body é rede de segurança, mas o certo é
  toda linha de filtros/controles ter `flex-wrap:wrap` desde o início —
  já aconteceu de uma aba ter e outra não (Findings ficou sem, só Assets
  tinha) e ninguém notar até testar em viewport estreito de verdade.
- **Item de CSS Grid sem `min-width:0` não encolhe abaixo do min-content
  de dentro dele — mesma família do bug acima, causa diferente.** `main`
  usa `display:grid` com `.panel`/`.content` como itens; o default de
  grid item é `min-width:auto`, que vira "o maior min-content de
  qualquer descendente" (ex: a option mais larga de um `<select>`, uma
  palavra sem ponto de quebra num `<code>`). Um form de parâmetro com
  nome técnico longo (`max_recursive_dirs`) bastou pra abrir 7px de
  overflow em mobile — e nenhum elemento individual "aparecia" como
  culpado numa busca por `scrollWidth > docW` elemento a elemento (só a
  `.panel` toda, cujo `right` batia o de nenhum filho — sinal de que é
  min-content do grid, não um elemento específico largo demais).
  Corrigido de vez com `main > .panel, main > .content{min-width:0}` —
  regra geral, não um patch pro form que expôs o bug dessa vez. Se
  aparecer overflow de novo sem um elemento óbvio e largo demais, suspeite
  de container flex/grid sem `min-width:0` antes de sair procurando o
  "elemento culpado" um por um.
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
- **Injeção de env var pro subprocesso de uma ferramenta tem DOIS
  mecanismos bem diferentes — usar o errado cria acoplamento que não
  devia existir.** `Engine.AuthLookup` (chamado só quando `job.Program !=
  ""`) é pra segredo/config POR PROGRAMA — cookie, bearer, proxy — porque
  cada programa pode ter uma sessão/circuito diferente. Mas
  `runner.Run()` já faz `env := os.Environ()` antes de somar o
  `extraEnv` do `AuthLookup`: qualquer env var setada no processo do
  HUB (não por programa — global) já propaga sozinha pra todo
  subprocesso de ferramenta, sem precisar de nenhum código novo no
  engine. Foi assim que `RECONHUB_CHROME_URL` (aponta pro sidecar de
  Chrome, infra compartilhada igual o Tor, mas SEM opt-in por programa)
  foi ligado: só setar a env var no serviço `reconhub` do
  `docker-compose.yml`, zero mudança em `internal/engine`/`cmd/reconhub`.
  Antes de tocar `AuthLookup`/`internal/project.Auth` pra uma env var
  nova, pergunte se ela é por-programa de verdade (então `AuthLookup` é
  o lugar certo) ou infra global (então é só env var no serviço do hub
  no compose, ponto).
- **Contagem de "N ferramentas"/"N pipelines" espalhada em prosa
  (README, GUIA-DE-USO, TOOL_CONTRACT, o texto da aba Mapa) já ficou
  dessincronizada da contagem real mais de uma vez, silenciosamente —
  ninguém recalcula na hora de adicionar 1 ferramenta nova, e nenhum
  teste/CI confere esses números contra `tools/*/tool.json` de verdade.**
  Achado ao adicionar `scan-xss-dom`: o texto dizia "34 ferramentas" em
  3 lugares diferentes com a contagem real já em 36 antes dessa
  ferramenta nova (drift de tarefas anteriores nunca propagado). Sempre
  que adicionar/remover uma ferramenta, recontar com `find tools -maxdepth
  2 -name tool.json | wc -l` (menos 1 pro `example-echo`, que não conta
  como ferramenta "prontas") e `grep -c '\*\*pronta\*\*' README.md`, e
  atualizar os 4 lugares junto: README (linha do catálogo + a tabela em
  si), `docs/GUIA-DE-USO.md` (título "N ferramentas, por grupo"), texto
  da aba Mapa em `web/index.html`, e a fração de adoção de proxy em
  README + `docs/GUIA-DE-USO.md` + `docs/TOOL_CONTRACT.md` (denominador =
  total; numerador = nº real de cópias de `proxy.go` = `find tools
  -maxdepth 2 -name proxy.go | wc -l`, que é exatamente total menos as
  que documentadamente não usam `http.Client`). E quando a prosa
  ENUMERA essas exceções (a README lista "as N que ficam de fora" uma a
  uma), essa lista também dessincroniza: ao adicionar `scan-privesc`
  a fração dizia "36 das 40" com 35 cópias reais de `proxy.go`, E a
  enumeração omitia `recon-subdomain-brute` (DNS puro via `miekg/dns`,
  nunca teve `http.Client`) — o número e a lista driftaram juntos, por
  motivos independentes. Confira os dois: numerador == `proxy.go` real,
  e a enumeração == o conjunto de tools SEM `proxy.go` (`for d in
  tools/*/; do [ -f "$d/proxy.go" ] || basename "$d"; done`).
- **O matrix de CI (`.github/workflows/ci.yml`, job `go`) é HARDCODED,
  tool por tool — adicionar `tools/<nova>/` não a coloca no CI, e o
  `docker build` (que faz `for d in tools/*/ … go build`) NÃO salva: ele
  só compila, não roda `gofmt -l`/`go vet`/`go test` por-tool.** Resultado:
  uma tool nova (ou uma antiga que ninguém registrou) fica com formatação,
  vet e testes SEM checagem no CI, passando "verde" por pura omissão — o
  gap não grita, some. Achado ao adicionar `scan-mass-assignment`: o matrix
  tinha 25 entradas de tool pra 40 tools reais; 14 tools (incluindo
  `scan-privesc`/`scan-path-traversal`/`scan-waf-fingerprint`, adicionadas
  em sessões anteriores) nunca foram registradas. Sempre que adicionar uma
  tool, some a linha `- "tools/<nome>"` no matrix, e confira o conjunto
  inteiro com `comm -23 <(for d in tools/*/; do n=$(basename "$d"); [ "$n"
  = example-echo ] || echo "tools/$n"; done | sort) <(grep -oE
  '"tools/[^"]+"' .github/workflows/ci.yml | tr -d '"' | sort)` — tem que
  vir vazio. Antes de registrar várias de uma vez, valide cada uma local
  (`gofmt -l . && go vet ./... && go build ./... && go test ./...`) pra não
  empurrar um CI vermelho por uma tool que o CI nunca tinha olhado.
  **Pegadinha junto:** o `setup-go` do CI estava fixado em `1.22`, ABAIXO
  da base do Docker (`golang:1.23-alpine`, `GOTOOLCHAIN=local`). Uma tool
  que legitimamente precisa de 1.23 (`scan-xss-dom` depende de `chromedp`,
  que exige 1.23; `scan-waf-fingerprint` também declarava 1.23) COMPILAVA no
  `docker build` mas, ao ser registrada no matrix, o job por-tool quebrava
  logo no `go vet` com `go.mod requires go >= 1.23 (running go 1.22;
  GOTOOLCHAIN=local)`. Baixar o `go` do go.mod da tool NÃO resolve quando é
  uma DEPENDÊNCIA que exige 1.23 (o toolchain 1.22 recusa a dependência de
  qualquer jeito) — o certo é alinhar o `go-version` do `setup-go` (os dois
  steps: job `go` e job `sqlite`) à base do Docker, nunca deixar o CI mais
  velho que a imagem que produção usa. Regra: `go-version` do CI == base do
  `Dockerfile`; a maior versão de `go` em qualquer `tools/*/go.mod` não pode
  passar disso.
- **Um `tool.json` que é JSON VÁLIDO mas com o SCHEMA errado derruba o hub
  inteiro no boot — e nem `go build` nem `go test` pegam isso, só o smoke
  test do Docker (ou subir o binário de verdade).** O registry carrega
  `tools/*/tool.json` no `store.Open()`/início do processo e trata erro de
  unmarshal como FATAL (o processo sai). Achado ao adicionar `scan-nosqli`:
  pus `modes[].params` como array de OBJETOS (copiando a forma do `params`
  top-level), mas no struct `Mode` o campo `params` é `[]string` (só os
  NOMES dos params a mostrar naquele modo, que já estão definidos no
  `params` top-level) — `json: cannot unmarshal object into Go struct field
  Mode.modes.params of type string`. O hub subia e saía na hora, e no CI
  isso apareceu como o container `rh` "exited" fazendo o smoke test do
  `docker build`/`docker build (tor sidecar)` falhar com `cannot join
  network namespace of a non running container` — uma mensagem que NÃO
  aponta pro tool.json, fácil de confundir com problema de infra/rede do
  sidecar (não é: as duas imagens buildaram; o hub é que crashou no boot).
  Regra: ao adicionar/editar um `tool.json`, SUBA o hub uma vez
  (`go build -o /tmp/rh ./cmd/reconhub && cd num dir isolado com symlinks
  pra tools/pipelines/wordlists/web && /tmp/rh -addr 127.0.0.1:PORTA`) e
  confira o log `registry: N ferramenta(s)...` + `/api/health` 200 — é o
  único jeito de validar o schema do manifesto sem o Docker. `modes[].params`
  é `[]string` (nomes); param novo de modo tem que existir no `params`
  top-level.
- **A aba Mapa (array `METHODOLOGY` em `web/index.html`) representa cada
  categoria de vuln por um chip — e uma tool de categoria nova some dele se
  ninguém adicionar.** Sutileza que engana: tools COM pipeline aparecem pelo
  chip da PIPELINE (ex: `scan-sqli`→`sqli-sweep`, `scan-cors`→`cors-sweep`,
  `scan-path-traversal`→`lfi-sweep`), então estão cobertas automaticamente;
  só as tools SINGLE-TARGET SEM pipeline (`scan-idor`, `scan-privesc`,
  `scan-mass-assignment`, `scan-nosqli`, `scan-xss-stored`,
  `scan-bruteforce-check`, `scan-waf-fingerprint`) precisam de um chip
  `{type:'tool'}` próprio — e foram justamente essas que driftaram pra fora
  do Mapa ao longo de várias sessões. É o "aparecer na aba Mapa" que a
  filosofia exige. Ao adicionar uma tool de vuln sem pipeline, some um chip
  na fase certa do `METHODOLOGY` (4 · Vulnerabilidades, em geral) e valide a
  UI com Playwright (chips presentes + sem overflow horizontal em 390px),
  como manda o passo 5 de "Antes de commitar". Confira o que falta: tool de
  vuln sem pipeline própria cujo nome não aparece em `web/index.html`.
- **O `FileStore` (backend padrão, JSON-lines) carrega tudo em memória no
  `store.Open()` e nunca relê o arquivo do disco depois — só o próprio
  processo que abriu o store vê o que ele mesmo escreve.** Popular dados
  de teste escrevendo direto num `data/*.jsonl` (ou via um script Go
  separado chamando `store.Open()` no mesmo diretório) enquanto o hub já
  está rodando não aparece em nenhuma resposta da API até reiniciar o
  processo do hub — não é um bug, é como um backend de arquivo simples
  costuma funcionar, mas é fácil gastar um tempo achando que a
  ferramenta/endpoint está com bug quando na verdade é só o processo
  antigo com o snapshot velho em memória. Pra popular findings de teste
  (ex: validar `internal/intel.DetectChains` fim-a-fim contra a API/UI
  de verdade, não só os testes unitários): (1) suba o servidor DEPOIS de
  escrever os dados, ou (2) se precisar escrever com o servidor já no
  ar, reinicie-o depois — nunca assuma que uma escrita externa aparece
  sozinha. Um script Go de seed que importa `internal/store` só compila
  se estiver dentro da árvore do módulo (`internal/` não é importável de
  fora) — crie um pacote `cmd/` temporário pra isso e apague antes de
  commitar, nunca deixe esse tipo de scratch pacote no diff.
- **Escopo de programa em notação CIDR (`10.10.0.0/24`) estava
  documentado como suportado (comentário do campo `InScope` em
  `internal/scope/scope.go` sempre citou `"10.0.0.0/8"` como exemplo
  válido) mas nunca funcionou de verdade — quebrado em dois lugares ao
  mesmo tempo.** `cleanPattern()` trata qualquer `/` como início de path
  de URL pra cortar fora (pensado pra `https://acme.com/api` →
  `acme.com`), então `10.10.0.0/24` virava silenciosamente `10.10.0.0`
  ao salvar — o programa "aceitava" a sub-rede sem erro nenhum, só que o
  que ficava gravado era um único IP. E mesmo se o prefixo sobrevivesse,
  `matchPattern()` nunca teve lógica de CIDR — só match exato de string
  ou sufixo de subdomínio, então nunca ia bater num IP individual dentro
  do range de qualquer jeito. Resultado: todo alvo real da sub-rede
  vinha "fora de escopo" (403), sem nenhuma mensagem apontando pro
  motivo real (parecia bug de digitação do operador, não bug do hub).
  Corrigido: `cleanPattern()` tenta `net.ParseCIDR()` ANTES da lógica de
  cortar path/porta (preserva e normaliza o prefixo), e `matchPattern()`
  ganhou um caso dedicado que usa `net.ParseCIDR`+`ipNet.Contains()` de
  verdade quando o pattern (limpo) contém `/`. Teste de regressão:
  `TestCIDRPrefixSurvivesCleanPattern`/`TestContainsCIDR` em
  `internal/scope/scope_test.go`. Lição maior: **um comentário de doc no
  código que promete um formato de input sem teste nenhum cobrindo esse
  formato é exatamente onde esse tipo de bug sutil sobrevive anos sem
  ninguém notar** — se o comentário cita um exemplo (`"10.0.0.0/8"`), tem
  que existir um teste pra esse exemplo específico, não só pros formatos
  óbvios (host puro, `*.host`).
- **`proxy.go` (compartilhado, 34 cópias idênticas) agora RESPEITA o rate
  limit do alvo, não só BYPASSA.** Antes o `blockRotator` só existia quando
  `RECONHUB_PROXY_CONTROL_URL` estava setado (Tor) e sua única ação era
  rotacionar circuito depois de N bloqueios. Faltava o outro lado: num 429/503
  ele não fazia backoff nem honrava `Retry-After` — martelava até o threshold.
  Agora `withBlockRotation` SEMPRE embrulha (mesmo sem Tor) e o `RoundTrip`,
  num 429/503, dorme antes de devolver a resposta (pausando naturalmente o
  worker que chamou), honrando `Retry-After` (segundos ou HTTP-date) limitado
  a `RECONHUB_RATELIMIT_MAX_BACKOFF_MS` (default 30s; 0 desliga). Respeitar é
  sempre; bypassar (rotação) segue só com Tor. Qualquer mudança no proxy.go
  precisa ser propagada às 34 cópias (são byte-idênticas — `md5sum` único é o
  invariante; há teste `parseRetryAfter`/`backoffFor` em `proxy_test.go`).
- **Encoding-bypass de payload vive nos injetores de URL/path/IP, por design
  — não nos de caractere, e NÃO é pra espalhar base64/hash em tudo.** Onde o
  payload É a string que atravessa o filtro (`scan-path-traversal`:
  `%2e%2e%2f` simples/duplo, `....//`, null byte, Windows; `scan-open-redirect`:
  22 variantes; `scan-ssrf`: IP decimal/hex/octal/IPv6/`%25`), as variantes de
  encoding são o próprio conjunto de payloads e vão verbatim na query (ver
  `withParamRaw` no path-traversal — `q.Encode()` re-encodaria e quebraria um
  `%2e` pré-encodado). Nos injetores de caractere (`scan-sqli` aspa, `scan-xss`,
  `scan-ssti`) o URL-encoding já é automático na query e base64/hash só passa
  se a app decodificar aquele formato (raro, app-específico) — espalhar isso
  multiplicaria o tráfego por N e feriria o "nunca DoS / pacing é padrão" da
  filosofia. Resumo: adicione variante de encoding onde ela de fato atravessa
  um filtro decodável, não como cargo cult em todo scanner.
- **Confirmação de finding que só checa se um fragmento aparece no corpo,
  sem provar que esse fragmento só poderia vir de exploração real, gera
  falso positivo todo santo dia que o alvo ecoar o próprio payload de
  volta.** Achado numa mesma sessão de triagem em três ferramentas
  diferentes: `js-secret-hunter` (o regex de "Private Key (PEM)" só
  conferia o cabeçalho `-----BEGIN...-----`, sem exigir corpo base64 real —
  um shim WebCrypto que monta o PEM via template literal JS
  `` `-----BEGIN PRIVATE KEY-----\n${key.toString("base64")}\n-----END...` ``
  batia igual, porque `${...}` nunca vira segredo de verdade);
  `scan-ssrf` (a lista de chaves que confirma `aws-metadata-iam-creds` e
  `gcp-metadata` inclui `"security-credentials"` e `"computeMetadata"` —
  que são, elas mesmas, substrings da URL injetada; se a página só
  refletir a query string de volta — canonical link, `__NEXT_DATA__`,
  mensagem de erro — o "achado" confirma sozinho sem o servidor nunca
  ter buscado o metadata endpoint); e `js-ai-key-hunter` ("Pinecone" era
  só o formato de qualquer UUID, sem exigir a palavra por perto; "Google
  AI (Gemini)" rotulava qualquer chave `AIza...` — formato compartilhado
  por Maps/Firebase/Identity Toolkit/etc — como Gemini especificamente,
  sem confirmar isso via `validate=true`). Regra geral pra qualquer
  `confirm()`/regex de secret novo: exigir corpo real (não só cabeçalho),
  remover o payload refletido do corpo antes de comparar contra ele
  mesmo, e exigir uma palavra de contexto por perto quando o formato do
  segredo for genérico (UUID, prefixo curto reaproveitado por vários
  produtos). Ver `tools/js-secret-hunter/patterns.go`,
  `tools/scan-ssrf/targets.go` (`stripReflected`) e
  `tools/js-ai-key-hunter/patterns.go`.
- **`os.Exit()` dentro de uma função chamada em loop sobre uma lista de
  hosts mata o job inteiro no primeiro host que falhar** — aconteceu no
  `scan-dep-confusion` (modo `site`/`site-list`): `harvestSite()` chamava
  `os.Exit(2)` no primeiro erro de fetch, e o primeiro "host" de uma
  varredura de programa é sempre `target` (adicionado antes da lista de
  `params.urls`), que numa esteira de bug bounty costuma ser o próprio
  padrão de escopo (`*.exemplo.com`) — nunca uma URL de verdade, sempre
  falha por DNS, sempre matava o job antes de tentar qualquer host real.
  Erro de I/O por item de uma lista processada em loop devia sempre virar
  `continue`/log — nunca `os.Exit` — e reservar `os.Exit` pra quando
  *nenhum* item da lista deu certo.
