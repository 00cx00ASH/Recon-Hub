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
