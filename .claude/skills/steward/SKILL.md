---
name: steward
description: Convenções deste repo (recon-hub) pra dirigir um PR ao verde/mergeável. Leia antes de agir em evento de CI ou review num PR deste repo — diz os gates de validação ANTES de todo push e as convenções (merge squash, force-with-lease na branch reiniciada) que têm precedência sobre as regras genéricas de drive-to-green. NÃO expande acesso nem anula nenhum "never" da orientação de stewardship; o CLAUDE.md é a fonte de verdade das lições, este arquivo só aponta pra elas.
---

# Stewardship do recon-hub — como dirigir um PR ao verde aqui

Este arquivo é lido pela orientação de drive-to-green antes de agir num PR
deste repo. Ele tem precedência sobre as regras genéricas **só em
convenção e em quão proativo ser** — nunca sobre os "never" (não pular/
desabilitar teste, não reescrever history de branch alheia, não commit
vazio / close-reopen pra chutar CI, não aprovar/mergear além do que o
operador autorizou). As **lições** técnicas moram no `CLAUDE.md` (o
"segundo cérebro"); aqui só ficam o posture e os gates, apontando pra lá.

## Antes de QUALQUER push (os gates deste repo, nesta ordem)

O CI roda `gofmt -l .` como PRIMEIRO passo, antes de compilar — um arquivo
Go desformatado reprova o job inteiro. Então, pra não gastar ciclo:

1. `gofmt -l .` na raiz — tem que vir vazio. Rode DEPOIS de editar Go,
   antes de build/vet/test (`go build` não garante formatação).
2. `go build ./... && go vet ./... && go test -race -count=1 ./...` no core,
   **com e sem** `-tags sqlite`.
3. Em cada `tools/<nome>/` tocado: `cd tools/<nome> && gofmt -l . &&
   go vet ./... && go build ./... && go test ./...`.
4. Validações específicas por tipo de mudança (abaixo).

## Gates por tipo de mudança — os que o CI só pega tarde (ou não pega)

- **Mexeu/criou `tool.json`** → SUBA o hub isolado e confira que ele carrega:
  `go build -o /tmp/rh ./cmd/reconhub`, rode de um dir com symlinks pra
  `tools/pipelines/wordlists/web` (nunca contra o `data/` do checkout), e
  veja o log `registry: N ferramenta(s)...` + `/api/health` 200. Um
  `tool.json` JSON-válido mas com schema errado é **fatal no boot** e `go
  build`/`go test` NÃO pegam — no CI vira o container `rh` "exited"
  quebrando o `docker build`/tor sidecar com uma mensagem que não aponta
  pro tool.json. (`modes[].params` é `[]string` de nomes, não objetos.)
- **Tool nova** → registre no matrix HARDCODED do `.github/workflows/ci.yml`
  (senão ela não roda gofmt/vet/test por-tool no CI), e confira que
  `go-version` do CI ≥ a maior versão em qualquer `tools/*/go.mod` e ==
  base do `Dockerfile` (1.23). Reconte os 4 lugares de contagem
  (README/GUIA-DE-USO/TOOL_CONTRACT/aba Mapa) e a fração de `proxy.go`.
  Tool de vuln SEM pipeline precisa de chip próprio no `METHODOLOGY` da
  aba Mapa (`web/index.html`).
- **Mudou `web/index.html`** → valide com Playwright num servidor de teste
  isolado: chips/fluxo presentes + **zero overflow horizontal em 390px**
  (mobile) além de desktop. Overflow de página é bug recorrente aqui.
- **Mudou `proxy.go`** → propague byte-idêntico pras 3x+ cópias (`md5sum`
  único é o invariante).

Detalhe e causa-raiz de cada um desses: seção "Lições aprendidas" do
`CLAUDE.md`. Não re-derive — leia de lá.

## Convenções de merge/branch deste repo

- **Merge = squash.** O histórico das branches carrega commits
  experimentais; o `main` fica limpo com um commit por PR.
- **Branch reiniciada pós-merge:** a branch de trabalho é reiniciada do
  `main` a cada PR (mesma branch). O remote ainda aponta pro head já
  mergeado, então o push volta rejeitado — `--force-with-lease` é o certo
  AQUI, mas só depois de provar que o remote já está 100% no `main`:
  `git diff origin/main <remote-head> -- .` tem que vir VAZIO (o squash
  não deixa o head antigo como ancestral, então `--is-ancestor` dá falso
  negativo; compare CONTEÚDO). Isso é a exceção documentada ao "nunca
  force-push" — vale porque é histórico já mergeado, não trabalho alheio.
- **Regra de manutenção:** todo fix de gotcha não-óbvio ganha uma entrada
  em "Lições aprendidas" do `CLAUDE.md` NA MESMA PR.

## Posture (proatividade neste repo)

- Só confirmação por resposta real conta (PoC-only); regex/confirm que só
  vê o payload refletido de volta é falso positivo — ver a lição de
  confirmação no `CLAUDE.md` antes de mexer em qualquer `confirm()`.
- Não invente: chain nova só com entrada correspondente no "Playbook de
  encadeamento" do `bugbounty.md`; variante de encoding só onde atravessa
  filtro decodável; nada que fira "nunca DoS / pacing é padrão".
- Escopo é enforced no servidor (`internal/scope` + `paramsOutOfScope`) —
  nunca contorne "pra funcionar".
