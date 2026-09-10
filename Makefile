# recon-hub — atalhos de dev. `make help` lista tudo.
export GOTOOLCHAIN ?= local

# módulos Go: a raiz (hub) + cada ferramenta com go.mod próprio
TOOL_MODS := $(dir $(wildcard tools/*/go.mod))
MODS      := . $(TOOL_MODS)

.DEFAULT_GOAL := help

## run: sobe o hub localmente (go run)
.PHONY: run
run:
	go run ./cmd/reconhub

## build: compila o binário do hub em ./reconhub (store em arquivos, zero deps)
.PHONY: build
build:
	go build -trimpath -ldflags="-s -w" -o reconhub ./cmd/reconhub

## build-sqlite: compila o hub com o backend SQLite opcional em ./reconhub-sqlite
.PHONY: build-sqlite
build-sqlite:
	go build -tags sqlite -trimpath -ldflags="-s -w" -o reconhub-sqlite ./cmd/reconhub

## mcp: compila o servidor MCP em ./reconhub-mcp
.PHONY: mcp
mcp:
	go build -trimpath -ldflags="-s -w" -o reconhub-mcp ./cmd/reconhub-mcp

## fmt: gofmt -w em todos os módulos
.PHONY: fmt
fmt:
	@for m in $(MODS); do echo ">> gofmt $$m"; gofmt -w "$$m"; done

## fmt-check: falha se algo não está gofmt-ado (usado no CI)
.PHONY: fmt-check
fmt-check:
	@bad=$$(gofmt -l $(MODS)); if [ -n "$$bad" ]; then echo "não formatado:"; echo "$$bad"; exit 1; fi

## vet: go vet em todos os módulos
.PHONY: vet
vet:
	@for m in $(MODS); do echo ">> vet $$m"; ( cd "$$m" && go vet ./... ) || exit 1; done

## test: go test em todos os módulos
.PHONY: test
test:
	@for m in $(MODS); do echo ">> test $$m"; ( cd "$$m" && go test ./... ) || exit 1; done

## test-race: idem com -race (mais lento)
.PHONY: test-race
test-race:
	@for m in $(MODS); do echo ">> test -race $$m"; ( cd "$$m" && go test -race ./... ) || exit 1; done

## test-sqlite: go test do backend SQLite opcional (tag `sqlite`, só o módulo raiz)
.PHONY: test-sqlite
test-sqlite:
	go build -tags sqlite ./cmd/reconhub
	go test -tags sqlite ./internal/store/

## check: fmt-check + vet + test + test-sqlite (o que o CI roda)
.PHONY: check
check: fmt-check vet test test-sqlite

## tools-build: compila cada módulo de ferramenta (valida offline)
.PHONY: tools-build
tools-build:
	@for m in $(TOOL_MODS); do echo ">> build $$m"; ( cd "$$m" && go build -o /dev/null ./... ) || exit 1; done

## docker: build da imagem reconhub:local
.PHONY: docker
docker:
	docker build -t reconhub:local .

## up / up-dev / down: docker compose
.PHONY: up up-dev down logs
up:
	docker compose up -d --build
up-dev:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
down:
	docker compose down
logs:
	docker compose logs -f reconhub

## clean: remove binários e dados locais
.PHONY: clean
clean:
	rm -rf reconhub reconhub-sqlite reconhub-mcp data

.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
