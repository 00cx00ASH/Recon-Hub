# recon-hub — imagem única.
#
# O núcleo é um binário Go estático, mas as ferramentas rodam via `go run .`
# (cada uma é um módulo Go próprio). Por isso a imagem final ainda carrega o
# toolchain Go: o build compila o hub e "esquenta" os caches de módulo/compilação
# de todas as ferramentas para que `go run` funcione offline em runtime.

FROM golang:1.22-alpine

ENV GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    GOFLAGS=-mod=mod

RUN apk add --no-cache ca-certificates tzdata bash wget \
 && adduser -D -u 10001 app

# Backend de store: "" (padrão, arquivos, zero deps) ou "sqlite" para compilar
# o hub com `-tags sqlite` (baixa modernc.org/sqlite, driver puro-Go).
ARG RECONHUB_SQLITE=""

WORKDIR /app
COPY . .

# 1) compila o hub + o servidor MCP  2) pré-compila cada módulo de ferramenta
#    (popula /go/pkg/mod e o cache de build)  3) limpa o que não vai na imagem
RUN GOTAGS=$([ "$RECONHUB_SQLITE" = "sqlite" ] || [ "$RECONHUB_SQLITE" = "1" ] && echo "-tags sqlite" || true) \
 && go build $GOTAGS -trimpath -ldflags="-s -w" -o /usr/local/bin/reconhub ./cmd/reconhub \
 && go build -trimpath -ldflags="-s -w" -o /usr/local/bin/reconhub-mcp ./cmd/reconhub-mcp \
 && for d in tools/*/ ; do \
      if [ -f "$d/go.mod" ]; then echo ">> warming $d" && (cd "$d" && go build -o /dev/null ./...); fi; \
    done \
 && rm -rf /app/reconhub /app/data \
 && mkdir -p /app/data /app/watches \
 && cp -a /root/.cache /home/app/.cache \
 && chown -R app:app /app /home/app /go/pkg/mod

USER app
ENV HOME=/home/app \
    GOCACHE=/home/app/.cache/go-build \
    GOMODCACHE=/go/pkg/mod

EXPOSE 7878
VOLUME ["/app/data", "/app/watches"]

# /api/health não exige token
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:7878/api/health >/dev/null 2>&1 || exit 1

ENTRYPOINT ["reconhub"]
CMD ["-addr", "0.0.0.0:7878"]
