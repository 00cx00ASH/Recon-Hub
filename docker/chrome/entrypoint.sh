#!/bin/sh
# Acha o binário do chromium instalado pelo pacote alpine — o nome do
# executável varia entre versões da distro (chromium-browser vs chromium),
# então detecta em vez de fixar um dos dois e quebrar silenciosamente numa
# atualização de imagem base.
set -eu

BIN=""
for cand in chromium-browser chromium; do
	if command -v "$cand" >/dev/null 2>&1; then
		BIN="$cand"
		break
	fi
done
if [ -z "$BIN" ]; then
	echo "entrypoint: nenhum binário chromium encontrado no PATH" >&2
	exit 1
fi

mkdir -p /tmp/chrome-data

exec "$BIN" \
	--headless=new \
	--remote-debugging-port=9222 \
	--remote-debugging-address=127.0.0.1 \
	--no-sandbox \
	--disable-gpu \
	--disable-dev-shm-usage \
	--disable-software-rasterizer \
	--disable-extensions \
	--user-data-dir=/tmp/chrome-data
