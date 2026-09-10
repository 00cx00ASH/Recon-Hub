#!/usr/bin/env bash
# example-echo — ferramenta de referência do recon-hub.
#
# Contrato (ver docs/TOOL_CONTRACT.md):
#   - params chegam em JSON no stdin E como env RECONHUB_PARAM_<NOME>
#   - o alvo chega em $RECONHUB_TARGET
#   - cada linha do stdout é um objeto JSON (NDJSON): log | progress | finding | asset | done
set -euo pipefail

cat > /dev/null || true   # drena o payload JSON do stdin (não usamos aqui)

TARGET="${RECONHUB_TARGET:-desconhecido}"
COUNT="${RECONHUB_PARAM_COUNT:-3}"
DELAY_MS="${RECONHUB_PARAM_DELAY_MS:-300}"
sleep_s=$(awk -v ms="$DELAY_MS" 'BEGIN { printf "%.3f", ms / 1000 }')

emit() { printf '%s\n' "$1"; }
jstr() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

emit "{\"type\":\"log\",\"level\":\"info\",\"msg\":\"example-echo iniciando contra $(jstr "$TARGET")\"}"

for i in $(seq 1 "$COUNT"); do
  sleep "$sleep_s"
  pct=$(( i * 100 / COUNT ))
  emit "{\"type\":\"progress\",\"msg\":\"passo ${i}/${COUNT}\",\"data\":{\"pct\":${pct}}}"
  emit "{\"type\":\"asset\",\"kind\":\"demo\",\"value\":\"host${i}.$(jstr "$TARGET")\"}"
  emit "{\"type\":\"finding\",\"severity\":\"info\",\"finding_type\":\"demo\",\"title\":\"Finding de exemplo ${i} em $(jstr "$TARGET")\",\"asset\":\"host${i}.$(jstr "$TARGET")\",\"evidence\":\"linha ${i} gerada pelo stub example-echo\"}"
done

emit "{\"type\":\"done\",\"ok\":true,\"msg\":\"${COUNT} finding(s) emitido(s)\"}"
