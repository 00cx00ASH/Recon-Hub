#!/usr/bin/env bash
# Atualiza e reinicia o recon-hub sozinho quando o branch remoto avança —
# pensado pra rodar via cron no host, mantendo o `docker compose up -d`
# sempre no commit mais novo sem intervenção manual.
#
# Uso: chame direto, ou agende no cron (ver README > Docker > Auto-update):
#   */5 * * * *  /caminho/pro/recon-hub/scripts/autoupdate.sh >> /caminho/pro/recon-hub/data/autoupdate.log 2>&1
#
# Não sobrescreve trabalho local: se o checkout tiver mudanças não commitadas
# ou divergir do remoto (commits locais que o remoto não tem), o merge
# --ff-only falha e o script para sem tocar em nada — só avisa no log.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_DIR="$(pwd)"
BRANCH="${RECONHUB_AUTOUPDATE_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
LOCK_FILE="$REPO_DIR/data/.autoupdate.lock"

mkdir -p "$REPO_DIR/data"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "$(date -Is) já tem uma atualização em andamento, pulando essa rodada."
  exit 0
fi

echo "$(date -Is) checando origin/$BRANCH..."
git fetch --quiet origin "$BRANCH"

LOCAL_REV="$(git rev-parse HEAD)"
REMOTE_REV="$(git rev-parse "origin/$BRANCH")"

if [ "$LOCAL_REV" = "$REMOTE_REV" ]; then
  echo "$(date -Is) sem mudanças (${LOCAL_REV:0:12})."
  exit 0
fi

echo "$(date -Is) commit novo em origin/$BRANCH: ${LOCAL_REV:0:12} -> ${REMOTE_REV:0:12}"

if ! git merge --ff-only "origin/$BRANCH"; then
  echo "$(date -Is) ERRO: não deu pra avançar o checkout local (working tree sujo ou histórico divergente)." \
       "Resolva manualmente — o script não sobrescreve nada sozinho." >&2
  exit 1
fi

echo "$(date -Is) reconstruindo e reiniciando o container..."
docker compose up -d --build

echo "$(date -Is) atualizado com sucesso pra ${REMOTE_REV:0:12}."
