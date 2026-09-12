# Sidecar de Chrome headless pro recon-hub — devtools remoto (CDP) em
# 127.0.0.1:9222. Roda como serviço separado no docker-compose,
# compartilhando a rede do container reconhub (network_mode:
# "service:reconhub"), então essa porta só existe dentro daquele namespace
# de rede — nada é exposto pro host. Usado por scan-xss-dom (e qualquer
# ferramenta futura que precise de navegador de verdade, não só
# http.Client) via RECONHUB_CHROME_URL. Ver docker-compose.yml e
# tools/scan-xss-dom/browser.go.
FROM alpine:3.20

# Usuário/grupo próprios (mesmo padrão do sidecar de Tor) — dono explícito
# do diretório de perfil do Chrome, sem depender de detalhe interno do
# pacote.
RUN apk add --no-cache chromium \
 && addgroup -g 10003 chromerunner \
 && adduser -D -u 10003 -G chromerunner chromerunner \
 && mkdir -p /tmp/chrome-data \
 && chown -R chromerunner:chromerunner /tmp/chrome-data

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER chromerunner
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
