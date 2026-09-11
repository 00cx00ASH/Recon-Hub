# Sidecar de Tor pro recon-hub — SOCKS5 em 127.0.0.1:9050, controle em
# 127.0.0.1:9051. Roda como serviço separado no docker-compose, compartilhando
# a rede do container reconhub (network_mode: "service:reconhub"), então
# essas portas só existem dentro daquele namespace de rede — nada é exposto
# pro host. Ver docker-compose.yml e README > Docker > Proxy/Tor.
FROM alpine:3.20

# Usuário/grupo próprios (não confia no uid que o pacote alpine cria) —
# dono explícito do DataDirectory que o torrc aponta, então a permissão
# nunca depende de detalhe interno do pacote.
RUN apk add --no-cache tor netcat-openbsd \
 && addgroup -g 10002 torrunner \
 && adduser -D -u 10002 -G torrunner torrunner \
 && mkdir -p /var/lib/tor-data \
 && chown -R torrunner:torrunner /var/lib/tor-data \
 && chmod 700 /var/lib/tor-data

COPY torrc /etc/tor/torrc

USER torrunner
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
