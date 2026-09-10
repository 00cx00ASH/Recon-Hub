# recon-infra-enum

**Port scan TCP (connect)** + **banner grab** + fingerprint de serviço. Marca
serviços sensíveis expostos. Sem raw sockets — não precisa de root, mas é
barulhento. **Use só em alvos autorizados.**

## O que preencher

- **Alvo:** um **host**, **IP** ou **CIDR** (`10.0.0.0/24`, expandido até
  `max_hosts`).
- **Sem wordlist.**

## Portas (`ports`)

| valor      | o que é                                                       |
|------------|-------------------------------------------------------------|
| `top100`   | ~120 portas curadas, cada uma com nome de serviço (default) |
| `top1000`  | as curadas + 1–1024                                          |
| `web`      | 80/81/88/443/3000/5000/8000/8080/8443/8888/9000/9200/9443…  |
| `db`       | 1433/1521/3306/5432/6379/9042/9200/11211/27017…             |
| csv/ranges | `22,80,8000-8100`                                           |

## O que ele faz

1. Connect scan (`net.DialTimeout`) de cada `host:porta`, com `concurrency`
   conexões simultâneas.
2. Pra cada porta aberta: **banner grab** best-effort — lê o greeting de
   SSH/SMTP/FTP/POP3/IMAP/MySQL/PostgreSQL, faz `PING` no Redis, `version` no
   Memcached, `HEAD /` nos HTTP. `no_banner` desliga.
3. `identify(porta, banner)` refina o serviço (SSH→produto, HTTP→`Server:`,
   Redis, Memcached, MySQL…).
4. Cada porta aberta → **`asset` kind=`port`** (`tcp://host:porta`) +
   `open-port` (**info**).
5. **`exposed-service` (medium)** quando o serviço é sensível: `redis`,
   `memcached`, `mongodb`, `elasticsearch`, `docker`/`docker-tls`,
   `kube-apiserver`, `kubelet`, `etcd`, `rdp`, `vnc`, `winrm`, `mssql`,
   `mysql`, `postgresql`, `oracle`, `couchdb`, `cassandra`, `kafka`,
   `zookeeper`, `rabbitmq-mgmt`, `jmx`, `java-rmi`, `smb`, `ldap`, `snmp`,
   `telnet`, `ftp`, `kibana`, `consul`, `influxdb`, `weblogic`, `epmd`.

## Parâmetros

| param        | default | efeito                                     |
|--------------|---------|-------------------------------------------|
| `ports`      | top100  | conjunto de portas                         |
| `no_banner`  | false   | só descobrir portas, sem banner            |
| `max_hosts`  | 1024    | teto ao expandir um CIDR                    |
| `concurrency`| 300     | conexões simultâneas                       |
| `timeout_ms` | 1500    | timeout por conexão                        |

## Numa pipeline

`recon-passive-enum` → `recon-infra-enum` (feed `hosts` dos subdomínios) —
`pipelines/infra-sweep.json`. Depois `scan-mongodb` pega os `27017` que
aparecerem.

## Avulso

```bash
echo '{"target":"10.0.0.5"}' | go run . -pretty
echo '{"target":"192.168.1.0/24","params":{"ports":"web","timeout_ms":800}}' | go run .
```
