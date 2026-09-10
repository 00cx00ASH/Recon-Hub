# scan-actuator

Procura **Spring Boot Actuator** (e os endpoints de management antigos, Boot 1.x)
expostos **sem autenticação**. Confirma cada achado pelo corpo da resposta — não
só pelo status 200 — pra não reportar página de login/erro como "endpoint".

## O que preencher

- **Alvo:** a **URL base** do app — `https://api.exemplo.com`. Sem `http://` /
  `https://` ele assume **https**. Não passe caminho (`/actuator`), só a origem.
- **Não usa wordlist.** A lista de caminhos é fixa (33 no total): `/actuator`,
  `/actuator/env`, `/actuator/heapdump`, `/actuator/beans`, … mais os antigos
  sem prefixo (`/env`, `/heapdump`, `/beans`, …) e `/jolokia`, `/jolokia/list`.

## Modos

| modo     | campo         | o que faz                                        |
|----------|---------------|--------------------------------------------------|
| `single` | Alvo (URL)    | varre uma URL base                               |
| `list`   | `hosts`       | várias URLs base coladas (vírgula ou uma/linha)  |
| `file`   | `hosts_file`  | arquivo no servidor, uma URL base por linha      |

## Parâmetros

| param        | default | efeito                              |
|--------------|---------|-------------------------------------|
| `concurrency`| 15      | requisições simultâneas             |
| `timeout_ms` | 8000    | timeout por requisição              |

## O que ele classifica

| finding_type          | sev.      | quando                                                              |
|-----------------------|-----------|--------------------------------------------------------------------|
| `actuator-heapdump`   | critical  | `/heapdump` devolve o dump (octet-stream / `JAVA PROFILE` / gzip)  |
| `actuator-env`        | high      | `/env` com `propertySources`/`activeProfiles`                      |
| `actuator-env`        | critical  | idem, e o corpo tem `password` / `secret` / `token` / `key`        |
| `actuator-jolokia`    | high      | Jolokia (JMX sobre HTTP) responde JSON com `agent`/`value`         |
| `actuator-index`      | medium    | `/actuator` lista os endpoints (`_links`)                          |
| `actuator-endpoint`   | medium    | `/beans` `/mappings` `/configprops` `/loggers` `/threaddump` … abertos |
| `actuator-endpoint`   | low       | `/health` ou `/info` com detalhes (`components`, `db`, `diskSpace`)|

Cada caminho aberto também sai como **`asset` kind=`endpoint`** (URL completa).

## Numa pipeline

Bom **2º step** depois de um recon que produz hosts/URLs
(`recon-crtsh` → feed `hosts`). Ver `pipelines/actuator-sweep.json`.

## Avulso

```bash
echo '{"target":"https://api.exemplo.com","params":{"timeout_ms":6000}}' | go run .
echo '' | go run . -target api.exemplo.com -pretty
```
