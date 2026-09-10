# scan-dep-confusion

**Dependency confusion** em npm, PyPI, Cargo e Composer. Lê um manifesto (ou
extrai os imports de uma página) e faz um `GET` no **registro público** de cada
dependência. Nome **ausente** = alguém pode publicar esse nome lá fora e o build
interno (que espera um pacote privado homônimo) puxa o do atacante.

Só faz `GET` nos registros — **não publica nada**.

## Modos

| modo    | Alvo / campo            | o que faz                                                        |
|---------|------------------------|----------------------------------------------------------------|
| `url`   | URL crua do manifesto  | baixa `package.json` / `requirements.txt` / `Cargo.toml` / … e parseia |
| `site`  | URL de uma página      | baixa a página + os `<script src>`, extrai `import`/`require` bare (trata como npm) |
| `paste` | `manifest` (+ `ecosystem`) | você cola o conteúdo do manifesto                         |
| `file`  | `manifest_file` (+ `ecosystem`) | caminho de um arquivo no servidor                    |

O ecossistema é detectado pelo **nome do arquivo** (`package.json`→npm,
`Cargo.toml`→cargo, `requirements*.txt`/`pyproject.toml`→pypi,
`composer.json`→composer) e, se não der, pelo **conteúdo**. Force com
`params.ecosystem` quando precisar (obrigatório nos modos `paste`/`file` sem
extensão reconhecível).

## O que é parseado

- **npm** — `dependencies`, `devDependencies`, `peerDependencies`,
  `optionalDependencies`. Ignora specs `file:` / `link:` / `workspace:` /
  `git+` / `github:` / URL (não são confusáveis).
- **PyPI** — `requirements*.txt` (um spec por linha, tira extras e markers),
  `pyproject.toml` PEP 621 (`dependencies = [...]`) e Poetry
  (`[tool.poetry.dependencies]`). Ignora `-r`, `-e`, `git+`, URLs, `python`.
- **Cargo** — `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`.
  Ignora `{ path = }` e `{ git = }`; resolve `{ package = "x" }` (dep renomeada).
- **Composer** — `require`, `require-dev`. Ignora `php`, `ext-*`, `lib-*`.

## Parâmetros

| param        | default | efeito                                          |
|--------------|---------|------------------------------------------------|
| `no_dev`     | false   | ignora dev/optional/peer                        |
| `concurrency`| 8       | consultas simultâneas aos registros            |
| `timeout_ms` | 10000   | timeout por requisição                          |

## Findings

| finding_type           | sev.   | quando                                                        |
|------------------------|--------|-------------------------------------------------------------|
| `dependency-confusion` | high   | nome **sem escopo** ausente do registro público             |
| `dependency-confusion` | high   | pacote **com escopo** cujo escopo inteiro não existe (npm)  |
| `dependency-confusion` | medium | pacote com escopo ausente, mas o escopo existe (npm)        |
| `dependency-confusion` | medium | `vendor/pacote` ausente do Packagist                        |

Cada hit também sai como **`asset` kind=`package`** (`ecosystem:nome`).
Nomes sem resposta clara do registro (rede/rate-limit) saem num `log` `warn`.

## Avulso

```bash
echo '{"target":"https://raw.githubusercontent.com/acme/app/main/package.json"}' | go run .
echo '{"params":{"mode":"site"},"target":"https://app.exemplo.com"}' | go run .
echo '{"params":{"mode":"paste","ecosystem":"pypi","manifest":"requests==2.0\ninternal-lib"}}' | go run . -pretty
```
