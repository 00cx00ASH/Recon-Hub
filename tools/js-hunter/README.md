# js-hunter

Recon de **JavaScript**: reconstrói o código-fonte a partir de **source maps** e
extrai a **superfície de API** que o front-end usa.

## O que preencher

- **Alvo:** a URL de uma página — `https://app.exemplo.com`. Baixa a página, os
  `<script src>` e, pra cada JS, tenta o source map.
- **Sem wordlist.**

## O que ele faz

1. **Source maps.** Pra cada `.js`, tenta o `//# sourceMappingURL=` declarado
   **e** o palpite `<arquivo>.js.map`. Se achar, faz o parse do formato v3 e
   recupera os arquivos originais de `sourcesContent` (código não-minificado:
   nomes reais, comentários, rotas). Vira `js-sourcemap-exposed` (**low**) + o
   `.map` sai como `asset` kind=`url`.
2. **Endpoints.** Varre o HTML inline + todos os JS + as fontes recuperadas por:
   - `fetch("…")`, `axios.get/post/…("…")`, `xhr.open("GET","…")`
   - chaves `url` / `uri` / `endpoint` / `baseURL` / `route` em objetos
   - caminhos que parecem API: `/api`, `/v1`, `/rest`, `/graphql`, `/internal`,
     `/admin`, `/auth`, `/oauth`, `/_next/data`, …
   - URLs absolutas (menos CDNs/analytics conhecidos)
   Deduplica, agrega os métodos HTTP vistos, e cada endpoint sai como
   **`asset` kind=`endpoint`**.
3. **Marca os sensíveis** → `js-interesting-endpoint` (**medium**):
   `/admin`, `/internal`, `/debug`, `/actuator`, `/graphql`, `/.env`,
   `/swagger` `/openapi` `/api-docs`, `/metrics`, `/.git`, `/backup`,
   `/token`, `/oauth`, `/upload`, `/export`, `/user(s)/`.
4. Um `js-endpoints-discovered` (**info**) resume a contagem.

## Parâmetros

| param        | default | efeito                              |
|--------------|---------|-------------------------------------|
| `no_maps`    | false   | não tentar os source maps           |
| `max_js`     | 60      | teto de arquivos JS por página      |
| `timeout_ms` | 12000   | timeout por requisição              |

## Numa pipeline

`recon-crtsh` → `js-hunter` → **`scan-fuzz`** (ou `scan-open-redirect`): os
endpoints achados alimentam o fuzzing. Ver `pipelines/js-recon.json`.

## Avulso

```bash
echo '{"target":"https://app.exemplo.com"}' | go run . -pretty
```
