# scan-open-redirect

Testa **parâmetros de redirect** com payloads de bypass e **confirma** o open
redirect pelo **destino real** da resposta — não só porque o valor foi
refletido. Confirmação = a resposta manda o navegador pro **canary**
(`example.com`, reservado pela IANA — navegar pra lá é inofensivo).

## O que preencher

- **Alvo:** uma URL `http`/`https`. **De preferência já com o parâmetro
  suspeito na query** — `https://site.com/login?next=/home`. Aí a ferramenta
  substitui o valor de `next` pelos payloads. Sem query, ela testa os nomes da
  wordlist mesmo assim (`?url=…`, `?redirect=…`, …).
- **`wordlist`:** lista de **NOMES de parâmetro** (não de caminhos). A embutida
  `builtin/open-redirect-params` (56 nomes) cobre os comuns. Dá pra escolher
  qualquer wordlist do SecLists; o mais parecido é
  `seclists/Discovery/Web-Content/...` mas a embutida costuma bastar.
- **`params`:** nomes extra além da wordlist, separados por vírgula.
- **`canary`:** troque só se `example.com` estiver na whitelist do alvo.

## Modos

| modo     | campo        | o que faz                                  |
|----------|--------------|--------------------------------------------|
| `single` | Alvo (URL)   | uma URL                                     |
| `list`   | `urls`       | várias URLs coladas (vírgula/linha)        |
| `file`   | `urls_file`  | arquivo no servidor, uma URL por linha     |

## Payloads (17 bypasses)

`https://CANARY` · `http://CANARY` · `//CANARY` · `https:/CANARY` (barra
faltando) · `/\CANARY` e `\/\/CANARY` (backslash) · `////CANARY` ·
`//CANARY/%2e%2e` · `%2F%2FCANARY` · `%09…` / `%0A…` (tab/newline) ·
`https://ALVO@CANARY` (userinfo) · `https://CANARY#.ALVO` · `https://CANARY?.ALVO`
· `https://CANARY\.ALVO` · `https://CANARY/.ALVO` · ` //CANARY` (espaço).

Para em cada `(URL, parâmetro)` no **1º payload** que confirmar.

## O que ele reporta

| finding_type               | sev.   | quando                                                    |
|----------------------------|--------|----------------------------------------------------------|
| `open-redirect`            | high   | resposta **3xx** com `Location` apontando pro canary     |
| `open-redirect-clientside` | medium | corpo com `<meta refresh>` ou `location.*=` pro canary   |

Cada hit também sai como **`asset` kind=`url`** (a URL exata que disparou).
Redirect **pro próprio alvo** (`/dashboard`, login) **não** vira finding.

## Numa pipeline

3º step depois de recon + coleta de URLs. Ver `pipelines/redirect-hunt.json`
(`recon-crtsh` → `scan-open-redirect` sobre os hosts encontrados).

## Avulso

```bash
echo '{"target":"https://site.com/login?next=/x","params":{"max_params":10}}' | go run .
echo '' | go run . -target site.com -params "next,url,dest" -pretty
```
