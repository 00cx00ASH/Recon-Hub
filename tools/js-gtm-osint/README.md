# js-gtm-osint

**OSINT de Google Tag Manager.** Acha os IDs de rastreamento numa página, baixa
o **container `gtm.js` público** de cada `GTM-ID` e o disseca. Não é intrusivo —
`gtm.js` é servido aberto pela Google pra qualquer um.

## O que preencher

- **Alvo:** a URL de uma página — `https://exemplo.com`. Baixa a página + os
  `<script src>` e extrai os IDs (`GTM-`, GA4 `G-`, `UA-`, Ads `AW-`, `GT-`,
  Floodlight `DC-`).
- Já tem o ID? Modo **id**: `params.gtm_id` = `GTM-XXXX` (um ou vários).
- **Sem wordlist.**

## O que ele reporta

| finding_type                 | sev.   | o quê                                                    |
|------------------------------|--------|--------------------------------------------------------|
| `tracking-ids-found`         | info   | todos os IDs achados na página                          |
| `gtm-container-loaded`       | info   | versão do container, nº de tags/triggers/variáveis, tipos de tag |
| `gtm-custom-html`            | info   | tag de HTML customizado (roda no contexto do site — revisar) |
| `gtm-custom-html-suspicious` | medium | idem, mas usa `document.write` / `eval` / `atob` / injeta `<script src>` de domínio desconhecido |
| `gtm-third-party-tags`       | info   | pixels de terceiros (Facebook, LinkedIn, TikTok, Hotjar, Criteo, UET…) |
| `gtm-linked-ids`             | info   | outros IDs de rastreamento referenciados dentro do container |
| `gtm-secret-in-container`    | low–high | chave/token hardcoded numa tag ou variável (valor redigido) |
| `gtm-container-empty`        | info   | `GTM-ID` referenciado mas container vazio / não publicado |

Cada ID vira **`asset` kind=`tracking-id`** (`GTM:…`, `GA4:…`, `UA:…`, …).

## Parâmetros

| param        | default | efeito                       |
|--------------|---------|------------------------------|
| `gtm_id`     | —       | `GTM-XXXX` direto (modo id)   |
| `timeout_ms` | 12000   | timeout por requisição       |

## Numa pipeline

`recon-crtsh` → `js-gtm-osint` (feed `urls` dos subdomínios) —
`pipelines/gtm-osint.json`. Bom pra mapear a stack de analytics/marketing e
achar tags customizadas ou segredos esquecidos em containers.

## Avulso

```bash
echo '{"target":"https://www.gov.uk"}' | go run . -pretty
echo '{"params":{"gtm_id":"GTM-XXXXXX"}}' | go run .
```
