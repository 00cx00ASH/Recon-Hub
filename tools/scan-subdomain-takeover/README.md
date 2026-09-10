# scan-subdomain-takeover

Detecta **subdomain takeover** por CNAME dangling. Para cada host:

1. Segue a cadeia de CNAME com queries DNS diretas (`miekg/dns`) — um alvo que
   dá **NXDOMAIN** fica visível, ao contrário do que `net.LookupCNAME` faria.
2. Casa qualquer nome da cadeia contra ~24 fingerprints de serviços
   (GitHub Pages, S3, Heroku, Netlify, Vercel, Azure, Fastly, Shopify, Zendesk,
   Ghost, Bitbucket, Pantheon, Surge, Unbounce, Webflow, Wix…).
3. Se `http` estiver ligado, faz um `GET` e procura o texto de "recurso não
   existe" do serviço no corpo.

## Veredito → evento

| situação                                                        | evento (contrato NDJSON)                | severidade |
|----------------------------------------------------------------|----------------------------------------|-----------|
| alvo do CNAME dá NXDOMAIN **e** é serviço reclamável           | `finding` `subdomain-takeover`         | **high**  |
| corpo HTTP casa o fingerprint do serviço                       | `finding` `subdomain-takeover`         | **high**  |
| alvo do CNAME dá NXDOMAIN, serviço desconhecido                | `finding` `dangling-cname`             | medium    |
| CNAME casa serviço conhecido, mas nada confirma                | `finding` `cname-known-service`        | low       |
| sem CNAME / CNAME resolve e não casa nada                      | —                                      | —         |

`only_confirmed` esconde os `low`.

## Parâmetros (`tool.json`)

| param            | tipo   | default | efeito                                              |
|------------------|--------|---------|----------------------------------------------------|
| `subdomains`     | string | —       | lista por vírgula/linha; vazio ⇒ checa só o target |
| `concurrency`    | int    | 20      | workers                                            |
| `timeout_ms`     | int    | 7000    | timeout por query DNS/HTTP                         |
| `http`           | bool   | true    | confirmar o fingerprint com um GET                 |
| `only_confirmed` | bool   | false   | só `high`/`medium`                                 |

## Uso avulso (sem o hub)

```bash
# lê params do stdin JSON (igual ao hub)
echo '{"target":"exemplo.com","params":{"subdomains":"a.exemplo.com,b.exemplo.com"}}' | go run .

# ou por flags, com saída legível
go run . -target exemplo.com -subs a.exemplo.com,b.exemplo.com -pretty
go run . -subs-file subs.txt -only-confirmed -pretty
```

Compilar em vez de `go run .` (mais rápido; troque o `exec` do `tool.json` para
`["./scan-subdomain-takeover"]`):

```bash
go build -o scan-subdomain-takeover .
```

## Notas

- Módulo Go próprio (`go.mod` aqui) — não entra nas deps do hub. Única
  dependência: `github.com/miekg/dns` (fixado em `v1.1.62`, compatível com Go 1.22).
- Fingerprints derivados de _can-i-take-over-xyz_ / _subjack_; um `high` ainda
  pede confirmação manual antes de reportar num programa.
- `InsecureSkipVerify` no cliente HTTP de propósito — alvos dangling costumam ter
  TLS quebrado.
