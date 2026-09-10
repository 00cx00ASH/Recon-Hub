# js-ai-key-hunter

Caça **credenciais de provedores de IA/ML** no HTML + `<script src>` + **source
maps** (`.js.map`). Foco no que hoje mais vaza no front: chaves de LLM/embeddings/
voz/observabilidade.

## O que preencher

- **Alvo:** a URL de uma página — `https://app.exemplo.com`. Baixa a página, os
  JS referenciados e os source maps.
- **Sem wordlist.**

## Provedores cobertos (28 padrões)

OpenAI (`sk-proj-` e legado), Anthropic (`sk-ant-api03-`), Groq (`gsk_`),
Mistral, Perplexity (`pplx-`), Replicate (`r8_`), HuggingFace (`hf_`),
OpenRouter (`sk-or-v1-`), Together, Fireworks (`fw_`), Cohere, Google AI /
Gemini (`AIza`), Azure OpenAI (endpoint), ElevenLabs, Deepgram, AssemblyAI,
LangSmith (`lsv2_`), LangChain legado (`ls__`), Pinecone, Weights & Biases,
Stability, Clarifai, **GCP service account** (Vertex — `critical`), **AWS key**
(Bedrock/SageMaker).

Filtro de **entropia de Shannon** nos padrões genéricos + **denylist de
placeholders** (`your_`, `example`, `xxxx`, valor todo igual, …).

## Validação (opcional, read-only)

Com **`validate: true`**, cada chave leva **um `GET`** ao endpoint de
**metadados** do provedor (`api.openai.com/v1/models`,
`huggingface.co/api/whoami-v2`, `api.replicate.com/v1/account`, …). Só diz se a
chave **está viva** — nada é escrito, nenhum crédito é gasto, e a chave já está
pública no JS do alvo.

| finding_type      | sev.     | quando                                       |
|-------------------|----------|---------------------------------------------|
| `ai-key-exposed`  | high/critical | chave encontrada (sev. pelo provedor)   |
| `ai-key-valid`    | critical | `validate` on e o provedor respondeu 200/429 |
| `ai-key-invalid`  | info     | `validate` on e o provedor respondeu 401/403 |

Cada chave vira **`asset` kind=`credential`** (`<Provedor>:<redigida>`).

## Parâmetros

| param        | default | efeito                                            |
|--------------|---------|------------------------------------------------|
| `validate`   | false   | 1 GET read-only por chave pro provedor          |
| `no_js`      | false   | só o HTML, sem os `<script src>`               |
| `no_maps`    | false   | não tentar os `.js.map`                         |
| `min_len`    | 16      | tamanho mínimo do valor                         |
| `timeout_ms` | 12000   | timeout por requisição                          |

## Numa pipeline

`recon-crtsh` → `js-ai-key-hunter` (feed `urls` dos subdomínios) —
`pipelines/ai-key-sweep.json`.

## Avulso

```bash
echo '{"target":"https://app.exemplo.com"}' | go run . -pretty
echo '{"target":"https://app.exemplo.com","params":{"validate":true}}' | go run .
```
