package report

import "strings"

// tmpl is the reusable knowledge for one class of finding: what it is, why it
// matters, how to reproduce it, how to fix it. Keyed by finding type.
type tmpl struct {
	Name        string
	CWE         string
	Description string
	Impact      string
	Remediation string
	Refs        []string
	// Repro returns numbered steps; f exposes the finding's fields.
	Repro func(f Item) []string
}

// genericRepro is the fallback: point at the asset, cite the evidence.
func genericRepro(f Item) []string {
	steps := []string{}
	if f.Asset != "" {
		steps = append(steps, "Acesse / requisite: `"+f.Asset+"`")
	}
	if m := f.Meta; m != nil {
		if u, ok := m["test_url"].(string); ok && u != "" {
			steps = append(steps, "URL exata do teste: `"+u+"`")
		}
		if p, ok := m["payload"].(string); ok && p != "" {
			steps = append(steps, "Payload: `"+p+"`")
		}
		if req, ok := m["request"].(string); ok && req != "" {
			steps = append(steps, "Requisição:\n```\n"+req+"\n```")
		}
	}
	if f.Evidence != "" {
		steps = append(steps, "Observe: "+f.Evidence)
	}
	if len(steps) == 0 {
		steps = append(steps, "Reproduza a condição descrita na evidência.")
	}
	return steps
}

// templates maps a finding type (exact, then prefix) to its knowledge.
var templates = map[string]tmpl{
	"subdomain-takeover": {
		Name: "Subdomain takeover", CWE: "CWE-350",
		Description: "Um registro DNS (CNAME/ALIAS) do alvo aponta para um recurso de terceiro (S3, Azure, GitHub Pages, Heroku, Netlify…) que **não existe mais**. Um atacante pode reivindicar esse recurso no provedor e passar a servir conteúdo sob o subdomínio do alvo.",
		Impact:      "Phishing convincente no domínio da vítima, roubo de cookies com escopo de domínio pai, bypass de CSP/CORS que confia em `*.alvo.com`, distribuição de malware e comprometimento de OAuth/SSO que usa o subdomínio como redirect.",
		Remediation: "Remover o registro DNS pendente **ou** recriar o recurso no provedor antes de qualquer atacante. Adotar processo de baixa que remove o DNS junto com o recurso. Monitorar CNAMEs para alvos de takeover conhecidos.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/350.html", "https://owasp.org/www-community/attacks/Subdomain_takeover", "https://github.com/EdOverflow/can-i-take-over-xyz"},
		Repro: func(f Item) []string {
			s := []string{"`dig +short " + host(f) + "` — observe o CNAME para o serviço de terceiro."}
			s = append(s, "`curl -sI https://"+host(f)+"` — a resposta do provedor indica recurso não reclamado ("+shortEvidence(f)+").")
			s = append(s, "No provedor correspondente, o nome do recurso ("+claimTarget(f)+") está disponível para registro.")
			return s
		},
	},
	"dangling-dns": {
		Name: "Registro DNS pendente (domínio registrável)", CWE: "CWE-350",
		Description: "Um host referenciado pelo alvo (link, CNAME, script) resolve para um domínio/subdomínio que **não existe mais** (NXDOMAIN). Qualquer pessoa pode registrar esse nome.",
		Impact:      "Sequestro do host: servir conteúdo malicioso onde a aplicação/usuários esperam o alvo, roubo de dados enviados àquele host, execução de JavaScript de terceiros se o host servia um `<script>`.",
		Remediation: "Remover a referência/registro pendente. Se o domínio for necessário, registrá-lo imediatamente.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/350.html"},
		Repro:       genericRepro,
	},
	"broken-link-hijack": {
		Name: "Broken Link Hijacking", CWE: "CWE-350",
		Description: "Uma página do alvo referencia (link, `<script src>`, `<iframe>`) um recurso externo — usuário/repo do GitHub, pacote npm, bucket S3, subdomínio de PaaS, handle de rede social — que **está livre para registro**. Um atacante o registra e passa a controlar o conteúdo servido a partir daquela referência.",
		Impact:      "Se a referência for um `<script src>`, é **execução de JavaScript arbitrário** no contexto da página do alvo (XSS persistente efetivo). Para links comuns: phishing e engano de usuários que confiam no destino.",
		Remediation: "Remover ou corrigir a referência. Para dependências, fixar em um recurso controlado (self-host, SRI). Registrar o nome órfão se ele deve permanecer sob controle da organização.",
		Refs:        []string{"https://owasp.org/www-community/attacks/Subdomain_takeover", "https://cwe.mitre.org/data/definitions/350.html"},
		Repro: func(f Item) []string {
			s := []string{}
			if p, ok := f.Meta["page"].(string); ok {
				s = append(s, "Abra `"+p+"` e localize a referência a `"+f.Asset+"`.")
			}
			s = append(s, "`curl -sI '"+f.Asset+"'` — "+shortEvidence(f)+".")
			if ct, ok := f.Meta["claim_target"].(string); ok && ct != "" {
				s = append(s, "O nome `"+ct+"` está disponível para registro no provedor correspondente.")
			}
			return s
		},
	},
	"open-bucket": {
		Name: "Bucket de armazenamento com listagem/leitura pública", CWE: "CWE-200",
		Description: "Um bucket (S3/GCS/Azure Blob/…) referenciado pela aplicação permite **listagem anônima** de objetos e/ou leitura pública do conteúdo.",
		Impact:      "Exposição de dados: backups, credenciais, PII de clientes, código-fonte, artefatos internos — o que estiver no bucket. Em buckets com escrita pública, também defacement e hospedagem de malware.",
		Remediation: "Bloquear acesso público (S3 Block Public Access na conta e no bucket), remover ACLs `AllUsers`/`AuthenticatedUsers`, revisar a bucket policy. Auditar o conteúdo já exposto e rotacionar qualquer segredo encontrado.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/200.html", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"},
		Repro: func(f Item) []string {
			return []string{"`curl -s '" + f.Asset + "'` — a resposta lista objetos do bucket (" + shortEvidence(f) + ").", "Baixe um objeto listado para confirmar a leitura anônima."}
		},
	},
	"bucket-takeover": {
		Name: "Bucket de armazenamento referenciado mas inexistente", CWE: "CWE-350",
		Description: "A aplicação referencia um bucket que **não existe** (NoSuchBucket). Um atacante pode criá-lo com o mesmo nome e controlar o conteúdo servido a partir daquela referência.",
		Impact:      "Servir conteúdo/JS malicioso onde a aplicação espera assets legítimos; potencial XSS se o bucket servia scripts.",
		Remediation: "Remover a referência ou recriar o bucket sob controle da organização, na mesma região.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/350.html"},
		Repro:       genericRepro,
	},
	"secret": {
		Name: "Segredo exposto em conteúdo público", CWE: "CWE-798",
		Description: "Uma credencial (chave de API, token, chave privada, string de conexão) está embutida em recurso servido publicamente (HTML, JavaScript, source map).",
		Impact:      "Acesso não autorizado ao serviço correspondente com os privilégios da credencial: leitura/escrita de dados, envio de mensagens/e-mails, custos financeiros, movimento lateral. Impacto exato depende do provedor e do escopo da chave.",
		Remediation: "**Revogar e rotacionar a credencial imediatamente.** Remover do código versionado e do bundle. Mover segredos para o backend / cofre (Vault, Secrets Manager) e nunca expor no cliente. Adicionar verificação de segredos no CI.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/798.html", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content"},
		Repro: func(f Item) []string {
			src := ""
			if s, ok := f.Meta["source"].(string); ok {
				src = s
			}
			s := []string{}
			if src != "" {
				s = append(s, "Baixe `"+src+"`.")
			} else if f.Asset != "" {
				s = append(s, "Baixe `"+f.Asset+"`.")
			}
			s = append(s, "Localize o valor: "+f.Evidence+" (valor redigido no relatório; o valor completo está no recurso).")
			return s
		},
	},
	"ai-key-exposed": {
		Name: "Chave de provedor de IA/ML exposta no cliente", CWE: "CWE-798",
		Description: "Uma chave de API de um provedor de IA (OpenAI, Anthropic, Google AI, HuggingFace, Replicate…) está embutida em recurso público.",
		Impact:      "Uso da conta do alvo para inferência/treino às custas dele (fatura), exfiltração de prompts/dados enviados ao provedor, e — para chaves de service account/Vertex — acesso amplo ao projeto de nuvem.",
		Remediation: "Revogar a chave. Fazer as chamadas de IA a partir do backend com a chave nunca no cliente. Aplicar limites de gasto e alertas no provedor.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/798.html"},
		Repro:       genericRepro,
	},
	"ai-key-valid": {
		Name: "Chave de IA/ML exposta e VÁLIDA", CWE: "CWE-798",
		Description: "A chave exposta no cliente foi confirmada como ativa por uma chamada de leitura ao endpoint de metadados do provedor.",
		Impact:      "Igual à chave exposta, mas confirmado: a conta é abusável agora.",
		Remediation: "Revogar/rotacionar imediatamente e mover a chave para o backend.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/798.html"},
		Repro:       genericRepro,
	},
	"cors-reflect-credentials": {
		Name: "CORS: reflexão de origem com credenciais", CWE: "CWE-942",
		Description: "O endpoint reflete a origem enviada pelo atacante em `Access-Control-Allow-Origin` **e** define `Access-Control-Allow-Credentials: true`. Qualquer site pode ler respostas autenticadas do alvo no navegador da vítima.",
		Impact:      "Roubo de dados sensíveis autenticados (perfil, tokens, mensagens) de qualquer usuário logado que visite uma página do atacante. Em muitos casos leva a comprometimento total da conta.",
		Remediation: "Nunca refletir a origem. Manter uma allowlist estrita de origens confiáveis. Se `credentials` não é necessário, não enviar o header. Não usar `*` com credenciais (é inválido, mas alguns servidores fazem).",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/942.html", "https://portswigger.net/web-security/cors"},
		Repro: func(f Item) []string {
			o, _ := f.Meta["sent_origin"].(string)
			return []string{
				"Requisição: `curl -s -H 'Origin: " + orDash(o, "https://evil.example") + "' -H 'Cookie: <sessão da vítima>' '" + f.Asset + "'`",
				"Resposta: " + f.Evidence,
				"PoC: página do atacante faz `fetch('" + f.Asset + "', {credentials:'include'})` e lê `response.text()`.",
			}
		},
	},
	"cors-null-origin": {
		Name: "CORS: origem 'null' aceita", CWE: "CWE-942",
		Description: "O endpoint aceita `Origin: null` (obtível via `<iframe sandbox>`, redirects ou arquivos locais) — combinada com credenciais, permite leitura cross-origin autenticada.",
		Impact:      "Vazamento de dados autenticados para uma página controlada pelo atacante.",
		Remediation: "Rejeitar `Origin: null`. Usar allowlist explícita de origens.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/942.html", "https://portswigger.net/web-security/cors"},
		Repro: func(f Item) []string {
			return []string{"`curl -s -H 'Origin: null' '" + f.Asset + "'`", "Resposta: " + f.Evidence}
		},
	},
	"open-redirect": {
		Name: "Open redirect", CWE: "CWE-601",
		Description: "Um parâmetro controla o destino de um redirecionamento HTTP sem validação de allowlist, permitindo enviar a vítima para um domínio externo arbitrário.",
		Impact:      "Phishing com URL do domínio confiável; bypass de validações de `redirect_uri` em OAuth/SSO levando a roubo de token; encadeamento com SSRF em alguns casos.",
		Remediation: "Redirecionar apenas para caminhos relativos ou para uma allowlist de destinos. Rejeitar `//`, `\\`, esquemas absolutos e credenciais em URL. Não confiar em filtros de string; parsear a URL e comparar o host.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/601.html", "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"},
		Repro: func(f Item) []string {
			return []string{
				"Requisite: `curl -sI '" + f.Asset + "'`",
				"Resposta: " + f.Evidence,
				"O navegador é redirecionado para o host do atacante (`example.com` no teste).",
			}
		},
	},
	"open-redirect-clientside": {
		Name: "Open redirect (client-side)", CWE: "CWE-601",
		Description: "Um parâmetro controla um redirect feito no cliente (`<meta refresh>` ou `location` em JS) para um destino externo arbitrário.",
		Impact:      "Igual ao open redirect server-side: phishing, bypass de `redirect_uri`.",
		Remediation: "Validar o destino contra uma allowlist antes de atribuir a `location`. Não construir o redirect a partir de parâmetros não confiáveis.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/601.html"},
		Repro:       genericRepro,
	},
	"graphql-introspection-enabled": {
		Name: "GraphQL: introspection habilitada", CWE: "CWE-200",
		Description: "O endpoint GraphQL responde à query `__schema`, expondo o schema inteiro (todos os tipos, queries, mutations, argumentos).",
		Impact:      "Facilita o mapeamento da superfície de ataque: revela mutations sensíveis, campos de PII/segredo e operações internas que deveriam ser descobertas com dificuldade. Não é vuln por si só, mas amplifica todas as outras.",
		Remediation: "Desabilitar introspection em produção (`introspection: false` no Apollo, equivalente no seu servidor). Desabilitar também as *field suggestions* (`\"Did you mean\"`).",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/200.html", "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"},
		Repro: func(f Item) []string {
			return []string{
				"`curl -s -XPOST '" + f.Asset + "' -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}'`",
				"Resposta: o schema completo é retornado (" + f.Evidence + ").",
			}
		},
	},
	"graphql-get-enabled": {
		Name: "GraphQL: queries via GET (CSRF)", CWE: "CWE-352",
		Description: "O endpoint aceita operações GraphQL pelo método GET com a query na query string.",
		Impact:      "Se mutations também forem aceitas por GET e não houver token anti-CSRF, um atacante executa mutations no navegador da vítima autenticada (CSRF). Também facilita cache poisoning e vazamento de queries em logs/histórico.",
		Remediation: "Aceitar apenas `POST` com `Content-Type: application/json`. Exigir token anti-CSRF. Nunca permitir mutations por GET.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/352.html", "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"},
		Repro: func(f Item) []string {
			return []string{"`curl -s '" + f.Asset + "?query=%7B__typename%7D'` — retorna dados GraphQL."}
		},
	},
	"actuator-heapdump": {
		Name: "Spring Boot Actuator: /heapdump exposto", CWE: "CWE-200",
		Description: "O endpoint `/actuator/heapdump` serve, sem autenticação, um dump completo da heap da JVM.",
		Impact:      "O heap contém tudo que estava em memória: senhas, tokens de sessão, chaves de API, dados de usuários, connection strings. Comprometimento praticamente total da aplicação.",
		Remediation: "Não expor o Actuator publicamente. Restringir `management.endpoints.web.exposure.include`, mover para uma porta/rede de gestão, exigir autenticação. Nunca expor `heapdump`, `env`, `threaddump`.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/200.html", "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security"},
		Repro: func(f Item) []string {
			return []string{"`curl -s '" + f.Asset + "' -o heap.hprof` — baixa o dump.", "Abra em um analisador (Eclipse MAT, `jhat`) e busque por credenciais."}
		},
	},
	"actuator-env": {
		Name: "Spring Boot Actuator: /env exposto", CWE: "CWE-200",
		Description: "`/actuator/env` expõe, sem autenticação, todas as propriedades de configuração da aplicação.",
		Impact:      "Vazamento de configuração e, frequentemente, de segredos (`spring.datasource.password`, chaves de API, tokens). Em versões vulneráveis, encadeável com `/env` POST para RCE.",
		Remediation: "Restringir a exposição do Actuator e exigir autenticação; sanitizar propriedades sensíveis.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/200.html"},
		Repro: func(f Item) []string {
			return []string{"`curl -s '" + f.Asset + "'` — " + f.Evidence + "."}
		},
	},
	"mongodb-no-auth": {
		Name: "MongoDB acessível sem autenticação", CWE: "CWE-306",
		Description: "A instância MongoDB aceita comandos administrativos (`listDatabases`) sem credenciais.",
		Impact:      "Leitura, alteração e exclusão de todos os bancos e coleções. Exfiltração completa de dados; ransomware de banco (dumps apagados e resgate cobrado) é comum nesse cenário.",
		Remediation: "Habilitar autenticação (`security.authorization: enabled`), criar usuários com menor privilégio, restringir o `bindIp` à rede interna e usar firewall. Nunca expor 27017 à internet.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/306.html", "https://www.mongodb.com/docs/manual/administration/security-checklist/"},
		Repro: func(f Item) []string {
			hp := strings.TrimPrefix(f.Asset, "mongodb://")
			return []string{"`mongosh 'mongodb://" + hp + "' --eval 'db.adminCommand({listDatabases:1})'` — lista os bancos sem pedir senha.", "Evidência: " + f.Evidence}
		},
	},
	"open-cognito-identity-pool": {
		Name: "AWS Cognito Identity Pool entrega credenciais a usuários não autenticados", CWE: "CWE-1188",
		Description: "O Identity Pool tem o acesso não autenticado habilitado e a role associada concede permissões além do mínimo. `GetId` + `GetCredentialsForIdentity` anônimos retornam credenciais AWS temporárias válidas.",
		Impact:      "Depende da política da role não autenticada — frequentemente inclui acesso a S3, DynamoDB, SNS/SQS ou outros serviços, permitindo leitura/escrita de dados sem qualquer conta.",
		Remediation: "Desabilitar acesso não autenticado se não for necessário. Restringir a policy da role unauth ao mínimo absoluto, com `Condition` por `aws:PrincipalTag`/recurso. Revisar o que a role permite hoje.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/1188.html", "https://docs.aws.amazon.com/cognito/latest/developerguide/role-based-access-control.html"},
		Repro: func(f Item) []string {
			region, _ := f.Meta["region"].(string)
			pool, _ := f.Meta["identity_pool_id"].(string)
			return []string{
				"`aws cognito-identity get-id --identity-pool-id " + orDash(pool, f.Asset) + " --region " + orDash(region, "<region>") + "`",
				"`aws cognito-identity get-credentials-for-identity --identity-id <do passo anterior> --region " + orDash(region, "<region>") + "` — retorna AccessKeyId/SecretKey/SessionToken.",
				"`aws sts get-caller-identity` com essas credenciais confirma o acesso. " + f.Evidence,
			}
		},
	},
	"supabase-anon-table-read": {
		Name: "Supabase: tabela com leitura anônima (RLS ausente)", CWE: "CWE-1220",
		Description: "Uma tabela exposta via PostgREST permite `SELECT` com a chave anônima — a Row Level Security está desabilitada ou sem policy restritiva.",
		Impact:      "Leitura de todos os registros da tabela por qualquer pessoa com a anon key (que é pública por design). Exposição de PII, dados de negócio, e potencialmente segredos armazenados em tabelas de config.",
		Remediation: "Habilitar RLS em **todas** as tabelas do schema `public` e escrever policies explícitas. Revisar `GRANT`s para os roles `anon`/`authenticated`. Nunca usar a `service_role` key no cliente.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/1220.html", "https://supabase.com/docs/guides/auth/row-level-security"},
		Repro: func(f Item) []string {
			return []string{"`curl -s '" + f.Asset + "?select=*&limit=5' -H 'apikey: <anon key do site>'` — retorna linhas.", "Evidência: " + f.Evidence}
		},
	},
	"supabase-service-role-key-exposed": {
		Name: "Supabase: service_role key no cliente", CWE: "CWE-798",
		Description: "A chave `service_role` do Supabase — que **ignora toda a RLS** — está embutida em recurso público.",
		Impact:      "Leitura e escrita irrestrita em todo o banco, incluindo `auth.users`. Comprometimento total do backend.",
		Remediation: "Revogar a chave imediatamente (rotacionar o JWT secret do projeto). A `service_role` key só pode existir no servidor.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/798.html"},
		Repro:       genericRepro,
	},
	"open-rtdb-read": {
		Name: "Firebase Realtime Database com leitura anônima", CWE: "CWE-1220",
		Description: "As regras do Realtime Database permitem `.read` sem autenticação; `GET <db>/.json` retorna dados.",
		Impact:      "Exposição de todo o conteúdo do banco (perfis, mensagens, config). Se `.write` também estiver aberto, alteração/destruição de dados.",
		Remediation: "Escrever regras que exijam `auth != null` e validem por usuário/caminho. Nunca deixar `\".read\": true` na raiz.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/1220.html", "https://firebase.google.com/docs/database/security"},
		Repro: func(f Item) []string {
			return []string{"`curl -s '" + strings.TrimSuffix(f.Asset, "/") + "/.json?shallow=true'` — retorna as chaves de topo sem autenticar.", "Evidência: " + f.Evidence}
		},
	},
	"open-firestore-read": {
		Name: "Firebase Firestore com leitura anônima", CWE: "CWE-1220",
		Description: "As regras do Firestore permitem `read` sem autenticação em ao menos uma coleção.",
		Impact:      "Leitura dos documentos da coleção por qualquer pessoa.",
		Remediation: "Regras com `allow read: if request.auth != null` e validação por documento. Nunca `allow read, write: if true`.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/1220.html", "https://firebase.google.com/docs/firestore/security/get-started"},
		Repro:       genericRepro,
	},
	"dependency-confusion": {
		Name: "Dependency confusion", CWE: "CWE-427",
		Description: "Um pacote listado como dependência (npm/PyPI/Cargo/Composer) **não existe no registro público**. Se o build resolve dependências pelo registro público (ou como fallback), um atacante publica esse nome e injeta código no build/CI do alvo.",
		Impact:      "Execução de código no ambiente de build/CI: exfiltração de segredos de CI, adulteração de artefatos, supply-chain compromise dos usuários finais.",
		Remediation: "Publicar um placeholder do nome no registro público (namespace claim), ou usar scoped packages com escopo registrado. Configurar o gerenciador para **nunca** cair no registro público para pacotes internos (`.npmrc` com scope→registry, `--index-url` único no pip, etc).",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/427.html", "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610"},
		Repro: func(f Item) []string {
			eco, _ := f.Meta["ecosystem"].(string)
			pkg, _ := f.Meta["package"].(string)
			return []string{
				"O manifesto do alvo declara `" + orDash(pkg, f.Asset) + "` (" + orDash(eco, "?") + ").",
				"Consulta ao registro público retorna 404 — o nome está livre: " + f.Evidence + ".",
			}
		},
	},
	"jwt-alg-none": {
		Name: "JWT aceita `alg: none`", CWE: "CWE-347",
		Description: "Um JWT usado pela aplicação tem header `alg: none` / vazio, indicando que a verificação de assinatura pode estar desabilitada.",
		Impact:      "Forja de tokens: um atacante monta um JWT com quaisquer claims (ex `admin: true`, outro `sub`) sem conhecer segredo algum.",
		Remediation: "Rejeitar explicitamente `alg: none`. Fixar o algoritmo esperado no verificador (allowlist, ex só `RS256`). Nunca deixar a lib escolher o `alg` a partir do header.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/347.html", "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"},
		Repro:       genericRepro,
	},
	"jwt-weak-secret": {
		Name: "Segredo HMAC do JWT quebrável", CWE: "CWE-347",
		Description: "O JWT é assinado com HS256/384/512 usando um segredo fraco, recuperado por força bruta com uma lista pequena.",
		Impact:      "Com o segredo, o atacante forja qualquer token válido: escalada de privilégio, personificação de qualquer usuário.",
		Remediation: "Trocar o segredo por um valor aleatório de ≥256 bits. Preferir algoritmos assimétricos (RS256/ES256) com a chave privada só no emissor. Rotacionar todos os tokens.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/347.html"},
		Repro: func(f Item) []string {
			sec, _ := f.Meta["secret"].(string)
			return []string{"O segredo `" + orDash(sec, "<recuperado>") + "` reproduz a assinatura do token.", "Com ele, `jwt.encode({...}, '" + orDash(sec, "<segredo>") + "', 'HS256')` gera tokens aceitos pela aplicação."}
		},
	},
	"cache-poisoning": {
		Name: "Web cache poisoning", CWE: "CWE-444",
		Description: "Uma entrada não-chaveada (header como `X-Forwarded-Host`) é refletida numa resposta que o cache compartilhado armazena. Uma requisição limpa subsequente à mesma URL cacheada recebeu o valor do atacante — confirmando o envenenamento.",
		Impact:      "A resposta envenenada é servida a **todos** os usuários que pedem aquela URL: XSS em massa, redirect malicioso, importação de scripts do atacante, DoS (CPDoS) se a resposta envenenada for um erro.",
		Remediation: "Incluir no cache key todos os inputs que afetam a resposta, ou não refletir headers não-chaveados. Normalizar/rejeitar `X-Forwarded-*` na borda. Configurar o CDN para não cachear respostas que variam por header não presente no `Vary`.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/444.html", "https://portswigger.net/research/practical-web-cache-poisoning"},
		Repro: func(f Item) []string {
			cb, _ := f.Meta["cache_buster"].(string)
			probe, _ := f.Meta["probe"].(string)
			return []string{
				"Envenene: `curl -s '" + f.Asset + "' -H '" + probeHeader(probe) + ": cachepoison-poc.example.com'`",
				"Confirme: `curl -s '" + f.Asset + "'` (sem o header) ainda retorna o valor do atacante — a resposta foi cacheada sob o cache-buster `" + orDash(cb, "?") + "`, isolando o teste do tráfego real.",
				"Evidência: " + f.Evidence,
			}
		},
	},
	"exposed-service": {
		Name: "Serviço sensível exposto na rede", CWE: "CWE-668",
		Description: "Uma porta com um serviço sensível (banco, cache, orquestrador, painel de gestão) está acessível.",
		Impact:      "Varia por serviço: acesso a dados sem auth (Redis, Elastic, Memcached), RCE (Docker API, JMX), controle de cluster (kube-apiserver, etcd). Ver a evidência para o serviço específico.",
		Remediation: "Restringir a porta a redes internas / VPN, habilitar autenticação do serviço, aplicar firewall. Não expor serviços de infraestrutura à internet.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/668.html"},
		Repro: func(f Item) []string {
			return []string{"`nc -v " + strings.TrimPrefix(f.Asset, "tcp://") + "` — a porta responde.", "Evidência: " + f.Evidence}
		},
	},
	"sensitive-file-exposed": {
		Name: "Arquivo sensível acessível", CWE: "CWE-538",
		Description: "Um arquivo que não deveria ser servido (`.env`, `.git/config`, backup, `.htpasswd`…) está acessível por HTTP.",
		Impact:      "Vazamento de credenciais, chaves, estrutura interna, ou — no caso de `.git/` — todo o código-fonte e histórico.",
		Remediation: "Bloquear o acesso a dotfiles/backups no servidor web. Remover o arquivo do webroot. Rotacionar qualquer segredo exposto.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/538.html"},
		Repro: func(f Item) []string {
			return []string{"`curl -s '" + f.Asset + "'` — " + f.Evidence + "."}
		},
	},
	"github-repo-secret": {
		Name: "Segredo versionado em repositório público", CWE: "CWE-798",
		Description: "Uma credencial está commitada em um repositório público da organização.",
		Impact:      "Acesso ao serviço correspondente. Mesmo após remoção do HEAD, o segredo permanece no histórico do git.",
		Remediation: "Revogar/rotacionar. Remover do histórico (`git filter-repo`) e forçar push, ou tornar o repo privado e rotacionar mesmo assim. Adicionar scanning de segredos (GitHub secret scanning, gitleaks no CI).",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/798.html"},
		Repro:       genericRepro,
	},
	"github-pwn-request": {
		Name: "GitHub Actions: workflow `pull_request_target` com checkout do PR", CWE: "CWE-269",
		Description: "Um workflow roda em `pull_request_target` (com acesso a secrets e a um token privilegiado) **e** faz checkout do código do PR, executando código não confiável de qualquer fork.",
		Impact:      "Um PR malicioso de qualquer pessoa executa código com o `GITHUB_TOKEN` privilegiado e os secrets do repo: exfiltração de segredos, push no repo, publicação de releases, comprometimento da supply chain.",
		Remediation: "Não fazer checkout do `head` do PR em `pull_request_target`. Se precisar do código do PR, usar `pull_request` (sem secrets) ou o padrão de dois workflows (build sem privilégio → comentário com privilégio). Ver a doc do GitHub sobre 'pwn requests'.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/269.html", "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"},
		Repro:       genericRepro,
	},
	"github-actions-injection": {
		Name: "GitHub Actions: injeção de shell via `${{ github.event.* }}`", CWE: "CWE-94",
		Description: "Um passo `run:` interpola diretamente um campo controlável pelo atacante (título/corpo de issue ou PR, `head_ref`…) no shell script.",
		Impact:      "Execução de comandos arbitrários no runner com o contexto do workflow (secrets, token).",
		Remediation: "Nunca interpolar `${{ ... }}` de dados não confiáveis dentro de `run:`. Passar por uma variável de ambiente (`env:`) e referenciar como `\"$VAR\"`, ou usar `actions/github-script` com argumentos.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/94.html", "https://securitylab.github.com/research/github-actions-untrusted-input/"},
		Repro:       genericRepro,
	},
	"reflected-xss": {
		Name: "Cross-Site Scripting (XSS) refletido", CWE: "CWE-79",
		Description: "Um parâmetro é refletido na resposta HTML sem sanitização — caracteres que fecham uma tag (`<`, `>`) voltam intactos, permitindo injetar markup arbitrário no contexto da página.",
		Impact:      "Execução de JavaScript arbitrário no navegador da vítima no contexto de origem do site: roubo de sessão/token, ações em nome do usuário, phishing in-page. Impacto real depende de mitigação em camada (CSP, `HttpOnly` no cookie de sessão) — descreva isso no relatório.",
		Remediation: "Escapar toda saída dinâmica pro contexto onde ela entra (HTML entity encoding no corpo, JS string escaping dentro de `<script>`, URL encoding em atributos `href`/`src`). Preferir template engines com auto-escape habilitado por padrão. Adicionar CSP como camada extra, não como correção principal.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/79.html", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
		Repro: func(f Item) []string {
			steps := []string{"Requisite: `curl -s '" + f.Asset + "'`"}
			if p, ok := f.Meta["payload"].(string); ok && p != "" {
				steps = append(steps, "Payload injetado: `"+p+"`")
			}
			steps = append(steps, "Observe: "+f.Evidence, "O marcador do payload aparece cru no HTML da resposta — sem escaping.")
			return steps
		},
	},
	"reflected-xss-attribute": {
		Name: "Possível XSS refletido (quebra de atributo/string JS, contexto não confirmado)", CWE: "CWE-79",
		Description: "Uma aspa (`\"` ou `'`) do payload voltou sem escapar, mas `<`/`>` não — sugere quebra de atributo HTML ou de string dentro de `<script>`, mas o scanner não faz parsing de HTML completo pra confirmar se o contexto ao redor permite exploração de verdade.",
		Impact:      "Se o contexto permitir (atributo sem aspas ao redor bem definidas, ou string JS concatenada em código executado), o mesmo impacto do XSS refletido comum. Precisa de confirmação manual antes de classificar como reportável — não trate como certeza.",
		Remediation: "Mesma correção do XSS refletido: escapar a saída pro contexto certo (atributo, string JS). Confirme o contexto exato antes de escrever o relatório.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/79.html", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
		Repro: func(f Item) []string {
			steps := []string{"Requisite: `curl -s '" + f.Asset + "'`"}
			if p, ok := f.Meta["payload"].(string); ok && p != "" {
				steps = append(steps, "Payload injetado: `"+p+"`")
			}
			steps = append(steps, "Observe: "+f.Evidence, "Abra a URL num navegador e inspecione o HTML ao redor do marcador antes de reportar — confirme se o atributo/script realmente quebra.")
			return steps
		},
	},
	"sqli-error-based": {
		Name: "SQL Injection (baseada em erro)", CWE: "CWE-89",
		Description: "Um caractere de quebra de string SQL (`'` ou `\"`) anexado a um parâmetro faz a aplicação vazar uma mensagem de erro real do banco de dados na resposta — prova que o valor chega numa query sem sanitização/parametrização.",
		Impact:      "Vazamento de erro por si só já expõe detalhes de implementação (engine, versão, às vezes a query). Se a entrada realmente for concatenada sem parametrização, o risco vai de leitura não autorizada de dados até, dependendo dos privilégios do usuário do banco, escrita/exclusão ou execução de comando — mas isso NÃO foi confirmado por esta ferramenta (que só prova o erro, nunca extrai dado).",
		Remediation: "Usar queries parametrizadas/prepared statements em toda a aplicação — nunca concatenar entrada do usuário numa query SQL. ORMs bem configurados já fazem isso por padrão; audite os pontos que usam SQL cru.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/89.html", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
		Repro: func(f Item) []string {
			steps := []string{"Requisite sem payload (baseline): confirme que a resposta normal NÃO menciona erro de banco."}
			if p, ok := f.Meta["payload"].(string); ok && p != "" {
				steps = append(steps, "Requisite com o payload anexado ao valor do parâmetro: `"+p+"`")
			}
			steps = append(steps, "URL de teste: `"+f.Asset+"`", "Observe: "+f.Evidence)
			return steps
		},
	},
}

// more exact templates for the medium+ variants that a blunt prefix would
// mislabel. Info-severity relatives (jwt-found, cognito-identifiers-exposed,
// supabase-key-exposed, …) intentionally have no template — they're skipped
// unless include_info, and then use the honest generic fallback.
var extra = map[string]tmpl{
	"jwt-no-exp": {
		Name: "JWT sem expiração", CWE: "CWE-613",
		Description: "Um JWT usado pela aplicação não tem o claim `exp` — o token nunca expira.",
		Impact:      "Um token vazado (log, histórico do navegador, XSS) é utilizável para sempre; não há janela de mitigação por expiração.",
		Remediation: "Emitir tokens de acesso de curta duração (minutos) com `exp`, e usar refresh tokens revogáveis para renovação.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/613.html"},
		Repro:       genericRepro,
	},
	"jwt-long-lived": {
		Name: "JWT com validade excessiva", CWE: "CWE-613",
		Description: "Um JWT usado pela aplicação expira apenas a mais de um ano da emissão.",
		Impact:      "Janela de abuso enorme para um token vazado.",
		Remediation: "Reduzir o `exp` para minutos/horas; usar refresh tokens.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/613.html"},
		Repro:       genericRepro,
	},
	"jwt-sensitive-claims": {
		Name: "JWT carrega dados sensíveis no payload", CWE: "CWE-312",
		Description: "O payload do JWT (que é apenas base64, **não criptografado**) contém dados sensíveis (e-mail, papel, permissões, sessão).",
		Impact:      "Qualquer pessoa que obtenha o token — inclusive o próprio usuário via DevTools — lê esses dados em claro. Se incluir dados de outros usuários ou lógica de autorização, é vazamento de informação.",
		Remediation: "Manter no JWT apenas identificadores opacos e o mínimo necessário. Buscar dados de perfil/autorização no backend por request.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/312.html"},
		Repro:       genericRepro,
	},
	"cors-reflect-origin": {
		Name: "CORS: reflexão de origem (sem credenciais)", CWE: "CWE-942",
		Description: "O endpoint reflete a origem do atacante em `Access-Control-Allow-Origin` sem `credentials`. Qualquer site pode ler respostas não autenticadas.",
		Impact:      "Vazamento de dados que não dependem de cookie/sessão (dados públicos-por-engano, respostas com info de ambiente). Menor que a variante com credenciais, mas ainda quebra a mesma-origem.",
		Remediation: "Usar allowlist explícita de origens. Não refletir o header `Origin`.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/942.html", "https://portswigger.net/web-security/cors"},
		Repro: func(f Item) []string {
			return []string{"`curl -s -H 'Origin: https://evil.example' '" + f.Asset + "'`", "Resposta: " + f.Evidence}
		},
	},
	"cors-wildcard": {
		Name: "CORS: Access-Control-Allow-Origin: *", CWE: "CWE-942",
		Description: "O endpoint responde com `Access-Control-Allow-Origin: *`. Isso é adequado para APIs de conteúdo público, mas problemático se a resposta contém dados que deveriam ser restritos por origem.",
		Impact:      "Se o endpoint serve dados sensíveis ou específicos do cliente, qualquer site pode lê-los. Sem `credentials`, não expõe respostas autenticadas.",
		Remediation: "Confirmar que a resposta é realmente pública. Se não for, trocar `*` por allowlist de origens.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/942.html"},
		Repro: func(f Item) []string {
			return []string{"`curl -sI '" + f.Asset + "' | grep -i access-control` — " + f.Evidence}
		},
	},
	"cors-wildcard-credentials": {
		Name: "CORS: wildcard com credenciais", CWE: "CWE-942",
		Description: "A resposta combina `Access-Control-Allow-Origin: *` com `Access-Control-Allow-Credentials: true`. É inválido pelo spec (navegadores rejeitam), mas alguns servidores/clientes/proxies antigos honram.",
		Impact:      "Em clientes que aceitam a combinação, leitura cross-origin autenticada de qualquer origem.",
		Remediation: "Nunca enviar `*` com `credentials`. Usar allowlist e refletir só origens confiáveis.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/942.html"},
		Repro: func(f Item) []string {
			return []string{"`curl -sI '" + f.Asset + "' | grep -i access-control` — " + f.Evidence}
		},
	},
	"graphql-sensitive-field": {
		Name: "GraphQL: campos de nome sensível no schema", CWE: "CWE-200",
		Description: "A introspection revela campos de query/mutation cujo nome sugere segredo/PII/privilégio (`password`, `token`, `ssn`, `session`, `credential`…).",
		Impact:      "Indicador de que dados sensíveis podem ser consultáveis. Confirme a autorização de cada campo; se algum retorna dados de outro usuário sem checagem, é IDOR/BOLA.",
		Remediation: "Revisar a autorização campo a campo (directive-based ou no resolver). Não expor campos que retornam segredos pela API GraphQL.",
		Refs:        []string{"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"},
		Repro:       genericRepro,
	},
	"graphql-dangerous-mutation": {
		Name: "GraphQL: mutations potencialmente perigosas", CWE: "CWE-284",
		Description: "O schema expõe mutations com nomes de operações destrutivas ou de privilégio (`delete*`, `impersonate*`, `*Role`, `makeAdmin`, `resetPassword`, `exec`…).",
		Impact:      "Se alguma dessas mutations não valida corretamente a autorização do chamador, permite escalada de privilégio, tomada de conta ou destruição de dados.",
		Remediation: "Auditar a autorização de cada mutation listada. Aplicar checagem de permissão no resolver, não só no gateway.",
		Refs:        []string{"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"},
		Repro:       genericRepro,
	},
	"graphql-error-leak": {
		Name: "GraphQL: vazamento em mensagens de erro", CWE: "CWE-209",
		Description: "As respostas de erro do endpoint GraphQL incluem rastro de implementação (stack trace, erro de SQL, caminhos de arquivo).",
		Impact:      "Revela stack tecnológica, estrutura de código e, às vezes, queries SQL — facilita ataques direcionados.",
		Remediation: "Em produção, retornar mensagens de erro genéricas e logar os detalhes no servidor. Desabilitar `debug`/`tracing`.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/209.html"},
		Repro:       genericRepro,
	},
	"actuator-endpoint": {
		Name: "Spring Boot Actuator: endpoint de gestão exposto", CWE: "CWE-200",
		Description: "Um endpoint do Actuator (`/beans`, `/mappings`, `/configprops`, `/loggers`, `/threaddump`, `/httptrace`…) está acessível sem autenticação.",
		Impact:      "Vazamento de configuração, rotas internas, dependências e, em `/httptrace`/`/httpexchanges`, de tokens de sessão de requisições recentes. `/loggers` permite alterar níveis de log em runtime.",
		Remediation: "Restringir `management.endpoints.web.exposure.include`, exigir autenticação e mover o Actuator para rede de gestão.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/200.html", "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security"},
		Repro:       func(f Item) []string { return []string{"`curl -s '" + f.Asset + "'` — " + f.Evidence} },
	},
	"actuator-jolokia": {
		Name: "Jolokia (JMX sobre HTTP) exposto", CWE: "CWE-284",
		Description: "O endpoint Jolokia está acessível sem autenticação, permitindo ler e — dependendo da config — escrever MBeans JMX via HTTP.",
		Impact:      "Leitura de estado interno da JVM; em cenários com MBeans perigosos (ex `createMBean` + MLet, Logback `JMXConfigurator`), leva a **RCE**.",
		Remediation: "Desabilitar o Jolokia ou protegê-lo com autenticação e uma policy restritiva de MBeans. Não expor à internet.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/284.html"},
		Repro: func(f Item) []string {
			return []string{"`curl -s '" + f.Asset + "/list'` — enumera os MBeans. " + f.Evidence}
		},
	},
	"actuator-index": {
		Name: "Spring Boot Actuator: índice exposto", CWE: "CWE-200",
		Description: "`/actuator` lista, sem autenticação, os endpoints de gestão disponíveis.",
		Impact:      "Facilita a descoberta de endpoints mais sensíveis (`/env`, `/heapdump`) que possam estar acessíveis.",
		Remediation: "Restringir a exposição do Actuator e exigir autenticação.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/200.html"},
		Repro:       func(f Item) []string { return []string{"`curl -s '" + f.Asset + "'` — lista os endpoints."} },
	},
	"mongodb-database-exposed": {
		Name: "MongoDB: banco legível sem autenticação", CWE: "CWE-306",
		Description: "Um banco não-sistema do MongoDB é enumerável (coleções listáveis) sem credenciais.",
		Impact:      "Leitura de todos os documentos das coleções. Exfiltração de dados de negócio/PII.",
		Remediation: "Habilitar autenticação e autorização no MongoDB, restringir `bindIp`, firewall.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/306.html", "https://www.mongodb.com/docs/manual/administration/security-checklist/"},
		Repro: func(f Item) []string {
			hp := strings.TrimPrefix(f.Asset, "mongodb://")
			return []string{"`mongosh '" + f.Asset + "' --eval 'db.getSiblingDB(\"" + lastSeg(hp) + "\").getCollectionNames()'` — lista as coleções sem senha. " + f.Evidence}
		},
	},
	"supabase-signup-enabled": {
		Name: "Supabase: cadastro de usuários aberto", CWE: "CWE-284",
		Description: "`/auth/v1/settings` indica `disable_signup: false` — qualquer pessoa pode criar conta.",
		Impact:      "Por si só nem sempre é vuln, mas combinado com RLS baseada em `authenticated` (em vez de checagem de dono) permite que um usuário recém-criado leia dados de outros. Também abre spam/abuse.",
		Remediation: "Desabilitar signup público se não for necessário, ou garantir que toda policy RLS valide o **dono** do registro, não apenas `auth.role() = 'authenticated'`.",
		Refs:        []string{"https://supabase.com/docs/guides/auth/row-level-security"},
		Repro:       genericRepro,
	},
	"cognito-open-signup": {
		Name: "AWS Cognito: SignUp anônimo habilitado", CWE: "CWE-284",
		Description: "O app client do User Pool aceita `SignUp` sem autenticação (revelado por um probe com senha inválida — nenhuma conta foi criada).",
		Impact:      "Registro de contas por qualquer pessoa. Relevante quando a autorização downstream confia em 'usuário autenticado' sem checagens adicionais.",
		Remediation: "Desabilitar auto-registro no app client se o cadastro deve ser controlado; exigir convite/verificação; validar autorização por recurso, não só por 'autenticado'.",
		Refs:        []string{"https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html"},
		Repro:       genericRepro,
	},
	"github-sensitive-file": {
		Name: "GitHub: arquivos de nome sensível em repo público", CWE: "CWE-538",
		Description: "Um repositório público da organização versiona arquivos cujo nome sugere segredo/config (`.env`, `*.pem`, `id_rsa`, `*.tfstate`, `serviceaccount*.json`…).",
		Impact:      "Potencial exposição de credenciais e estado de infraestrutura. Confirme o conteúdo de cada arquivo; mesmo removidos do HEAD, permanecem no histórico.",
		Remediation: "Remover do repo e do histórico; rotacionar qualquer segredo; adicionar `.gitignore` e secret scanning no CI.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/538.html"},
		Repro:       genericRepro,
	},
	"github-gist-secret": {
		Name: "GitHub: segredo em gist público", CWE: "CWE-798",
		Description: "Um gist público de um membro da organização contém uma credencial.",
		Impact:      "Acesso ao serviço correspondente.",
		Remediation: "Revogar/rotacionar. Remover o gist. Orientar sobre uso de gists para snippets sem segredos.",
		Refs:        []string{"https://cwe.mitre.org/data/definitions/798.html"},
		Repro:       genericRepro,
	},
	"github-self-hosted-runner": {
		Name: "GitHub Actions: runner self-hosted em repo (potencialmente) público", CWE: "CWE-284",
		Description: "Um workflow usa `runs-on: self-hosted`. Se o repositório for público, um PR de qualquer pessoa pode executar código no runner.",
		Impact:      "Execução de código no runner self-hosted: acesso à rede interna onde ele roda, persistência entre jobs (runners não-efêmeros), roubo de credenciais da máquina.",
		Remediation: "Usar runners hospedados pelo GitHub para repos públicos, ou runners **efêmeros e isolados**. Exigir aprovação para workflows de forks.",
		Refs:        []string{"https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security"},
		Repro:       genericRepro,
	},
	"cache-poisoning-likely": {
		Name: "Web cache poisoning (provável, não confirmado)", CWE: "CWE-444",
		Description: "Uma entrada não-chaveada é refletida numa resposta cacheável (`X-Cache`, `Age`, `s-maxage`…), mas a persistência no cache não foi confirmada nesta varredura.",
		Impact:      "Se a resposta refletida for de fato armazenada pelo cache compartilhado, o impacto é o de cache poisoning (XSS/redirect/DoS em massa). Requer confirmação manual.",
		Remediation: "Confirmar manualmente (enviar o header, depois requisitar limpo). Independente disso: incluir o input no cache key ou parar de refleti-lo.",
		Refs:        []string{"https://portswigger.net/research/practical-web-cache-poisoning"},
		Repro:       genericRepro,
	},
	"header-reflection": {
		Name: "Header de requisição refletido na resposta", CWE: "CWE-444",
		Description: "Um header controlável pelo cliente é refletido no corpo/headers da resposta, sem sinais claros de cache nesta varredura.",
		Impact:      "Base para cache poisoning se houver um cache compartilhado a montante que não chaveie por esse header; também pode habilitar host-header injection (reset de senha envenenado, links absolutos).",
		Remediation: "Não refletir headers não confiáveis. Construir URLs absolutas a partir de config, não do `Host`/`X-Forwarded-*`.",
		Refs:        []string{"https://portswigger.net/web-security/host-header"},
		Repro:       genericRepro,
	},
}

func init() {
	for k, v := range extra {
		templates[k] = v
	}
}

// prefixTemplates: only for genuinely homogeneous families where a blunt match
// is still accurate.
var prefixTemplates = []struct {
	prefix string
	t      tmpl
}{
	{"open-redirect", templates["open-redirect"]},
	{"ai-key-", templates["ai-key-exposed"]},
	{"dependency-confusion", templates["dependency-confusion"]},
}

// lookup returns the best template for a finding type.
func lookup(ftype string) (tmpl, bool) {
	if t, ok := templates[ftype]; ok {
		return t, true
	}
	for _, p := range prefixTemplates {
		if strings.HasPrefix(ftype, p.prefix) {
			return p.t, true
		}
	}
	return tmpl{}, false
}

func lastSeg(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return "admin"
}
