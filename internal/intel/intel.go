// Package intel turns raw findings into a triage call: a 0–100 priority
// score and a concrete action ("reportar agora", "confirmar e reportar",
// "investigar quando der", "revisar em lote"). There is no trained model —
// the hub's core is deliberately zero-dependency Go stdlib, so intel is a
// transparent, deterministic scorer instead of a black box.
//
// Scoring blends two signals:
//
//  1. knownRisk — a built-in security knowledge base (below), keyed by the
//     same finding `Type` the report package already has templates for. It
//     encodes the same judgment a security-literate reviewer applies on
//     sight: a MongoDB open to the world or a validated AI key is critical
//     on its face; a bare open-redirect or CORS wildcard without credentials
//     is usually low-value noise. This is what makes a brand-new hub, with
//     zero operator triage yet, already able to say "isto é provavelmente
//     crítico" instead of shrugging at every finding equally.
//
//  2. operator feedback — every time a finding is marked confirmed or
//     false_positive (store.Finding.Triage, via POST /api/findings/{id}/triage),
//     it's folded into Stats, a frequency table keyed by (tool, type). The
//     built-in prior and the accumulated feedback are blended with a simple
//     Bayesian smoothing (see Assess): with little or no feedback yet, the
//     built-in knowledge carries the score; as real verdicts pile up for a
//     given tool+type pair, they increasingly override the built-in guess —
//     e.g. if *this* environment's "cors-wildcard" findings keep turning out
//     to matter, its effective score rises above the generic baseline, and
//     vice-versa. That's the "aprende cada vez mais" part, done with
//     arithmetic instead of a model.
package intel

import (
	"fmt"
	"strings"

	"reconhub/internal/store"
)

// Operator verdicts — the only values store.Finding.Triage should carry.
const (
	VerdictConfirmed     = "confirmed"
	VerdictFalsePositive = "false_positive"
	VerdictIgnored       = "ignored"
)

var validVerdicts = map[string]bool{
	VerdictConfirmed:     true,
	VerdictFalsePositive: true,
	VerdictIgnored:       true,
}

// ValidVerdict reports whether v is a verdict the API should accept.
func ValidVerdict(v string) bool { return validVerdicts[v] }

var severityWeight = map[string]int{
	"critical": 95,
	"high":     75,
	"medium":   50,
	"low":      25,
	"info":     10,
}

// priorSample is how many "pseudo-observations" the built-in prior counts as
// when blended with real operator feedback (Bayesian smoothing, see Assess).
// A tool+type pair needs roughly this many real verdicts before its own
// track record outweighs the built-in guess.
const priorSample = 4.0

// risk is the built-in, intrinsic judgment for one finding type — independent
// of any operator feedback.
type risk struct {
	Prior  float64 // 0-1: prior probability this type is a real, reportable issue
	Advice string  // short, type-specific nudge shown alongside the score
}

// knownRisk mirrors report/templates.go's type coverage — same keys, same
// "known finding types" boundary — but answers a different question:
// templates.go says what the finding *is*; knownRisk says how much to
// *trust* it before you've confirmed anything yourself.
var knownRisk = map[string]risk{
	"subdomain-takeover":                {0.90, "CNAME dangling com fingerprint batendo é quase sempre sequestrável — confirme registrando o recurso (ou provando que dá) antes de reportar."},
	"dangling-dns":                      {0.65, "dangling sem confirmação HTTP forte tem mais chance de já ter expirado/mudado — vale reverificar antes de reportar."},
	"broken-link-hijack":                {0.45, "valor varia muito com o contexto do link (rodapé genérico vs botão de login social) — confira onde ele aparece."},
	"open-bucket":                       {0.80, "LIST público quase sempre é reportável; olhe o conteúdo pra calibrar a severidade real."},
	"bucket-takeover":                   {0.85, "bucket referenciado mas inexistente é um sinal forte — poucas chances de falso positivo."},
	"secret":                            {0.45, "achado por padrão/entropia tem taxa de falso positivo real — valide a chave antes de reportar."},
	"ai-key-exposed":                    {0.55, "exposta mas não validada — confirme se ainda é uma chave ativa."},
	"ai-key-valid":                      {0.95, "validada como funcional (read-only) — crítico, sem necessidade de mais confirmação."},
	"cors-reflect-credentials":          {0.85, "reflexão de origem + credentials:true é um dos bugs de CORS mais sérios — confirme o impacto lendo um endpoint autenticado de verdade."},
	"cors-null-origin":                  {0.55, "Origin: null costuma exigir um vetor específico (iframe sandboxed, arquivo local) pra ser explorável — descreva o vetor no relatório."},
	"open-redirect":                     {0.30, "a maioria dos programas paga pouco ou nem aceita open redirect isolado — vale mais como parte de uma cadeia (ex: OAuth)."},
	"open-redirect-clientside":          {0.25, "redirect só no JS do cliente é ainda mais fácil de rejeitar — considere só se encadear com outra falha."},
	"graphql-introspection-enabled":     {0.25, "sozinho, quase sempre tratado como informativo — o valor real está no que a introspecção revela."},
	"graphql-get-enabled":               {0.40, "relevante principalmente se abrir CSRF em mutation sensível — confirme o cenário concreto."},
	"actuator-heapdump":                 {0.85, "heapdump baixável costuma carregar segredo — extraia e confira antes de fixar a severidade final."},
	"actuator-env":                      {0.70, "exposição de env vars é séria se houver credencial real nelas — confira o conteúdo antes de reportar como crítico."},
	"mongodb-no-auth":                   {0.95, "banco respondendo sem auth na rede é crítico por definição."},
	"mongodb-database-exposed":          {0.90, "listagem de bancos/coleções sem auth — crítico, mesmo só com nomes."},
	"open-cognito-identity-pool":        {0.85, "Identity Pool dando credencial AWS a anônimo é grave — confirme o escopo real dessa credencial (sts:GetCallerIdentity)."},
	"supabase-anon-table-read":          {0.70, "RLS ausente expõe a tabela inteira — o impacto real depende do que ela guarda."},
	"supabase-service-role-key-exposed": {0.95, "service_role key no cliente é acesso total ao banco — crítico, sem dúvida."},
	"supabase-signup-enabled":           {0.30, "geralmente informativo isolado — só relevante se combinado com outra falha de autorização."},
	"open-rtdb-read":                    {0.75, "leitura anônima liberada no Realtime Database é normalmente reportável — olhe se há PII."},
	"open-firestore-read":               {0.75, "mesma lógica do RTDB — confirme se há dado sensível pra definir o impacto."},
	"dependency-confusion":              {0.50, "confirme que o pacote realmente não existe no registro público antes de reportar — monorepos privados geram falso positivo com frequência."},
	"jwt-alg-none":                      {0.85, "alg:none aceito é falsificação de token quase garantida — crítico se confirmado no endpoint de verdade."},
	"jwt-weak-secret":                   {0.90, "segredo HMAC quebrado por wordlist é crítico — você já consegue forjar um token válido."},
	"jwt-no-exp":                        {0.30, "token sem expiração é relevante como higiene, raramente crítico sozinho."},
	"jwt-long-lived":                    {0.25, "vida longa isolada tem pouco apelo pra maioria dos programas."},
	"jwt-sensitive-claims":              {0.45, "depende do que exatamente está no claim — leia o payload antes de classificar a severidade."},
	"cache-poisoning":                   {0.55, "confirmado com 2ª requisição limpa é um sinal forte, mas o impacto varia muito por página afetada."},
	"cache-poisoning-likely":            {0.35, "ainda não confirmado com a 2ª requisição — trate como hipótese até verificar."},
	"exposed-service":                   {0.45, "exposição varia muito por serviço — confira se é algo que deveria mesmo estar público."},
	"sensitive-file-exposed":            {0.60, "depende do arquivo — .env/.pem pesa muito mais que um README interno."},
	"header-reflection":                 {0.30, "reflexão de header sozinha raramente é reportável — veja se abre poisoning ou outro efeito colateral."},
	"github-repo-secret":                {0.65, "segredo commitado é sério mesmo em repo antigo — confirme se a credencial ainda está ativa."},
	"github-sensitive-file":             {0.55, "presença do arquivo (.env, *.pem) já é um sinal — confirme o conteúdo antes de reportar."},
	"github-gist-secret":                {0.60, "gists públicos são fáceis de esquecer — confirme se a credencial segue válida."},
	"github-pwn-request":                {0.55, "pwn request é real se o workflow rodar em PR de fork sem aprovação — confirme o trigger exato."},
	"github-actions-injection":          {0.55, "injeção em `run:` via evento controlável pelo atacante é séria — confirme que o campo é editável por non-collaborator."},
	"github-self-hosted-runner":         {0.40, "risco depende de quem pode abrir PR nesse repo — confirme visibilidade e permissões antes de escalar."},
	"github-ambient-config-secret-risk": {0.35, "combinação de sinais (config ambiente + secrets.* + execução não confiável), não confirmação de exploração — confirme se a ferramenta de CLI usada no job realmente lê o destino desse arquivo de config antes de reportar como crítico."},
	"cors-reflect-origin":               {0.50, "reflexão sem credentials tem impacto bem menor — confirme o header Access-Control-Allow-Credentials."},
	"cors-wildcard":                     {0.20, "wildcard sem credentials é, no melhor caso, informativo — navegadores já limitam o abuso."},
	"cors-wildcard-credentials":         {0.60, "combinação estranha (a maioria dos navegadores rejeita `*` com credentials) — confirme que é mesmo isso que o servidor manda."},
	"graphql-sensitive-field":           {0.50, "depende de quão sensível é o campo exposto pelo schema — liste um exemplo concreto no relatório."},
	"graphql-dangerous-mutation":        {0.65, "mutation perigosa exposta sem auth vale a pena escalar — confirme se ela realmente executa sem token."},
	"graphql-error-leak":                {0.30, "stack trace em erro é normalmente informativo, salvo se vazar dado interno relevante."},
	"actuator-endpoint":                 {0.35, "exposição genérica do endpoint é informativa — o valor está no que cada endpoint específico revela."},
	"actuator-jolokia":                  {0.75, "Jolokia exposto costuma permitir RCE via MBean — trate como sério até provar o contrário."},
	"actuator-index":                    {0.20, "índice dos endpoints disponíveis, por si só, é só um mapa — quase sempre informativo."},
	"cognito-open-signup":               {0.25, "signup aberto é normal na maioria dos apps — só relevante combinado com outra falha."},
	"reflected-xss":                     {0.85, "\"<\" voltou sem escapar de verdade — injeção de tag confirmada por texto puro, sem navegador. Antes de reportar como crítico, confira CSP/httpOnly no cookie de sessão: eles não desfazem o bug, mas mudam o impacto real que você escreve no relatório."},
	"reflected-xss-attribute":           {0.40, "só a aspa quebrou, sem \"<\" — pode ser atributo explorável (se desprotegido) ou só um valor de texto solto sem risco. Abra a URL de verdade e confira o HTML ao redor do marcador antes de decidir a severidade."},
	"dom-xss":                           {0.92, "confirmado por EXECUÇÃO real num navegador (o onerror da <img> injetada disparou e setou uma propriedade JS com token aleatório), não por heurística de texto — praticamente sem falso positivo possível. Se o vetor foi \"hash\", lembre que o payload nunca chegou no servidor: não vai aparecer em log de acesso nem em WAF baseado em requisição, o que também significa que WAF de borda não protege esse caso — a correção tem que ser no JS do cliente. Mesmo caveat do reflected-xss pra impacto real: confira CSP e HttpOnly no cookie de sessão antes de escrever o relatório."},
	"sqli-error-based":                  {0.90, "erro real de banco vazado, confirmado por diferença contra o baseline sem payload — sinal forte, poucas chances de falso positivo. Ainda não prova quanto dá pra extrair (isso é SQLi cega/booleana, fora do escopo desta ferramenta) — descreva no relatório que a prova é vazamento de erro, não extração de dado."},
	"ssti":                              {0.90, "resultado calculado (não o payload cru) apareceu na resposta e sumiu no baseline — prova avaliação real de expressão no servidor, não reflexo tipo XSS. Motores de template sem sandbox (Jinja2/Twig/FreeMarker/Velocity/ERB sem restrição) costumam dar RCE a partir daqui — mas isso NÃO foi confirmado por esta ferramenta (só prova a avaliação da expressão matemática, nunca executa comando). Cite no relatório qual sintaxe de engine confirmou (`meta.engine`) — ajuda o time a saber onde procurar no código."},
	"idor-horizontal":                   {0.85, "confirmado contra o baseline legítimo do dono real (status+tamanho batendo), não só um 200 genérico — sinal forte. Ainda vale abrir a URL manualmente com a sessão cruzada pra confirmar que o conteúdo é mesmo do outro usuário antes de reportar."},
	"missing-rate-limiting":             {0.55, "ausência confirmada num número pequeno de tentativas não garante que não haja proteção mais adiante (ex: só depois de 20+ tentativas, ou por IP/dispositivo em vez de por conta) — rode mais tentativas manualmente antes de reportar como crítico, e descreva exatamente quantas tentativas foram feitas sem bloqueio."},
	"access-control-vertical":           {0.85, "confirmado contra o baseline legítimo da sessão admin (mesmo status 2xx + tamanho de corpo dentro da tolerância), não um 200 genérico — sinal forte de broken function level authorization. Ainda vale abrir a URL manualmente com a sessão de menor privilégio pra confirmar que o CONTEÚDO é mesmo a função admin (não uma página de 'sem permissão' que por acaso deu 200 do mesmo tamanho). Acesso anônimo (actor=anonymous) é mais grave que por sessão de baixo privilégio."},
	"path-traversal":                    {0.88, "leitura de arquivo de sistema confirmada por conteúdo real (root:x:0:0 do /etc/passwd ou marca do win.ini) ausente no baseline — sinal forte, pouco falso positivo. Prova que dá LER arquivo arbitrário; se a app também inclui o arquivo como código (LFI→RCE via log poisoning, wrapper php://, session), isso é o passo manual seguinte, não confirmado aqui. Cite no relatório qual variante de bypass (meta.payload) passou — diz que filtro o alvo tem."},
	"waf-detected":                      {0.05, "presença de WAF/CDN NÃO é vulnerabilidade — é contexto de metodologia (info). Serve pra explicar 403/429 que vêm da borda e não da aplicação: antes de concluir que um endpoint é seguro, lembre que o bloqueio pode ser o WAF, e ajuste encoding/rotação de circuito ao vendor identificado. Não reporte isto isolado; use pra calibrar os outros scanners."},
	"mass-assignment":                   {0.85, "o servidor bindou um campo privilegiado do corpo (valor sentinela aleatório voltou ligado à chave) enquanto IGNOROU um campo de controle bogus no mesmo corpo — não é eco cego, é bind seletivo real. A ferramenta NÃO escalou de verdade (mandou sentinela, nunca role=admin): o passo manual seguinte é confirmar o impacto setando o campo pra um valor de privilégio real (role=admin, is_admin=true, balance alto) com a conta de teste e ver se persiste/eleva. A severidade depende do campo (meta.field): role/is_admin/permissions é escalada de privilégio; verified/approved é quebra de confiança; balance/credit é fraude. Cite no relatório qual campo (meta.field) e o método (meta.method)."},
	"nosql-injection":                   {0.88, "operador NoSQL ($ne/$regex/$gt) foi interpretado pelo servidor — confirmado por diferencial booleano (operador sempre-verdadeiro divergiu de dois controles literais ESTÁVEIS), não por reflexo nem por string solta. Quando meta.vector=auth-bypass, o operador em username+password autenticou SEM credencial válida (critical — account takeover direto). Nos outros casos (meta.param/meta.field), prova que dá pra manipular a query: o passo manual seguinte é medir o alcance (listar registros de outros usuários via $ne, extrair por $regex char-a-char) — a ferramenta NÃO faz isso de propósito (seria extração/carga). Corrige com validação de tipo estrita no input (rejeitar objeto onde se espera string) e cast explícito antes de montar a query."},
}

// IsKnownType reports whether ftype is in the built-in knowledge base
// (knownRisk). Other packages (ex: guidance) usam isto pra garantir, em teste,
// que só referenciam finding types que o hub de fato reconhece — evita o bug
// de mapear uma chave inventada que nunca casa com o que as tools emitem.
func IsKnownType(ftype string) bool {
	_, ok := knownRisk[ftype]
	return ok
}

// riskFor looks up knownRisk by exact type, falling back to a neutral prior
// for anything not in the built-in knowledge base (same "unknown type, no
// opinion yet" honesty report.Build already applies to its own templates).
func riskFor(ftype string) risk {
	if r, ok := knownRisk[ftype]; ok {
		return r
	}
	return risk{Prior: 0.5, Advice: ""}
}

// minSample is how many of the operator's own verdicts a (tool, type) pair
// needs before its track record is shown as a first-class reason, separate
// from the Bayesian blend already folding it into the score.
const minSample = 3

// Stats is the accumulated triage track record for one (tool, type) pair.
type Stats struct {
	Confirmed     int `json:"confirmed"`
	FalsePositive int `json:"false_positive"`
	Ignored       int `json:"ignored"`
	Total         int `json:"total"`
}

// History maps "tool\x00type" -> Stats, built from every finding that has
// received operator feedback so far.
type History map[string]Stats

func historyKey(tool, typ string) string { return tool + "\x00" + typ }

// BuildHistory scans findings for operator feedback and aggregates it by
// (tool, type). Pass the widest set of findings available (not just the ones
// currently displayed) — more history means better-calibrated scores.
func BuildHistory(findings []*store.Finding) History {
	h := History{}
	for _, f := range findings {
		if f.Triage == "" {
			continue
		}
		k := historyKey(f.Tool, f.Type)
		s := h[k]
		s.Total++
		switch f.Triage {
		case VerdictConfirmed:
			s.Confirmed++
		case VerdictFalsePositive:
			s.FalsePositive++
		case VerdictIgnored:
			s.Ignored++
		}
		h[k] = s
	}
	return h
}

// Assessment is the triage call for one finding.
type Assessment struct {
	FindingID  string  `json:"finding_id"`
	Score      int     `json:"score"`            // 0-100, maior = mais urgente
	Action     string  `json:"action"`           // o que fazer, em uma frase
	Why        string  `json:"why"`              // base do score, curto e legível
	Advice     string  `json:"advice,omitempty"` // conhecimento específico do tipo, se houver
	Confidence float64 `json:"confidence"`       // 0-1: probabilidade estimada de ser um achado real/reportável
	SampleSize int     `json:"sample_size"`      // quantas triagens do operador embasam isso
}

// Assess scores one finding, blending the built-in knowledge base with
// accumulated operator feedback for this (tool, type) pair.
func Assess(f *store.Finding, h History) Assessment {
	sev := strings.ToLower(f.Severity)
	sevW, ok := severityWeight[sev]
	if !ok {
		sevW = 40
	}

	r := riskFor(f.Type)
	stats := h[historyKey(f.Tool, f.Type)]

	// Bayesian smoothing: o prior embutido conta como `priorSample`
	// observações "virtuais". Poucas triagens reais e o prior domina; muitas
	// triagens reais e o histórico do próprio operador assume o controle.
	conf := (r.Prior*priorSample + float64(stats.Confirmed)) / (priorSample + float64(stats.Total))

	// A pontuação combina severidade (o que a ferramenta mediu) com
	// confiança (o que se sabe — de fábrica ou aprendido — sobre esse tipo
	// costumar ser real). conf ∈ [0,1] escala o peso entre 50% e 150%.
	score := int(float64(sevW) * (0.5 + conf))

	// achado recorrente (mesma chave de dedup, count>1) pesa um pouco mais —
	// reapareceu em execuções diferentes, não foi um fluke de uma rodada só.
	if f.Count > 1 {
		bonus := f.Count - 1
		if bonus > 15 {
			bonus = 15
		}
		score += bonus / 3
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	why := fmt.Sprintf("severidade %s", sev)
	switch {
	case stats.Total >= minSample:
		why = fmt.Sprintf("severidade %s + seu histórico: %d/%d achados de %s/%s confirmados antes",
			sev, stats.Confirmed, stats.Total, f.Tool, f.Type)
	case stats.Total > 0:
		why = fmt.Sprintf("severidade %s + só %d triagem(ns) sua(s) desse tipo ainda (pouco pra pesar muito)",
			sev, stats.Total)
	default:
		if _, known := knownRisk[f.Type]; known {
			why = fmt.Sprintf("severidade %s + conhecimento prévio do tipo `%s`", sev, f.Type)
		}
	}

	return Assessment{
		FindingID:  f.ID,
		Score:      score,
		Action:     actionFor(score),
		Why:        why,
		Advice:     r.Advice,
		Confidence: conf,
		SampleSize: stats.Total,
	}
}

func actionFor(score int) string {
	switch {
	case score >= 80:
		return "reportar agora"
	case score >= 55:
		return "confirmar e reportar"
	case score >= 30:
		return "investigar quando der"
	default:
		return "revisar em lote / provável ruído"
	}
}

// AssessAll scores every finding in items against history and returns the
// assessments sorted score-descending.
func AssessAll(items []*store.Finding, h History) []Assessment {
	out := make([]Assessment, 0, len(items))
	for _, f := range items {
		out = append(out, Assess(f, h))
	}
	sortByScoreDesc(out)
	return out
}

func sortByScoreDesc(a []Assessment) {
	// insertion sort: N é o total de findings retornados por uma chamada da
	// API (tipicamente dezenas a centenas), então O(n²) não pesa.
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j].Score > a[j-1].Score; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
