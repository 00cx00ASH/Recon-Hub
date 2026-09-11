package main

import (
	"math"
	"regexp"
	"strings"
)

// aiPattern matches one AI/ML provider credential.
type aiPattern struct {
	Provider string
	Severity string // high | critical | medium
	Re       *regexp.Regexp
	Group    int
	Entropy  float64 // min Shannon bits/char for the captured value (0 = skip)
	// Validate names how to check the key is live (see validate.go). "" = none.
	Validate string
}

// patterns — curated, case-sensitive (keys have fixed alphabets).
var patterns = []aiPattern{
	{"OpenAI", "high", regexp.MustCompile(`\b(sk-proj-[A-Za-z0-9_-]{40,})`), 1, 0, "openai"},
	{"OpenAI (legacy)", "high", regexp.MustCompile(`\b(sk-[A-Za-z0-9]{48,})\b`), 1, 3.2, "openai"},
	{"OpenAI Org", "medium", regexp.MustCompile(`\b(org-[A-Za-z0-9]{20,})\b`), 1, 0, ""},
	{"Anthropic", "critical", regexp.MustCompile(`\b(sk-ant-api03-[A-Za-z0-9_-]{80,})`), 1, 0, "anthropic"},
	{"Anthropic (generic)", "high", regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_-]{20,})`), 1, 0, "anthropic"},
	{"Groq", "high", regexp.MustCompile(`\b(gsk_[A-Za-z0-9]{40,})\b`), 1, 0, "openai-compat:https://api.groq.com/openai"},
	{"Mistral", "high", regexp.MustCompile(`(?i)mistral[._-]?api[._-]?key["'\s:=]+([A-Za-z0-9]{32})\b`), 1, 3.2, ""},
	{"Perplexity", "high", regexp.MustCompile(`\b(pplx-[A-Za-z0-9]{32,})\b`), 1, 0, "openai-compat:https://api.perplexity.ai"},
	{"Replicate", "high", regexp.MustCompile(`\b(r8_[A-Za-z0-9]{37,})\b`), 1, 0, "replicate"},
	{"HuggingFace", "high", regexp.MustCompile(`\b(hf_[A-Za-z0-9]{34,})\b`), 1, 0, "huggingface"},
	{"OpenRouter", "high", regexp.MustCompile(`\b(sk-or-v1-[a-f0-9]{64})\b`), 1, 0, "openai-compat:https://openrouter.ai/api"},
	{"Together AI", "high", regexp.MustCompile(`(?i)together[._-]?api[._-]?key["'\s:=]+([a-f0-9]{64})\b`), 1, 0, "openai-compat:https://api.together.xyz"},
	{"Fireworks AI", "high", regexp.MustCompile(`\b(fw_[A-Za-z0-9]{24,})\b`), 1, 0, "openai-compat:https://api.fireworks.ai/inference"},
	{"Cohere", "high", regexp.MustCompile(`(?i)cohere[._-]?api[._-]?key["'\s:=]+([A-Za-z0-9]{40})\b`), 1, 3.2, ""},
	// "AIza..." is the shared format for every Google Cloud API key (Maps,
	// Firebase Web config, Identity Toolkit, YouTube Data API, Generative
	// Language/Gemini...) — the format alone never proves it's a Gemini key,
	// only Validate (a real GET against the Generative Language API) does.
	// Labeled honestly as "unconfirmed product" until that check runs.
	{"Google API Key (AIza, produto não confirmado)", "high", regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`), 1, 0, "google-ai"},
	{"Azure OpenAI endpoint", "medium", regexp.MustCompile(`\b(https://[a-z0-9-]+\.openai\.azure\.com)\b`), 1, 0, ""},
	{"ElevenLabs", "high", regexp.MustCompile(`(?i)(?:elevenlabs|xi-api-key)["'\s:=]+([a-f0-9]{32})\b`), 1, 3.0, "elevenlabs"},
	{"AssemblyAI", "high", regexp.MustCompile(`(?i)assemblyai["'\s:=]+([a-f0-9]{32})\b`), 1, 3.0, ""},
	{"Deepgram", "high", regexp.MustCompile(`(?i)deepgram["'\s:=]+([a-f0-9]{40})\b`), 1, 3.0, "deepgram"},
	{"LangSmith", "high", regexp.MustCompile(`\b(lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10})\b`), 1, 0, ""},
	{"LangChain (legacy)", "high", regexp.MustCompile(`\b(ls__[a-f0-9]{32})\b`), 1, 0, ""},
	// A Pinecone key IS shaped like a bare UUID — but so is a session id, a
	// tracking id, a build hash, a request id... anything. Without requiring
	// "pinecone" nearby, this matches essentially any UUID in any bundle.
	{"Pinecone", "high", regexp.MustCompile(`(?i)pinecone[\s\S]{0,60}?\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`), 1, 0, ""},
	{"Weights & Biases", "medium", regexp.MustCompile(`(?i)wandb[._-]?api[._-]?key["'\s:=]+([a-f0-9]{40})\b`), 1, 3.2, ""},
	{"Stability AI", "high", regexp.MustCompile(`\b(sk-[A-Za-z0-9]{48})\b`), 1, 3.2, ""},
	{"Clarifai", "medium", regexp.MustCompile(`(?i)clarifai[._-]?pat["'\s:=]+([a-f0-9]{32})\b`), 1, 3.0, ""},
	{"Hugging Face endpoint", "medium", regexp.MustCompile(`\b(https://[a-z0-9-]+\.(?:endpoints\.huggingface\.cloud|aws\.endpoints\.huggingface\.cloud))\b`), 1, 0, ""},
	{"GCP service account (Vertex)", "critical", regexp.MustCompile(`"type"\s*:\s*"service_account"[\s\S]{0,400}?"private_key"`), 0, 0, ""},
	{"AWS key (Bedrock/SageMaker)", "high", regexp.MustCompile(`\b((?:AKIA|ASIA)[A-Z0-9]{16})\b`), 1, 0, ""},
}

// hit is one credential occurrence.
type hit struct {
	Provider string
	Severity string
	Value    string // raw (used for validation); redacted before emit
	Validate string
}

// scan runs every pattern over body and returns deduped hits. Patterns are
// ordered specific→generic, so the first pattern to claim a value wins (a
// generic `sk-ant-` won't re-report a value already caught as `sk-ant-api03-`).
func scan(body string, minLen int) []hit {
	claimed := map[string]bool{}
	var out []hit
	for _, p := range patterns {
		for _, m := range p.Re.FindAllStringSubmatch(body, -1) {
			v := m[0]
			if p.Group < len(m) {
				v = m[p.Group]
			}
			if len(v) < minLen || claimed[v] {
				continue
			}
			if p.Entropy > 0 && shannon(v) < p.Entropy {
				continue
			}
			if looksPlaceholder(v) {
				continue
			}
			claimed[v] = true
			out = append(out, hit{p.Provider, p.Severity, v, p.Validate})
		}
	}
	return out
}

var placeholderWords = []string{
	"example", "your_", "your-", "xxxx", "0000", "changeme", "placeholder",
	"dummy", "test123", "sk-xxx", "abcdef", "123456", "redacted", "insert",
	"<your", "notreal", "sample", "fake",
}

func looksPlaceholder(v string) bool {
	l := strings.ToLower(v)
	for _, w := range placeholderWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	// all one character
	if len(v) > 6 {
		allSame := true
		for i := 1; i < len(v); i++ {
			if v[i] != v[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}
	return false
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

func redact(s string) string {
	if len(s) <= 10 {
		return "***"
	}
	return s[:4] + "…" + s[len(s)-4:]
}
