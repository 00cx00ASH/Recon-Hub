package main

import (
	"fmt"
	"math"
	"strings"
)

// attemptResult holds only DERIVED signals from one login attempt — never
// the raw response body. blockKeyword is the single matched keyword (e.g.
// "captcha"), not the surrounding text, so nothing from a real response body
// ends up stored or emitted.
type attemptResult struct {
	idx          int
	status       int
	length       int
	latencyMs    int64
	retryAfter   bool
	blockKeyword string
}

// verdict is the outcome of classifying a sequence of attempts.
type verdict struct {
	blocked   bool
	reason    string
	atAttempt int
}

// blockKeywords are checked case-insensitively against the response body.
// Kept short and specific to avoid matching normal "invalid credentials"
// copy, which would falsely read as a protection signal.
var blockKeywords = []string{
	"captcha", "too many attempts", "too many requests", "muitas tentativas",
	"temporarily locked", "temporarily disabled", "account locked",
	"conta bloqueada", "try again later", "tente novamente mais tarde",
	"rate limit", "access temporarily restricted",
}

func findBlockKeyword(bodyLower string) string {
	for _, kw := range blockKeywords {
		if strings.Contains(bodyLower, kw) {
			return kw
		}
	}
	return ""
}

// classifyAttempts looks for ANY signal, across the whole sequence so far,
// that the target is throttling/blocking repeated failed attempts:
//
//  1. an explicit 429 or Retry-After on any attempt (checked from attempt 1 —
//     no need to wait for drift if the very first attempt is already throttled)
//  2. a block/CAPTCHA/lockout keyword in the response body
//  3. the HTTP status drifting away from the first attempt's status
//  4. the response body length drifting more than lengthTolerancePct from
//     the first attempt's length (a swapped-in CAPTCHA/error page)
//  5. latency on a later attempt growing past latencyMult× the first
//     attempt's latency (progressive-delay throttling, never a hard block)
//
// Any one of these means "a protection exists" — classifyAttempts stops at
// the first attempt where it can say so. Returning blocked:false only after
// ALL attempts in the slice cleared every check means none of them found a
// protection, which is itself the finding: absence of rate limiting.
func classifyAttempts(results []attemptResult, lengthTolerancePct, latencyMult float64) verdict {
	if len(results) == 0 {
		return verdict{}
	}
	baseline := results[0]
	for i, r := range results {
		if r.status == 429 {
			return verdict{true, fmt.Sprintf("status 429 na tentativa %d", r.idx), r.idx}
		}
		if r.retryAfter {
			return verdict{true, fmt.Sprintf("header Retry-After presente na tentativa %d", r.idx), r.idx}
		}
		if r.blockKeyword != "" {
			return verdict{true, fmt.Sprintf("resposta da tentativa %d contém sinal de bloqueio (%q)", r.idx, r.blockKeyword), r.idx}
		}
		if i == 0 {
			continue
		}
		if r.status != baseline.status {
			return verdict{true, fmt.Sprintf("status mudou de %d (tentativa 1) para %d (tentativa %d)", baseline.status, r.status, r.idx), r.idx}
		}
		if baseline.length > 0 {
			delta := math.Abs(float64(r.length-baseline.length)) / float64(baseline.length) * 100
			if delta > lengthTolerancePct {
				return verdict{true, fmt.Sprintf("tamanho da resposta mudou %.1f%% da tentativa 1 (%d bytes) para a tentativa %d (%d bytes) — possível página de captcha/bloqueio", delta, baseline.length, r.idx, r.length), r.idx}
			}
		}
		if baseline.latencyMs > 20 && float64(r.latencyMs) > float64(baseline.latencyMs)*latencyMult {
			return verdict{true, fmt.Sprintf("latência da tentativa %d (%dms) é %.1fx maior que a da tentativa 1 (%dms) — possível rate limiting por atraso progressivo", r.idx, r.latencyMs, float64(r.latencyMs)/float64(baseline.latencyMs), baseline.latencyMs), r.idx}
		}
	}
	return verdict{blocked: false}
}
