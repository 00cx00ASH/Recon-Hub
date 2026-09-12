package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

type JWTPayload struct {
	Exp int64  `json:"exp,omitempty"`
	Iat int64  `json:"iat,omitempty"`
	Sub string `json:"sub,omitempty"`
	Aud string `json:"aud,omitempty"`
	Iss string `json:"iss,omitempty"`
}

type Finding struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Evidence string `json:"evidence"`
	Triage   string `json:"triage"`
}

type Event struct {
	Event   string   `json:"event"`
	Finding *Finding `json:"finding,omitempty"`
}

func decodeJWT(tokenStr string) (map[string]interface{}, map[string]interface{}, string, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, nil, "", fmt.Errorf("JWT inválido: esperava 3 partes, recebeu %d", len(parts))
	}

	header := make(map[string]interface{})
	payload := make(map[string]interface{})

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", fmt.Errorf("falha ao decodificar header: %v", err)
	}

	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, "", fmt.Errorf("header não é JSON válido: %v", err)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", fmt.Errorf("falha ao decodificar payload: %v", err)
	}

	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, nil, "", fmt.Errorf("payload não é JSON válido: %v", err)
	}

	return header, payload, string(payloadJSON), nil
}

func checkAlgNone(header map[string]interface{}) *Finding {
	alg, ok := header["alg"].(string)
	if !ok {
		return nil
	}

	if strings.ToLower(alg) == "none" {
		return &Finding{
			Type:     "jwt-alg-none",
			Severity: "critical",
			Title:    "JWT com alg=none — assinatura não verificada",
			Evidence: "header.alg = 'none': o servidor não valida a assinatura. Qualquer pessoa pode falsificar um token válido removendo a parte de assinatura.",
			Triage:   "confirmed",
		}
	}
	return nil
}

func checkWeakAlg(header map[string]interface{}) *Finding {
	alg, ok := header["alg"].(string)
	if !ok {
		return nil
	}

	if strings.ToUpper(alg) == "HS256" || strings.ToUpper(alg) == "HS384" || strings.ToUpper(alg) == "HS512" {
		return &Finding{
			Type:     "jwt-weak-algorithm",
			Severity: "high",
			Title:    "JWT com algoritmo HMAC (HS256) — vulnerável a brute force de secret",
			Evidence: fmt.Sprintf("header.alg = '%s': usa HMAC (secret compartilhado) em vez de assimétrico (chave pública). Secret fraco é fácil de brute force.", alg),
			Triage:   "",
		}
	}
	return nil
}

func checkExpiry(payload map[string]interface{}) *Finding {
	expFloat, ok := payload["exp"].(float64)
	if !ok {
		return nil
	}

	expTime := time.Unix(int64(expFloat), 0)
	now := time.Now()

	if expTime.After(now.AddDate(0, 0, 30)) {
		daysRemaining := int(expTime.Sub(now).Hours() / 24)
		return &Finding{
			Type:     "jwt-long-expiry",
			Severity: "medium",
			Title:    fmt.Sprintf("JWT com expiração muito longa (%d dias)", daysRemaining),
			Evidence: fmt.Sprintf("exp = %d (expira em %s — %d dias a partir de agora). JWTs deveriam expirar em minutos/horas, não dias/meses.", int64(expFloat), expTime.Format("2006-01-02"), daysRemaining),
			Triage:   "",
		}
	}

	if expTime.Before(now) {
		return &Finding{
			Type:     "jwt-expired",
			Severity: "info",
			Title:    "JWT expirado",
			Evidence: fmt.Sprintf("exp = %d (expirou em %s). Token não é mais válido, mas interessante como histórico.", int64(expFloat), expTime.Format("2006-01-02 15:04:05")),
			Triage:   "confirmed",
		}
	}

	return nil
}

func checkKidInjection(header map[string]interface{}) *Finding {
	kid, ok := header["kid"].(string)
	if !ok || kid == "" {
		return nil
	}

	if len(kid) > 256 || strings.Contains(kid, "../") || strings.Contains(kid, "%00") {
		return &Finding{
			Type:     "jwt-kid-injection",
			Severity: "high",
			Title:    "JWT com kid suspeito — potencial path traversal ou null byte injection",
			Evidence: fmt.Sprintf("header.kid = '%s' parece malformado ou injeção (../,  %c%c). Alguns servidores usam kid diretamente em path/SQL sem validação.", kid, '%', '0'),
			Triage:   "",
		}
	}

	return nil
}

func checkCommonWeakSecrets(tokenStr string) *Finding {
	weakSecrets := []string{
		"secret", "password", "123456", "admin", "jwt",
		"test", "key", "12345678", "password123", "secret123",
		"token", "your-secret-key", "your-secret", "mysecret",
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil
	}

	for _, secret := range weakSecrets {
		token, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		})

		if err == nil && token.Valid {
			return &Finding{
				Type:     "jwt-weak-secret",
				Severity: "critical",
				Title:    "JWT com secret fraco descoberto",
				Evidence: fmt.Sprintf("secret descoberto: '%s'. Qualquer pessoa pode re-assinar o token e modificar claims.", secret),
				Triage:   "confirmed",
			}
		}
	}

	return nil
}

func analyzeJWT(tokenStr string) []Finding {
	var findings []Finding

	header, payload, _, err := decodeJWT(tokenStr)
	if err != nil {
		return findings
	}

	if f := checkAlgNone(header); f != nil {
		findings = append(findings, *f)
	}

	if f := checkWeakAlg(header); f != nil {
		findings = append(findings, *f)
	}

	if f := checkExpiry(payload); f != nil {
		findings = append(findings, *f)
	}

	if f := checkKidInjection(header); f != nil {
		findings = append(findings, *f)
	}

	if f := checkCommonWeakSecrets(tokenStr); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

func emitEvent(event string, finding *Finding) {
	e := Event{Event: event}
	if finding != nil {
		e.Finding = finding
	}
	data, _ := json.Marshal(e)
	fmt.Println(string(data))
}

func main() {
	token := os.Getenv("TOKEN")
	tokens := os.Getenv("TOKENS")
	tokensFile := os.Getenv("TOKENS_FILE")

	var tokenList []string

	if token != "" {
		tokenList = append(tokenList, token)
	} else if tokens != "" {
		scanner := bufio.NewScanner(strings.NewReader(tokens))
		for scanner.Scan() {
			t := strings.TrimSpace(scanner.Text())
			if t != "" {
				tokenList = append(tokenList, t)
			}
		}
	} else if tokensFile != "" {
		file, err := os.Open(tokensFile)
		if err != nil {
			emitEvent("error", nil)
			fmt.Fprintf(os.Stderr, "erro ao abrir arquivo: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			t := strings.TrimSpace(scanner.Text())
			if t != "" {
				tokenList = append(tokenList, t)
			}
		}
	}

	if len(tokenList) == 0 {
		emitEvent("error", nil)
		fmt.Fprintf(os.Stderr, "nenhum JWT fornecido\n")
		os.Exit(1)
	}

	emitEvent("start", nil)

	for _, t := range tokenList {
		findings := analyzeJWT(t)

		if len(findings) == 0 {
			emitEvent("notice", nil)
		} else {
			for _, f := range findings {
				emitEvent("finding", &f)
			}
		}
	}

	emitEvent("done", nil)
}
