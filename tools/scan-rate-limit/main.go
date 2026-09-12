package main

import (
	"bufio"
	"encoding/json"
	"fmt"
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

func emitEvent(event string, finding *Finding) {
	e := Event{Event: event}
	if finding != nil {
		e.Finding = finding
	}
	data, _ := json.Marshal(e)
	fmt.Println(string(data))
}

type RateLimitInfo struct {
	Limit      int
	Remaining  int
	Reset      int
	RetryAfter int
	IsLimited  bool
}

func extractRateLimitHeaders(resp *http.Response) RateLimitInfo {
	info := RateLimitInfo{}

	// Check common rate limit headers
	if val := resp.Header.Get("X-RateLimit-Limit"); val != "" {
		fmt.Sscanf(val, "%d", &info.Limit)
	}
	if val := resp.Header.Get("RateLimit-Limit"); val != "" {
		fmt.Sscanf(val, "%d", &info.Limit)
	}

	if val := resp.Header.Get("X-RateLimit-Remaining"); val != "" {
		fmt.Sscanf(val, "%d", &info.Remaining)
	}
	if val := resp.Header.Get("RateLimit-Remaining"); val != "" {
		fmt.Sscanf(val, "%d", &info.Remaining)
	}

	if val := resp.Header.Get("X-RateLimit-Reset"); val != "" {
		fmt.Sscanf(val, "%d", &info.Reset)
	}
	if val := resp.Header.Get("RateLimit-Reset"); val != "" {
		fmt.Sscanf(val, "%d", &info.Reset)
	}

	if val := resp.Header.Get("Retry-After"); val != "" {
		fmt.Sscanf(val, "%d", &info.RetryAfter)
	}

	if resp.StatusCode == 429 || resp.StatusCode == 503 {
		info.IsLimited = true
	}

	return info
}

func testRateLimit(baseURL string, requests int, timeout time.Duration) *Finding {
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

	limitFound := false
	firstLimit := 0
	limitHeaders := ""

	// Send multiple rapid requests
	for i := 0; i < requests; i++ {
		req, _ := http.NewRequest("GET", baseURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		rlInfo := extractRateLimitHeaders(resp)

		if rlInfo.IsLimited || rlInfo.Limit > 0 {
			limitFound = true
			if firstLimit == 0 && rlInfo.Limit > 0 {
				firstLimit = rlInfo.Limit
			}

			limitHeaders = fmt.Sprintf("X-RateLimit-Limit: %d, X-RateLimit-Remaining: %d, X-RateLimit-Reset: %d, Retry-After: %d",
				rlInfo.Limit, rlInfo.Remaining, rlInfo.Reset, rlInfo.RetryAfter)
		}

		resp.Body.Close()
	}

	if !limitFound {
		return nil
	}

	severity := "info"
	if firstLimit < 100 {
		severity = "medium"
	}
	if firstLimit < 10 {
		severity = "high"
	}

	return &Finding{
		Type:     "rate-limit-detected",
		Severity: severity,
		Title:    fmt.Sprintf("Rate limit detectado: %d req/window", firstLimit),
		Evidence: fmt.Sprintf("Após %d requisições rápidas, endpoint respondeu com rate limit. Headers: %s. Endpoint pode estar sob proteção de brute force.", requests, limitHeaders),
		Triage:   "confirmed",
	}
}

func main() {
	target := os.Getenv("TARGET")
	urls := os.Getenv("URLS")
	urlsFile := os.Getenv("URLS_FILE")
	timeoutMs := os.Getenv("TIMEOUT_MS")
	requestsStr := os.Getenv("REQUESTS")

	if timeoutMs == "" {
		timeoutMs = "2000"
	}
	if requestsStr == "" {
		requestsStr = "15"
	}

	var timeoutInt int
	var requests int
	fmt.Sscanf(timeoutMs, "%d", &timeoutInt)
	fmt.Sscanf(requestsStr, "%d", &requests)
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

			finding := testRateLimit(url, requests, timeout)
			mu.Lock()
			if finding == nil {
				emitEvent("notice", nil)
			} else {
				emitEvent("finding", finding)
			}
			mu.Unlock()
		}(u)
	}

	wg.Wait()
	emitEvent("done", nil)
}
