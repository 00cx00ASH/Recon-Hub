package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

type ResponseDiff struct {
	StatusCode int
	BodyLen    int
	BodyHash   string
}

func emitEvent(event string, finding *Finding) {
	e := Event{Event: event}
	if finding != nil {
		e.Finding = finding
	}
	data, _ := json.Marshal(e)
	fmt.Println(string(data))
}

func hashBody(body []byte) string {
	sum := 0
	for _, b := range body {
		sum += int(b)
	}
	return fmt.Sprintf("%d", sum)
}

func testRaceCondition(baseURL string, concurrency int, timeout time.Duration) *Finding {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Track responses
	responseDiffs := make(map[string]int)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var failedReqs atomic.Int32

	// Send concurrent requests
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			req, _ := http.NewRequest("GET", baseURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := client.Do(req)
			if err != nil {
				failedReqs.Add(1)
				return
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))
			resp.Body.Close()

			diff := fmt.Sprintf("%d_%d", resp.StatusCode, len(body))

			mu.Lock()
			responseDiffs[diff]++
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// Analyze results
	if len(responseDiffs) <= 1 {
		return nil // No race condition detected, all responses same
	}

	// Different responses detected
	evidence := fmt.Sprintf("Enviadas %d requisições concorrentes; respostas variaram: ", concurrency)
	for diff, count := range responseDiffs {
		evidence += fmt.Sprintf("%s (x%d), ", diff, count)
	}

	severity := "medium"
	if len(responseDiffs) > 3 {
		severity = "high"
	}

	return &Finding{
		Type:     "race-condition-detected",
		Severity: severity,
		Title:    "Potencial race condition — respostas não-determinísticas",
		Evidence: evidence + fmt.Sprintf("Falhas: %d. Race condition pode permitir state inconsistency, double-spend, ou authorization bypass.", failedReqs.Load()),
		Triage:   "",
	}
}

func main() {
	target := os.Getenv("TARGET")
	urls := os.Getenv("URLS")
	urlsFile := os.Getenv("URLS_FILE")
	timeoutMs := os.Getenv("TIMEOUT_MS")
	concurrencyStr := os.Getenv("CONCURRENCY")

	if timeoutMs == "" {
		timeoutMs = "2000"
	}
	if concurrencyStr == "" {
		concurrencyStr = "20"
	}

	var timeoutInt int
	var concurrency int
	fmt.Sscanf(timeoutMs, "%d", &timeoutInt)
	fmt.Sscanf(concurrencyStr, "%d", &concurrency)
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
	sem := make(chan struct{}, 3)

	for _, u := range urlList {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			finding := testRaceCondition(url, concurrency, timeout)
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
