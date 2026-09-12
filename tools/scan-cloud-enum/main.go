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

var filePaths = map[string]string{
	"/.env":                  "env-file",
	"/.env.local":            "env-file",
	"/.env.example":          "env-example",
	"/.env.production":       "env-file",
	"/.env.staging":          "env-file",
	"/Dockerfile":            "docker-file",
	"/docker-compose.yml":    "docker-compose",
	"/docker-compose.yaml":   "docker-compose",
	"/.dockerignore":         "docker-ignore",
	"/.git/config":           "git-config",
	"/.git/HEAD":             "git-head",
	"/.gitignore":            "gitignore",
	"/terraform.tfstate":     "terraform-state",
	"/.terraform.lock.hcl":   "terraform-lock",
	"/package.json":          "package-json",
	"/pom.xml":               "pom-xml",
	"/requirements.txt":      "requirements-txt",
	"/config/database.yml":   "config-database",
	"/.aws/credentials":      "aws-credentials",
	"/.aws/config":           "aws-config",
	"/.gcp/credentials.json": "gcp-credentials",
	"/.ssh/config":           "ssh-config",
	"/web.config":            "web-config",
	"/.htaccess":             "htaccess",
	"/config.php":            "config-php",
}

func emitEvent(event string, finding *Finding) {
	e := Event{Event: event}
	if finding != nil {
		e.Finding = finding
	}
	data, _ := json.Marshal(e)
	fmt.Println(string(data))
}

func testFile(baseURL, filePath string, timeout time.Duration) *Finding {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	fileURL := u.Scheme + "://" + u.Host + filePath

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, _ := http.NewRequest("GET", fileURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))
	content := string(body)

	fileType := filePaths[filePath]
	severity := "high"
	if fileType == "env-example" {
		severity = "medium"
	}

	evidence := content
	if len(evidence) > 100 {
		evidence = evidence[:100] + "..."
	}

	if strings.Contains(strings.ToLower(content), "password") ||
		strings.Contains(strings.ToLower(content), "secret") ||
		strings.Contains(strings.ToLower(content), "key=") ||
		strings.Contains(strings.ToLower(content), "credentials") {
		severity = "critical"
	}

	return &Finding{
		Type:     "cloud-config-exposed",
		Severity: severity,
		Title:    fmt.Sprintf("Arquivo sensível exposto: %s", filePath),
		Evidence: fmt.Sprintf("GET %s retornou 200 com conteúdo: %s", fileURL, evidence),
		Triage:   "confirmed",
	}
}

func testURL(baseURL string, timeout time.Duration) []Finding {
	var findings []Finding

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 10)

	for filePath := range filePaths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			finding := testFile(baseURL, path, timeout)
			if finding != nil {
				mu.Lock()
				findings = append(findings, *finding)
				mu.Unlock()
			}
		}(filePath)
	}

	wg.Wait()
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

	for _, u := range urlList {
		findings := testURL(u, timeout)
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
