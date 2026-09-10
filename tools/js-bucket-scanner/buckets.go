package main

import (
	"fmt"
	"regexp"
	"strings"
)

// bucketRef is a cloud-storage bucket referenced somewhere in a page's assets.
type bucketRef struct {
	Provider string `json:"provider"` // aws-s3 | gcs | azure-blob | r2 | do-spaces
	Name     string `json:"name"`
	Region   string `json:"region,omitempty"`
}

func (b bucketRef) id() string { return b.Provider + "|" + b.Name }

// extractor pairs a compiled pattern with how to turn a match into a bucketRef.
type extractor struct {
	provider string
	re       *regexp.Regexp
	name     int // submatch index for the bucket name
	region   int // submatch index for the region (0 = none)
}

var extractors = []extractor{
	// bucket.s3.amazonaws.com / bucket.s3.eu-west-1.amazonaws.com / bucket.s3-eu-west-1.amazonaws.com
	{"aws-s3", regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-](?:([a-z0-9\-]+)\.)?amazonaws\.com`), 1, 2},
	// s3.amazonaws.com/bucket  /  s3-eu-west-1.amazonaws.com/bucket  /  s3.eu-west-1.amazonaws.com/bucket
	{"aws-s3", regexp.MustCompile(`(?i)\bs3[.\-](?:([a-z0-9\-]+)\.)?amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])`), 2, 1},
	// storage.googleapis.com/bucket  and  bucket.storage.googleapis.com
	{"gcs", regexp.MustCompile(`(?i)\bstorage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,220}[a-z0-9])`), 1, 0},
	{"gcs", regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9._\-]{1,220}[a-z0-9])\.storage\.googleapis\.com`), 1, 0},
	// account.blob.core.windows.net
	{"azure-blob", regexp.MustCompile(`(?i)\b([a-z0-9]{3,24})\.blob\.core\.windows\.net`), 1, 0},
	// bucket.r2.dev  and  <hash>.r2.cloudflarestorage.com
	{"r2", regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.r2\.dev`), 1, 0},
	{"r2", regexp.MustCompile(`(?i)\b([a-z0-9\-]+)\.([a-f0-9]{32})\.r2\.cloudflarestorage\.com`), 1, 0},
	// bucket.region.digitaloceanspaces.com  and  region.digitaloceanspaces.com/bucket
	{"do-spaces", regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.([a-z0-9\-]+)\.digitaloceanspaces\.com`), 1, 2},
	{"do-spaces", regexp.MustCompile(`(?i)\b([a-z0-9\-]+)\.digitaloceanspaces\.com/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])`), 2, 1},
	// Wasabi
	{"wasabi", regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3\.([a-z0-9\-]+)\.wasabisys\.com`), 1, 2},
	{"wasabi", regexp.MustCompile(`(?i)\bs3\.([a-z0-9\-]+)\.wasabisys\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])`), 2, 1},
	// Backblaze B2 (S3-compat)
	{"backblaze", regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3\.([a-z0-9\-]+)\.backblazeb2\.com`), 1, 2},
	{"backblaze", regexp.MustCompile(`(?i)\bs3\.([a-z0-9\-]+)\.backblazeb2\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])`), 2, 1},
	// Linode Object Storage
	{"linode", regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.([a-z0-9\-]+)\.linodeobjects\.com`), 1, 2},
	// Scaleway
	{"scaleway", regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3\.([a-z0-9\-]+)\.scw\.cloud`), 1, 2},
	// Alibaba OSS
	{"alibaba-oss", regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.oss-([a-z0-9\-]+)\.aliyuncs\.com`), 1, 2},
	// IBM Cloud Object Storage
	{"ibm-cos", regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3\.([a-z0-9\-]+)\.cloud-object-storage\.appdomain\.cloud`), 1, 2},
}

// bad names that the loose patterns pick up but are never real buckets.
var nameBlocklist = map[string]bool{
	"s3": true, "www": true, "static": true, "assets": true, "cdn": true,
	"storage": true, "blob": true, "com": true, "amazonaws": true,
}

// extractBuckets scans one body (HTML, JS or source map) for bucket references.
func extractBuckets(body string) []bucketRef {
	seen := map[string]bool{}
	var out []bucketRef
	for _, ex := range extractors {
		for _, m := range ex.re.FindAllStringSubmatch(body, -1) {
			name := strings.ToLower(strings.Trim(m[ex.name], ".-"))
			if !validBucketName(name) {
				continue
			}
			b := bucketRef{Provider: ex.provider, Name: name}
			if ex.region > 0 && ex.region < len(m) {
				b.Region = strings.ToLower(m[ex.region])
			}
			if !seen[b.id()] {
				seen[b.id()] = true
				out = append(out, b)
			}
		}
	}
	return out
}

func validBucketName(n string) bool {
	if len(n) < 3 || len(n) > 222 || nameBlocklist[n] {
		return false
	}
	if strings.Contains(n, "..") || strings.HasPrefix(n, "-") || strings.HasSuffix(n, "-") {
		return false
	}
	dots, alnum := 0, 0
	for _, r := range n {
		switch {
		case r == '.':
			dots++
		case r == '-' || r == '_':
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			alnum++
		default:
			return false
		}
	}
	// reject things that are just a domain-looking token with no bucket-ish part
	return alnum >= 3 && !(dots >= 1 && len(n) <= 6)
}

// --- probe classification (pure, testable) ---

type exposure struct {
	State  string // open | private | missing | unknown
	Detail string
}

func classifyS3(status int, body string) exposure {
	switch {
	case status == 200 && strings.Contains(body, "<ListBucketResult"):
		return exposure{"open", "LIST anônimo permitido (HTTP 200 + ListBucketResult)"}
	case strings.Contains(body, "NoSuchBucket"), status == 404:
		return exposure{"missing", "NoSuchBucket — referenciado mas não existe (candidato a takeover)"}
	case strings.Contains(body, "AccessDenied"), status == 403:
		return exposure{"private", "bucket existe, LIST negado (AccessDenied)"}
	case strings.Contains(body, "PermanentRedirect"), strings.Contains(body, "AuthorizationHeaderMalformed"), status == 301:
		return exposure{"private", "bucket existe (endpoint de região diferente)"}
	case strings.Contains(body, "AllAccessDisabled"):
		return exposure{"private", "bucket existe, acesso desabilitado"}
	}
	return exposure{"unknown", fmt.Sprintf("HTTP %d", status)}
}

func classifyGCS(status int, body string) exposure {
	switch {
	case status == 200 && (strings.Contains(body, "<ListBucketResult") || strings.Contains(body, "\"kind\": \"storage#objects\"")):
		return exposure{"open", "listagem pública (HTTP 200)"}
	case status == 403 || strings.Contains(body, "AccessDenied") || strings.Contains(body, "does not have storage.objects.list"):
		return exposure{"private", "bucket existe, listagem negada"}
	case status == 404 || strings.Contains(body, "NoSuchBucket") || strings.Contains(body, "\"code\": 404"):
		return exposure{"missing", "bucket não existe"}
	}
	return exposure{"unknown", fmt.Sprintf("HTTP %d", status)}
}

func classifyAzure(status int, body string) exposure {
	switch {
	case status == 200 && strings.Contains(body, "<EnumerationResults"):
		return exposure{"open", "container público (EnumerationResults)"}
	case status == 403 || strings.Contains(body, "PublicAccessNotPermitted") || strings.Contains(body, "ResourceNotFound") && status == 403:
		return exposure{"private", "conta existe, acesso público desativado"}
	case status == 404 || strings.Contains(body, "The specified account does not exist"):
		return exposure{"missing", "conta de storage não existe"}
	}
	return exposure{"unknown", fmt.Sprintf("HTTP %d", status)}
}

func classify(provider string, status int, body string) exposure {
	switch provider {
	case "gcs":
		return classifyGCS(status, body)
	case "azure-blob":
		return classifyAzure(status, body)
	default: // aws-s3, r2, do-spaces all speak the S3 protocol
		return classifyS3(status, body)
	}
}
