package main

import (
	"sort"
	"testing"
)

func TestExtractBuckets(t *testing.T) {
	body := `
	<img src="https://assets-prod.s3.amazonaws.com/logo.png">
	<link href="https://cdn.example.com/app.css">
	fetch("https://s3.eu-west-1.amazonaws.com/legacy-uploads/x.json")
	var g = "https://storage.googleapis.com/company-backups/db.sql";
	azure = "https://acct01.blob.core.windows.net/pub/file";
	r2  = "https://media-cdn.r2.dev/v/1.mp4";
	spaces = "https://myspace.nyc3.digitaloceanspaces.com/a.zip";
	wasabi = "https://backups-2024.s3.us-east-1.wasabisys.com/x";
	b2 = "https://cdn-assets.s3.us-west-002.backblazeb2.com/y";
	oss = "https://static-cn.oss-cn-hangzhou.aliyuncs.com/z";
	notabucket = "https://www.s3.amazonaws.com/";
	`
	got := map[string]bool{}
	for _, b := range extractBuckets(body) {
		got[b.Provider+":"+b.Name] = true
	}
	want := []string{
		"aws-s3:assets-prod",
		"aws-s3:legacy-uploads",
		"gcs:company-backups",
		"azure-blob:acct01",
		"r2:media-cdn",
		"do-spaces:myspace",
		"wasabi:backups-2024",
		"backblaze:cdn-assets",
		"alibaba-oss:static-cn",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("faltou %q (got %v)", w, keys(got))
		}
	}
	if got["aws-s3:www"] {
		t.Error("www não deveria virar bucket")
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestValidBucketName(t *testing.T) {
	ok := []string{"assets-prod", "company.backups", "a1b2c3", "my_bucket_2024"}
	bad := []string{"", "ab", "s3", "www", "-lead", "trail-", "a..b", "com"}
	for _, n := range ok {
		if !validBucketName(n) {
			t.Errorf("%q deveria ser válido", n)
		}
	}
	for _, n := range bad {
		if validBucketName(n) {
			t.Errorf("%q deveria ser inválido", n)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		provider string
		status   int
		body     string
		want     string
	}{
		{"aws-s3", 200, `<?xml version="1.0"?><ListBucketResult><Name>x</Name></ListBucketResult>`, "open"},
		{"aws-s3", 403, `<Error><Code>AccessDenied</Code></Error>`, "private"},
		{"aws-s3", 404, `<Error><Code>NoSuchBucket</Code></Error>`, "missing"},
		{"aws-s3", 301, `<Error><Code>PermanentRedirect</Code></Error>`, "private"},
		{"aws-s3", 500, `boom`, "unknown"},
		{"gcs", 200, `<ListBucketResult><Name>x</Name></ListBucketResult>`, "open"},
		{"gcs", 403, `AccessDenied`, "private"},
		{"gcs", 404, `NoSuchBucket`, "missing"},
		{"azure-blob", 200, `<?xml version="1.0"?><EnumerationResults>`, "open"},
		{"azure-blob", 404, `The specified account does not exist.`, "missing"},
		{"r2", 200, `<ListBucketResult></ListBucketResult>`, "open"},
	}
	for _, c := range cases {
		if got := classify(c.provider, c.status, c.body); got.State != c.want {
			t.Errorf("classify(%s,%d) = %q, quer %q (%s)", c.provider, c.status, got.State, c.want, got.Detail)
		}
	}
}
