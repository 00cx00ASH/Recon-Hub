package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// tempCreds are the temporary AWS credentials returned by Cognito.
type tempCreds struct {
	AccessKeyID  string `json:"AccessKeyId"`
	SecretKey    string `json:"SecretKey"`
	SessionToken string `json:"SessionToken"`
}

// stsCallerIdentity confirms the creds are live by calling sts:GetCallerIdentity
// (read-only) with SigV4. Returns the caller ARN and account id.
func stsCallerIdentity(c *http.Client, cr tempCreds) (arn, account string, err error) {
	const (
		region  = "us-east-1"
		service = "sts"
		host    = "sts.amazonaws.com"
	)
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	payloadHash := sha256hex(body)
	canonicalHeaders := "content-type:application/x-www-form-urlencoded; charset=utf-8\n" +
		"host:" + host + "\n" +
		"x-amz-date:" + amzDate + "\n" +
		"x-amz-security-token:" + cr.SessionToken + "\n"
	signedHeaders := "content-type;host;x-amz-date;x-amz-security-token"
	canonicalRequest := strings.Join([]string{
		"POST", "/", "", canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, sha256hex(canonicalRequest),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+cr.SecretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	authz := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		cr.AccessKeyID, scope, signedHeaders, signature)

	req, _ := http.NewRequest("POST", "https://"+host+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Security-Token", cr.SessionToken)
	req.Header.Set("Authorization", authz)

	resp, err := c.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("STS %d: %s", resp.StatusCode, strings.TrimSpace(firstLine(string(b))))
	}
	txt := string(b)
	return xmlTag(txt, "Arn"), xmlTag(txt, "Account"), nil
}

var reXMLTag = map[string]*regexp.Regexp{}

func xmlTag(body, tag string) string {
	re, ok := reXMLTag[tag]
	if !ok {
		re = regexp.MustCompile("<" + regexp.QuoteMeta(tag) + ">([^<]*)</" + regexp.QuoteMeta(tag) + ">")
		reXMLTag[tag] = re
	}
	if m := re.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// awsJSON POSTs a JSON body to an AWS JSON1.1 endpoint with the given target.
func awsJSON(c *http.Client, endpoint, target, jsonBody string) (int, string, error) {
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(jsonBody))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b), nil
}

func mustJSON(kv map[string]string) string {
	var sb strings.Builder
	sb.WriteByte('{')
	first := true
	for k, v := range kv {
		if !first {
			sb.WriteByte(',')
		}
		first = false
		sb.WriteString(`"` + k + `":` + quote(v))
	}
	sb.WriteByte('}')
	return sb.String()
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
