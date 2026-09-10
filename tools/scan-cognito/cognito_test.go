package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractIdentifiers(t *testing.T) {
	body := `
	const awsmobile = {
	  "aws_project_region": "eu-west-1",
	  "aws_cognito_identity_pool_id": "eu-west-1:11111111-2222-3333-4444-555555555555",
	  "aws_user_pools_id": "eu-west-1_AbCd1234X",
	  "aws_user_pools_web_client_id": "abcdefghij0123456789abcdef",
	  "endpoint": "https://cognito-idp.eu-west-1.amazonaws.com/"
	};`
	i := extractIdentifiers(body)
	if i.UserPoolID != "eu-west-1_AbCd1234X" {
		t.Errorf("user pool = %q", i.UserPoolID)
	}
	if i.IdentityPoolID != "eu-west-1:11111111-2222-3333-4444-555555555555" {
		t.Errorf("identity pool = %q", i.IdentityPoolID)
	}
	if len(i.AppClientIDs) != 1 || i.AppClientIDs[0] != "abcdefghij0123456789abcdef" {
		t.Errorf("client ids = %v", i.AppClientIDs)
	}
	if i.Region != "eu-west-1" {
		t.Errorf("region = %q", i.Region)
	}
}

func TestExtractIdentifiersLoose(t *testing.T) {
	body := `xhr.open("POST","https://cognito-identity.us-east-2.amazonaws.com/");
	         var pool = "us-east-2:deadbeef-0000-1111-2222-333344445555";`
	i := extractIdentifiers(body)
	if i.IdentityPoolID != "us-east-2:deadbeef-0000-1111-2222-333344445555" || i.Region != "us-east-2" {
		t.Errorf("%+v", i)
	}
	if !i.empty() == false {
		// has identity pool -> not empty
	}
}

func TestExtractEmpty(t *testing.T) {
	if !extractIdentifiers(`<html>nothing</html>`).empty() {
		t.Error("deveria ser empty()")
	}
}

func TestRegionOf(t *testing.T) {
	if regionOf("us-east-1_AbC123") != "us-east-1" {
		t.Error("user pool region")
	}
	if regionOf("ap-south-1:uuid-here") != "ap-south-1" {
		t.Error("identity pool region")
	}
	if regionOf("garbage") != "" {
		t.Error("garbage -> vazio")
	}
}

func TestClassifyGetId(t *testing.T) {
	if v := classifyGetId(200, `{"IdentityId":"us-east-1:abc"}`); v.kind != "open-identity-getid" {
		t.Errorf("%+v", v)
	}
	if v := classifyGetId(400, `{"__type":"ResourceNotFoundException","message":"x"}`); v.kind != "identity-absent" {
		t.Errorf("%+v", v)
	}
	if v := classifyGetId(400, `{"__type":"NotAuthorizedException"}`); v.kind != "identity-getid-denied" {
		t.Errorf("%+v", v)
	}
}

func TestClassifyGetCreds(t *testing.T) {
	ok := `{"Credentials":{"AccessKeyId":"ASIAXXXXXXXXXXXXXXXX","SecretKey":"s","SessionToken":"t"}}`
	v := classifyGetCreds(200, ok)
	if v.kind != "open-identity-credentials" || v.akid != "ASIAXXXXXXXXXXXXXXXX" {
		t.Errorf("%+v", v)
	}
	if v := classifyGetCreds(400, `{"__type":"InvalidIdentityPoolConfigurationException"}`); v.kind != "no-unauth-role" {
		t.Errorf("%+v", v)
	}
	if v := classifyGetCreds(403, `{"__type":"NotAuthorizedException"}`); v.kind != "credentials-denied" {
		t.Errorf("%+v", v)
	}
}

func TestSigV4STS(t *testing.T) {
	// smoke: the signer produces a well-formed Authorization header and parses
	// the XML response.
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/unauth/x</Arn><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`))
	}))
	defer srv.Close()

	// point the signer at the test server by overriding the transport host
	c := srv.Client()
	c.Transport = rewriteHost{srv.Listener.Addr().String(), c.Transport}

	arn, acct, err := stsCallerIdentity(c, tempCreds{AccessKeyID: "ASIA", SecretKey: "sk", SessionToken: "tok"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if acct != "123456789012" || arn == "" {
		t.Errorf("arn=%q acct=%q", arn, acct)
	}
	if gotAuth == "" || !contains(gotAuth, "AWS4-HMAC-SHA256 Credential=ASIA/") {
		t.Errorf("Authorization mal formado: %q", gotAuth)
	}
}

type rewriteHost struct {
	addr string
	base http.RoundTripper
}

func (rw rewriteHost) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = "http"
	r.URL.Host = rw.addr
	return rw.base.RoundTrip(r)
}

func contains(s, sub string) bool { return len(s) >= len(sub) && indexOf(s, sub) >= 0 }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
