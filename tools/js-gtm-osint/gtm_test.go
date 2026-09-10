package main

import (
	"reflect"
	"testing"
)

func TestExtractTrackingIDs(t *testing.T) {
	text := `
	gtag('config','G-ABC123DEF4');
	<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABCD12"></script>
	ga('create','UA-12345678-9','auto');
	gtag('config','AW-123456789');
	dupe GTM-ABCD12
	`
	ids := extractTrackingIDs(text)
	if !reflect.DeepEqual(ids["GTM"], []string{"GTM-ABCD12"}) {
		t.Errorf("GTM: %v", ids["GTM"])
	}
	if !reflect.DeepEqual(ids["GA4"], []string{"G-ABC123DEF4"}) {
		t.Errorf("GA4: %v", ids["GA4"])
	}
	if !reflect.DeepEqual(ids["UA"], []string{"UA-12345678-9"}) {
		t.Errorf("UA: %v", ids["UA"])
	}
	if !reflect.DeepEqual(ids["AW"], []string{"AW-123456789"}) {
		t.Errorf("AW: %v", ids["AW"])
	}
	flat := flatIDs(ids)
	if len(flat) != 4 {
		t.Errorf("flatIDs = %v", flat)
	}
}

func TestExtractJSONObject(t *testing.T) {
	s := `something "resource": {"version":"3","tags":[{"function":"__html","vtp_html":"<b>{}</b>"}]} trailing junk`
	got := extractJSONObject(s, `"resource":`)
	want := `{"version":"3","tags":[{"function":"__html","vtp_html":"<b>{}</b>"}]}`
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	if extractJSONObject("no marker here", `"resource":`) != "" {
		t.Error("marcador ausente -> vazio")
	}
	// string com chave de fechar escapada não deve quebrar o balanceamento
	s2 := `"resource": {"a":"}\"still in string{","b":1}`
	if extractJSONObject(s2, `"resource":`) != `{"a":"}\"still in string{","b":1}` {
		t.Errorf("balanceamento com string: %q", extractJSONObject(s2, `"resource":`))
	}
}

func TestParseContainer(t *testing.T) {
	js := `var data = {"resource":{"version":"42","macros":[{"function":"__u"}],"predicates":[{"function":"_eq"}],"tags":[
	  {"function":"__html","vtp_name":"Custom pixel","vtp_html":"<script>document.write('x')</script>"},
	  {"function":"__googtag"},
	  {"function":"__fbq"}
	],"rules":[[["if",0]]]}};`
	c := parseContainer(js)
	if !c.parsed {
		t.Fatal("não parseou")
	}
	if c.Version != "42" || len(c.Tags) != 3 || len(c.Macros) != 1 || len(c.Predicates) != 1 {
		t.Fatalf("container: %+v", c)
	}
	counts := c.tagTypeCounts()
	if counts["__html"] != 1 || counts["__fbq"] != 1 {
		t.Errorf("counts: %v", counts)
	}
	tags := c.tags()
	var custom *tagInfo
	for i := range tags {
		if tags[i].Function == "__html" {
			custom = &tags[i]
		}
	}
	if custom == nil || custom.Name != "Custom pixel" || custom.HTML == "" {
		t.Fatalf("custom html tag: %+v", custom)
	}
	if ok, why := interestingHTML(custom.HTML); !ok || why == "" {
		t.Errorf("document.write devia ser suspeito: %v %q", ok, why)
	}
}

func TestInterestingHTML(t *testing.T) {
	if ok, _ := interestingHTML(`<script src="https://www.googletagmanager.com/gtag/js"></script>`); ok {
		t.Error("script do google é confiável")
	}
	if ok, why := interestingHTML(`<script src="https://evil.tracker.xyz/a.js"></script>`); !ok || why == "" {
		t.Errorf("script externo desconhecido devia acender: %v", why)
	}
	if ok, _ := interestingHTML(`<img src="https://track.example/p.gif">`); ok {
		t.Error("pixel img simples não é suspeito")
	}
}

func TestScanContainerSecrets(t *testing.T) {
	text := `"vtp_url":"https://api.example.com/x?api_key=abcdef1234567890abcdef",
	         "key":"AIzaSyDCf1Gh2Jk3Lm4Np5Qr6St7Uv8Wx9Yz0Ab",
	         "other":"AIzaSyDplaceholder0000000000000000000000"`
	hits := scanContainerSecrets(text)
	var kinds []string
	for _, h := range hits {
		kinds = append(kinds, h.Kind)
	}
	if !contains(kinds, "google-api-key") || !contains(kinds, "url-embedded-key") {
		t.Errorf("kinds = %v", kinds)
	}
	for _, h := range hits {
		if h.Kind == "google-api-key" && len(h.Value) > 12 {
			t.Errorf("valor não redigido: %q", h.Value)
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
