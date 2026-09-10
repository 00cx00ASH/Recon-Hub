package main

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		status   int
		ctype    string
		body     string
		wantKind string
		wantSev  string
		wantHit  bool
	}{
		{"heapdump octet", "actuator/heapdump", 200, "application/octet-stream", "JAVA PROFILE 1.0.2", "actuator-heapdump", "critical", true},
		{"heapdump gzip", "heapdump", 200, "application/vnd.spring-boot.actuator.v3+json", "\x1f\x8b\x08\x00", "actuator-heapdump", "critical", true},
		{"heapdump html 404-page", "actuator/heapdump", 200, "text/html", "<html>not found</html>", "", "", false},
		{"env plain", "actuator/env", 200, "application/json", `{"activeProfiles":["prod"],"propertySources":[]}`, "actuator-env", "high", true},
		{"env with secret", "env", 200, "application/json", `{"propertySources":[{"name":"x","properties":{"db.password":{"value":"***"}}}]}`, "actuator-env", "critical", true},
		{"actuator index", "actuator", 200, "application/json", `{"_links":{"self":{"href":"/actuator"},"env":{}}}`, "actuator-index", "medium", true},
		{"jolokia", "jolokia/list", 200, "application/json", `{"request":{},"value":{},"agent":"1.6.0"}`, "actuator-jolokia", "high", true},
		{"beans", "actuator/beans", 200, "application/json", `{"contexts":{"application":{"beans":{}}}}`, "actuator-endpoint", "medium", true},
		{"health basic", "actuator/health", 200, "application/json", `{"status":"UP"}`, "", "", false},
		{"health detailed", "health", 200, "application/json", `{"status":"UP","components":{"db":{"status":"UP"}}}`, "actuator-endpoint", "low", true},
		{"non-200", "actuator/env", 401, "application/json", `{}`, "", "", false},
		{"random 200 html", "actuator/beans", 200, "text/html", "<html><body>Login</body></html>", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, hit := classify(c.path, c.status, c.ctype, c.body)
			if hit != c.wantHit {
				t.Fatalf("hit=%v, quer %v (%+v)", hit, c.wantHit, v)
			}
			if hit && (v.kind != c.wantKind || v.severity != c.wantSev) {
				t.Fatalf("kind/sev = %s/%s, quer %s/%s", v.kind, v.severity, c.wantKind, c.wantSev)
			}
		})
	}
}
