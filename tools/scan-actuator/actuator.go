package main

import "strings"

// endpoints to probe. prefixed = /actuator/<x>, also tried bare (Boot 1.x).
var probePaths = []string{
	"actuator", "actuator/env", "actuator/health", "actuator/info",
	"actuator/heapdump", "actuator/threaddump", "actuator/mappings",
	"actuator/beans", "actuator/configprops", "actuator/loggers",
	"actuator/httptrace", "actuator/httpexchanges", "actuator/metrics",
	"actuator/scheduledtasks", "actuator/caches", "actuator/sessions",
	"actuator/gateway/routes", "actuator/conditions", "actuator/quartz",
	"env", "health", "heapdump", "dump", "trace", "mappings", "beans",
	"configprops", "loggers", "metrics", "info", "autoconfig",
	"jolokia", "jolokia/list",
}

type verdict struct {
	kind     string // actuator-index | actuator-env | actuator-heapdump | actuator-jolokia | actuator-endpoint
	severity string
	note     string
}

// classify decides what an exposed path means, from the path + response.
func classify(path string, status int, ctype, bodyHead string) (verdict, bool) {
	if status != 200 {
		// heapdump often streams as 200 but some setups 500 mid-dump; ignore non-200
		return verdict{}, false
	}
	body := strings.ToLower(bodyHead)
	ct := strings.ToLower(ctype)
	p := strings.TrimPrefix(path, "actuator/")

	switch {
	case p == "heapdump" || p == "dump":
		if strings.Contains(ct, "octet-stream") || strings.HasPrefix(bodyHead, "JAVA PROFILE") ||
			strings.HasPrefix(bodyHead, "\x1f\x8b") /* gzip */ {
			return verdict{"actuator-heapdump", "critical", "download de heap dump — contém tudo em memória (senhas, tokens, sessões)"}, true
		}
		return verdict{}, false

	case p == "env":
		if strings.Contains(body, "propertysources") || strings.Contains(body, "activeprofiles") || strings.Contains(body, "\"applicationconfig") {
			sev := "high"
			note := "/env exposto — vaza configuração"
			if strings.Contains(body, "password") || strings.Contains(body, "secret") || strings.Contains(body, "\"key\"") || strings.Contains(body, "token") {
				sev, note = "critical", "/env exposto e contém propriedades password/secret/token"
			}
			return verdict{"actuator-env", sev, note}, true
		}
		return verdict{}, false

	case strings.HasPrefix(p, "jolokia"):
		if strings.Contains(body, "\"agent\"") || strings.Contains(body, "\"value\"") || strings.Contains(ct, "json") {
			return verdict{"actuator-jolokia", "high", "Jolokia (JMX sobre HTTP) exposto — leitura/escrita de MBeans"}, true
		}
		return verdict{}, false

	case p == "actuator" || p == "":
		if strings.Contains(body, "\"_links\"") || strings.Contains(body, "\"self\"") {
			return verdict{"actuator-index", "medium", "índice do Actuator exposto — lista os endpoints disponíveis"}, true
		}
		return verdict{}, false

	case p == "health" || p == "info":
		// muito comum e quase sempre benigno; só reporta se traz detalhe
		if strings.Contains(body, "\"diskspace\"") || strings.Contains(body, "\"db\"") || strings.Contains(body, "\"components\"") {
			return verdict{"actuator-endpoint", "low", "/" + p + " com detalhes (management.endpoint.health.show-details)"}, true
		}
		return verdict{}, false

	default:
		// beans/mappings/configprops/loggers/metrics/threaddump/httptrace…
		if looksActuatorJSON(body, ct) {
			return verdict{"actuator-endpoint", "medium", "/" + p + " exposto"}, true
		}
		return verdict{}, false
	}
}

func looksActuatorJSON(body, ct string) bool {
	if !strings.Contains(ct, "json") && !strings.HasPrefix(strings.TrimSpace(body), "{") {
		return false
	}
	for _, k := range []string{"\"contexts\"", "\"beans\"", "\"mappings\"", "\"loggers\"", "\"names\"", "\"traces\"", "\"exchanges\"", "\"propertysources\"", "\"threads\""} {
		if strings.Contains(body, k) {
			return true
		}
	}
	return false
}
