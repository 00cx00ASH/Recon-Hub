package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// svc maps a port to a default service name.
var svc = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 43: "whois", 53: "dns",
	69: "tftp", 79: "finger", 80: "http", 88: "kerberos", 110: "pop3",
	111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
	143: "imap", 161: "snmp", 179: "bgp", 389: "ldap", 427: "slp", 443: "https",
	445: "smb", 465: "smtps", 500: "ike", 512: "rexec", 513: "rlogin", 514: "syslog",
	515: "lpd", 543: "klogin", 548: "afp", 554: "rtsp", 587: "submission",
	631: "ipp", 636: "ldaps", 873: "rsync", 902: "vmware", 989: "ftps-data",
	990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks", 1099: "java-rmi",
	1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs",
	2181: "zookeeper", 2222: "ssh-alt", 2375: "docker", 2376: "docker-tls",
	2379: "etcd", 2380: "etcd-peer", 3000: "http-dev", 3128: "squid-proxy",
	3306: "mysql", 3389: "rdp", 3690: "svn", 4369: "epmd", 4444: "metasploit",
	4500: "ipsec-nat", 5000: "http-dev", 5044: "logstash-beats", 5060: "sip",
	5222: "xmpp", 5353: "mdns", 5432: "postgresql", 5555: "adb", 5601: "kibana",
	5672: "amqp", 5900: "vnc", 5984: "couchdb", 5985: "winrm", 5986: "winrm-tls",
	6000: "x11", 6379: "redis", 6443: "kube-apiserver", 6667: "irc", 7000: "cassandra",
	7001: "weblogic", 7077: "spark", 7199: "cassandra-jmx", 7473: "neo4j-https",
	7474: "neo4j", 7687: "bolt", 8000: "http-alt", 8009: "ajp", 8020: "hdfs",
	8080: "http-proxy", 8081: "http-alt", 8086: "influxdb", 8088: "yarn",
	8161: "activemq", 8443: "https-alt", 8500: "consul", 8529: "arangodb",
	8686: "jmx", 8888: "http-alt", 9000: "http-alt", 9042: "cassandra-cql",
	9092: "kafka", 9160: "cassandra-thrift", 9200: "elasticsearch", 9300: "elasticsearch-tcp",
	9418: "git", 9990: "wildfly-mgmt", 10000: "webmin", 10250: "kubelet",
	11211: "memcached", 15672: "rabbitmq-mgmt", 16379: "redis-cluster",
	27017: "mongodb", 27018: "mongodb-shard", 27019: "mongodb-config",
	28015: "rethinkdb", 50000: "sap", 50070: "hdfs-namenode", 61616: "activemq-openwire",
}

// portSet resolves a spec ("top100", "top1000", "web", or "22,80,8000-8100").
func portSet(spec string) []int {
	spec = strings.TrimSpace(strings.ToLower(spec))
	switch spec {
	case "", "top100", "top":
		return keysSorted(svc) // ~120 curated
	case "web":
		return []int{80, 81, 88, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9200, 9443}
	case "db":
		return []int{1433, 1521, 3306, 5432, 5984, 6379, 7000, 8086, 9042, 9200, 11211, 27017, 27018, 28015}
	case "top1000":
		return append(keysSorted(svc), fillRange(1, 1024)...)
	}
	var out []int
	seen := map[int]bool{}
	for _, part := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' }) {
		if lo, hi, ok := parseRange(part); ok {
			for p := lo; p <= hi && p-lo < 65535; p++ {
				if p > 0 && p < 65536 && !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil && n > 0 && n < 65536 && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func parseRange(s string) (int, int, bool) {
	lo, hi, found := strings.Cut(s, "-")
	if !found {
		return 0, 0, false
	}
	a, e1 := strconv.Atoi(strings.TrimSpace(lo))
	b, e2 := strconv.Atoi(strings.TrimSpace(hi))
	if e1 != nil || e2 != nil || a > b {
		return 0, 0, false
	}
	return a, b, true
}

func fillRange(lo, hi int) []int {
	out := make([]int, 0, hi-lo+1)
	for p := lo; p <= hi; p++ {
		out = append(out, p)
	}
	return out
}

func keysSorted(m map[int]string) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// insertion-ish sort (small n)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// grab does a best-effort banner read after connecting.
func grab(conn net.Conn, port int, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout))
	// protocols that speak first
	speaksFirst := map[int]bool{21: true, 22: true, 25: true, 110: true, 143: true, 587: true, 3306: true, 5432: true, 6379: false}
	buf := make([]byte, 2048)

	if speaksFirst[port] {
		n, _ := conn.Read(buf)
		return clean(buf[:n])
	}
	// otherwise poke it
	switch {
	case port == 6379: // redis
		conn.Write([]byte("PING\r\n"))
		n, _ := conn.Read(buf)
		return clean(buf[:n])
	case port == 11211: // memcached
		conn.Write([]byte("version\r\n"))
		n, _ := conn.Read(buf)
		return clean(buf[:n])
	case isHTTPish(port):
		conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: x\r\nUser-Agent: recon-hub\r\n\r\n"))
		n, _ := conn.Read(buf)
		return clean(buf[:n])
	default:
		conn.Write([]byte("\r\n"))
		n, _ := conn.Read(buf)
		return clean(buf[:n])
	}
}

func isHTTPish(port int) bool {
	switch port {
	case 80, 81, 88, 443, 591, 2375, 2379, 3000, 5000, 5601, 5984, 7001, 7473, 7474,
		8000, 8008, 8080, 8081, 8086, 8088, 8161, 8443, 8500, 8529, 8888, 9000, 9090,
		9200, 9443, 9990, 10000, 15672, 50070:
		return true
	}
	return false
}

func clean(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, string(b))
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

var (
	reSSH    = regexp.MustCompile(`(?i)SSH-([0-9.]+)-(\S+)`)
	reHTTP   = regexp.MustCompile(`(?i)^HTTP/[0-9.]+ (\d{3})`)
	reServer = regexp.MustCompile(`(?i)\r?\nServer:\s*([^\r\n]+)`)
)

// identify refines the service name and returns (service, product, extra note).
func identify(port int, banner string) (service, product string) {
	service = svc[port]
	if service == "" {
		service = "unknown"
	}
	b := banner
	switch {
	case reSSH.MatchString(b):
		m := reSSH.FindStringSubmatch(b)
		return "ssh", m[2]
	case strings.HasPrefix(b, "220 ") && (service == "smtp" || service == "ftp" || strings.Contains(strings.ToLower(b), "ftp") || strings.Contains(strings.ToLower(b), "smtp")):
		return service, firstWords(b, 8)
	case reHTTP.MatchString(b):
		svcName := "http"
		if port == 443 || port == 8443 || port == 9443 {
			svcName = "https"
		} else if s := svc[port]; s != "" {
			svcName = s
		}
		if m := reServer.FindStringSubmatch(b); m != nil {
			return svcName, strings.TrimSpace(m[1])
		}
		return svcName, ""
	case strings.Contains(b, "+PONG") || strings.HasPrefix(b, "-NOAUTH") || strings.HasPrefix(b, "-ERR"):
		return "redis", ""
	case strings.HasPrefix(b, "VERSION "):
		return "memcached", strings.TrimPrefix(b, "VERSION ")
	case strings.Contains(strings.ToLower(b), "mysql") || (port == 3306 && len(b) > 4):
		return "mysql", firstWords(b, 6)
	}
	return service, firstWords(b, 8)
}

func firstWords(s string, n int) string {
	f := strings.Fields(s)
	if len(f) > n {
		f = f[:n]
	}
	return strings.Join(f, " ")
}

// notable classifies exposed sensitive services.
func notable(service string, port int) (bool, string, string) {
	sensitive := map[string]string{
		"redis":          "banco em memória — normalmente sem auth",
		"memcached":      "cache — sem auth, amplificação DDoS",
		"mongodb":        "banco NoSQL — checar auth (ver scan-mongodb)",
		"mongodb-shard":  "banco NoSQL",
		"elasticsearch":  "índice de busca — normalmente sem auth",
		"docker":         "Docker API sem TLS — RCE se acessível",
		"docker-tls":     "Docker API",
		"kube-apiserver": "API do Kubernetes",
		"kubelet":        "kubelet — pode expor exec/logs",
		"etcd":           "etcd — armazena os secrets do cluster",
		"rdp":            "RDP exposto — brute force / BlueKeep",
		"vnc":            "VNC exposto",
		"winrm":          "WinRM — administração remota Windows",
		"mssql":          "SQL Server exposto",
		"mysql":          "MySQL exposto",
		"postgresql":     "PostgreSQL exposto",
		"oracle":         "Oracle DB exposto",
		"couchdb":        "CouchDB — checar admin party",
		"cassandra-cql":  "Cassandra CQL",
		"kafka":          "Kafka broker",
		"zookeeper":      "ZooKeeper — expõe config do cluster",
		"rabbitmq-mgmt":  "RabbitMQ mgmt (guest/guest?)",
		"jenkins":        "Jenkins",
		"weblogic":       "WebLogic — CVEs de deserialização",
		"jmx":            "JMX — RCE via MLet",
		"java-rmi":       "Java RMI — deserialização",
		"smb":            "SMB exposto",
		"ldap":           "LDAP — pode permitir bind anônimo",
		"snmp":           "SNMP — community 'public'?",
		"telnet":         "Telnet — texto puro",
		"ftp":            "FTP — checar login anônimo",
		"epmd":           "Erlang port mapper — expõe nós",
		"influxdb":       "InfluxDB",
		"kibana":         "Kibana — pode dar acesso ao Elastic",
		"consul":         "Consul — service mesh / KV",
	}
	if note, ok := sensitive[service]; ok {
		return true, "medium", note
	}
	return false, "", ""
}

func hostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func portLabel(port int, service, product string) string {
	if product != "" {
		return fmt.Sprintf("%d/%s (%s)", port, service, product)
	}
	return fmt.Sprintf("%d/%s", port, service)
}
