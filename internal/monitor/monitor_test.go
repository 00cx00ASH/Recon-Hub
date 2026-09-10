package monitor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"reconhub/internal/pipeline"
	"reconhub/internal/scope"
)

func TestWatchDue(t *testing.T) {
	now := time.Now()
	w := Watch{Enabled: true, Every: "1h"}
	if !w.due(now) {
		t.Error("nunca rodou -> due")
	}
	past := now.Add(-90 * time.Minute)
	w.LastRunAt = &past
	if !w.due(now) {
		t.Error("passou o intervalo -> due")
	}
	recent := now.Add(-10 * time.Minute)
	w.LastRunAt = &recent
	if w.due(now) {
		t.Error("dentro do intervalo -> não due")
	}
	w.Enabled = false
	w.LastRunAt = &past
	if w.due(now) {
		t.Error("disabled -> nunca due")
	}
}

func TestInterval(t *testing.T) {
	if (Watch{Every: "6h"}).interval() != 6*time.Hour {
		t.Error("6h")
	}
	if (Watch{Every: "5s"}).interval() != time.Minute {
		t.Error("< 1m sobe pra 1m")
	}
	if (Watch{Every: "lixo"}).interval() != time.Minute {
		t.Error("inválido -> 1m")
	}
}

func TestRegistrySaveLoadState(t *testing.T) {
	dir := t.TempDir()
	r, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	w := Watch{Name: "acme-nightly", Pipeline: "crtsh-takeover", Target: "acme.com", Every: "24h", Enabled: true}
	if err := r.Save(w); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(w); err == nil {
		t.Error("segundo Save do mesmo nome deveria falhar")
	}

	r2, _ := Load(dir)
	got, ok := r2.Get("acme-nightly")
	if !ok || got.Pipeline != "crtsh-takeover" || got.Target != "acme.com" {
		t.Fatalf("reload = %+v", got)
	}

	at := time.Now()
	r2.setState("acme-nightly", "run123", at, 4, 4, 0, 0)
	// persistiu no arquivo?
	b, _ := os.ReadFile(filepath.Join(dir, "acme-nightly.json"))
	var onDisk Watch
	_ = json.Unmarshal(b, &onDisk)
	if onDisk.LastRunID != "run123" || onDisk.LastNew != 4 || onDisk.LastRunAt == nil {
		t.Fatalf("estado não persistido: %+v", onDisk)
	}
}

func TestSaveRejectsBad(t *testing.T) {
	r, _ := Load(t.TempDir())
	if r.Save(Watch{Name: "x", Target: "a.com", Every: "1h"}) == nil {
		t.Error("sem pipeline")
	}
	if r.Save(Watch{Name: "y", Pipeline: "p", Target: "a.com", Every: "banana"}) == nil {
		t.Error("every inválido")
	}
	if r.Save(Watch{Name: "BAD NAME", Pipeline: "p", Target: "a.com", Every: "1h"}) == nil {
		t.Error("nome inválido")
	}
}

// --- fake hub ---

type fakeHub struct {
	mu          sync.Mutex
	submits     int
	keysByRun   map[string][]string
	jsByRun     map[string][]string
	statusByRun map[string]string
}

func (h *fakeHub) Pipeline(name string) (pipeline.Pipeline, bool) {
	return pipeline.Pipeline{Name: name, Steps: []pipeline.Step{{Tool: "x"}}}, true
}
func (h *fakeHub) Program(name string) (*scope.Program, error) { return nil, nil }
func (h *fakeHub) Submit(pl pipeline.Pipeline, target string, prog *scope.Program) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.submits++
	id := "run" + itoa(h.submits)
	h.statusByRun[id] = "succeeded"
	return id, nil
}
func (h *fakeHub) RunStatus(id string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.statusByRun[id]
	return s, s == "succeeded" || s == "failed"
}
func (h *fakeHub) FindingKeys(id string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.keysByRun[id]
}

func (h *fakeHub) JSAssets(id string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.jsByRun[id]
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestValidWebhookType(t *testing.T) {
	for _, ok := range []string{"", "discord", "slack", "telegram", "generic"} {
		if !ValidWebhookType(ok) {
			t.Errorf("%q deveria ser válido", ok)
		}
	}
	if ValidWebhookType("whatsapp") {
		t.Error("tipo desconhecido não deveria ser válido")
	}
}

func TestBuildPayloadDiscordDefault(t *testing.T) {
	// Watch sem WebhookType (todo watch criado antes desse campo existir) —
	// deve continuar postando exatamente como antes: campo "content".
	w := Watch{Name: "w1", Pipeline: "p", Target: "t.com"}
	var p map[string]any
	_ = json.Unmarshal(buildPayload(w, "run1", 1, []FindingBrief{{Severity: "high", Title: "x"}}, Anomaly{}, 0, 0), &p)
	if _, ok := p["content"]; !ok {
		t.Error("discord (default) deveria ter campo content")
	}
	if _, ok := p["text"]; ok {
		t.Error("discord não deveria ter campo text")
	}
}

func TestBuildPayloadSlack(t *testing.T) {
	w := Watch{Name: "w1", Pipeline: "p", Target: "t.com", WebhookType: "slack"}
	var p map[string]any
	_ = json.Unmarshal(buildPayload(w, "run1", 1, []FindingBrief{{Severity: "high", Title: "x"}}, Anomaly{}, 0, 0), &p)
	text, ok := p["text"].(string)
	if !ok || !strings.Contains(text, "w1") {
		t.Fatalf("slack deveria ter campo text com a mensagem: %v", p["text"])
	}
	if _, ok := p["content"]; ok {
		t.Error("slack não deveria ter campo content (Discord)")
	}
}

func TestBuildPayloadTelegramIsMinimal(t *testing.T) {
	// Telegram sendMessage só olha "text" (chat_id vem embutido na URL do
	// webhook) — o payload não deveria carregar os campos extras (findings
	// estruturados etc.), que a API do Telegram rejeitaria como parâmetro
	// desconhecido.
	w := Watch{Name: "w1", Pipeline: "p", Target: "t.com", WebhookType: "telegram"}
	body := buildPayload(w, "run1", 1, []FindingBrief{{Severity: "high", Title: "x"}}, Anomaly{}, 0, 0)
	var p map[string]any
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	if _, ok := p["text"]; !ok {
		t.Fatal("telegram deveria ter campo text")
	}
	for _, unexpected := range []string{"content", "findings", "watch", "pipeline"} {
		if _, ok := p[unexpected]; ok {
			t.Errorf("telegram não deveria carregar %q (a API do Telegram rejeita campo desconhecido)", unexpected)
		}
	}
}

func TestBuildPayloadGenericHasBoth(t *testing.T) {
	w := Watch{Name: "w1", Pipeline: "p", Target: "t.com", WebhookType: "generic"}
	var p map[string]any
	_ = json.Unmarshal(buildPayload(w, "run1", 1, nil, Anomaly{}, 0, 0), &p)
	if _, ok := p["content"]; !ok {
		t.Error("generic deveria ter content")
	}
	if _, ok := p["text"]; !ok {
		t.Error("generic deveria ter text")
	}
	if _, ok := p["findings"]; !ok {
		t.Error("generic deveria manter os campos estruturados")
	}
}

func TestFireDiffAndAlert(t *testing.T) {
	dir := t.TempDir()
	reg, _ := Load(dir)
	_ = reg.Save(Watch{Name: "w1", Pipeline: "p", Target: "t.com", Every: "1h", Enabled: true, Webhook: "http://hook"})

	hub := &fakeHub{keysByRun: map[string][]string{}, statusByRun: map[string]string{}}
	m := New(reg, hub, 30*time.Second)

	var posted [][]byte
	var pmu sync.Mutex
	m.post = func(url string, body []byte) error {
		pmu.Lock()
		posted = append(posted, body)
		pmu.Unlock()
		return nil
	}
	m.FindingsForBrief = func(runID string, keys []string) []FindingBrief {
		out := make([]FindingBrief, len(keys))
		for i, k := range keys {
			out[i] = FindingBrief{Severity: "high", Title: k}
		}
		return out
	}

	// 1ª run: 2 findings -> ambos novos -> alerta
	hub.keysByRun["run1"] = []string{"k\x00a", "k\x00b"}
	w1, _ := reg.Get("w1")
	m.fire(context.Background(), w1)

	pmu.Lock()
	if len(posted) != 1 {
		t.Fatalf("1ª run: esperava 1 post, got %d", len(posted))
	}
	var p1 map[string]any
	_ = json.Unmarshal(posted[0], &p1)
	if int(p1["new_findings"].(float64)) != 2 {
		t.Errorf("1ª run: new_findings = %v", p1["new_findings"])
	}
	pmu.Unlock()

	st, _ := reg.Get("w1")
	if st.LastRunID != "run1" || st.LastNew != 2 {
		t.Fatalf("estado após 1ª run: %+v", st)
	}

	// 2ª run: 1 repetido + 1 novo -> só 1 novo -> alerta com 1
	hub.keysByRun["run2"] = []string{"k\x00b", "k\x00c"}
	w2, _ := reg.Get("w1")
	m.fire(context.Background(), w2)

	pmu.Lock()
	defer pmu.Unlock()
	if len(posted) != 2 {
		t.Fatalf("2ª run: esperava 2 posts total, got %d", len(posted))
	}
	var p2 map[string]any
	_ = json.Unmarshal(posted[1], &p2)
	if int(p2["new_findings"].(float64)) != 1 {
		t.Errorf("2ª run: new_findings = %v (quer 1)", p2["new_findings"])
	}
}

func TestFireDetectsJSDiff(t *testing.T) {
	dir := t.TempDir()
	reg, _ := Load(dir)
	_ = reg.Save(Watch{Name: "w1", Pipeline: "p", Target: "t.com", Every: "1h", Enabled: true, Webhook: "http://hook"})

	hub := &fakeHub{keysByRun: map[string][]string{}, jsByRun: map[string][]string{}, statusByRun: map[string]string{}}
	m := New(reg, hub, 30*time.Second)

	var posted [][]byte
	m.post = func(url string, body []byte) error { posted = append(posted, body); return nil }

	// 1ª run: sem findings novos (nada pra comparar ainda), mas estabelece o baseline de JS
	hub.keysByRun["run1"] = nil
	hub.jsByRun["run1"] = []string{"/api/v1/users", "/api/v1/login"}
	w1, _ := reg.Get("w1")
	m.fire(context.Background(), w1)
	if len(posted) != 0 {
		t.Fatalf("1ª run sem finding novo não deveria postar (é só o baseline): %d posts", len(posted))
	}

	// 2ª run: ainda sem finding novo, mas o JS mudou (endpoint novo + um sumiu) -> deve alertar mesmo assim
	hub.keysByRun["run2"] = nil
	hub.jsByRun["run2"] = []string{"/api/v1/users", "/api/v2/admin"}
	w2, _ := reg.Get("w1")
	m.fire(context.Background(), w2)

	if len(posted) != 1 {
		t.Fatalf("2ª run com JS mudando deveria alertar mesmo sem finding novo: %d posts", len(posted))
	}
	var p map[string]any
	_ = json.Unmarshal(posted[0], &p)
	if int(p["js_new"].(float64)) != 1 {
		t.Errorf("js_new = %v, quer 1 (/api/v2/admin)", p["js_new"])
	}
	if int(p["js_removed"].(float64)) != 1 {
		t.Errorf("js_removed = %v, quer 1 (/api/v1/login)", p["js_removed"])
	}
	if !strings.Contains(p["content"].(string), "JS mudou") {
		t.Errorf("mensagem deveria mencionar a mudança de JS: %v", p["content"])
	}

	st, _ := reg.Get("w1")
	if st.LastNewJS != 1 || st.LastRemovedJS != 1 {
		t.Fatalf("estado do watch não guardou o diff de JS: %+v", st)
	}
}

func TestFireNoNewNoPost(t *testing.T) {
	dir := t.TempDir()
	reg, _ := Load(dir)
	_ = reg.Save(Watch{Name: "w", Pipeline: "p", Target: "t", Every: "1h", Enabled: true, Webhook: "http://h"})
	hub := &fakeHub{keysByRun: map[string][]string{}, statusByRun: map[string]string{}}
	m := New(reg, hub, 30*time.Second)
	posts := 0
	m.post = func(string, []byte) error { posts++; return nil }

	hub.keysByRun["run1"] = []string{"k1"}
	w, _ := reg.Get("w")
	m.fire(context.Background(), w) // 1ª: k1 novo -> post
	hub.keysByRun["run2"] = []string{"k1"}
	w, _ = reg.Get("w")
	m.fire(context.Background(), w) // 2ª: nada novo -> sem post
	if posts != 1 {
		t.Errorf("posts = %d, quer 1", posts)
	}
}
