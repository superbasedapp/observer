package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/applane"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestAppLanesRoutes pins the S5 node API: GET lists the lanes with their
// client base URLs, POST adds one (confirm token), DELETE removes one
// (confirm token), and the write is the one config writer's.
func TestAppLanesRoutes(t *testing.T) {
	f := newFirstRunFixture(t, true)
	h := f.server.Handler()
	do := func(method, path, body string, arm bool) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if arm {
			req = armLocalWrite(req)
		}
		h.ServeHTTP(rr, req)
		return rr
	}
	decode := func(rr *httptest.ResponseRecorder) appLanesBody {
		t.Helper()
		var b appLanesBody
		if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
			t.Fatalf("decode %d %s: %v", rr.Code, rr.Body, err)
		}
		return b
	}
	if rr := do(http.MethodGet, "/api/apps/lanes", "", false); rr.Code != http.StatusOK || len(decode(rr).Lanes) != 0 {
		t.Fatalf("empty GET: %d %s", rr.Code, rr.Body)
	}
	if rr := do(http.MethodPost, "/api/apps/lanes", `{"id":"openai"}`, false); rr.Code != http.StatusForbidden {
		t.Fatalf("POST without the confirm token = %d, want 403", rr.Code)
	}
	rr := do(http.MethodPost, "/api/apps/lanes", `{"id":"openai","models":["gpt-5-nano"]}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST: %d %s", rr.Code, rr.Body)
	}
	b := decode(rr)
	if len(b.Lanes) != 1 || b.Lanes[0].ClientBaseURL != "http://127.0.0.1:8820/up/openai/v1" || b.Lanes[0].Models[0] != "gpt-5-nano" || b.Budget != "enforce" || !b.RestartRequired {
		t.Fatalf("after POST: %+v", b)
	}
	if rr := do(http.MethodPost, "/api/apps/lanes", `{"id":"openai"}`, true); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate = %d, want 409", rr.Code)
	}
	if rr := do(http.MethodPost, "/api/apps/lanes", `{"id":"mine","upstream":"http://example.com"}`, true); rr.Code != http.StatusBadRequest {
		t.Fatalf("plain http off loopback = %d, want 400", rr.Code)
	}
	raw, _ := os.ReadFile(f.server.opts.ConfigPath)
	if !strings.Contains(string(raw), "enabled_adapters") {
		t.Fatalf("the write dropped the file's other keys:\n%s", raw)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: f.server.opts.ConfigPath})
	if err != nil || cfg.Proxy.Upstreams["openai"] != "https://api.openai.com" {
		t.Fatalf("written: %v %v", cfg.Proxy.Upstreams, err)
	}
	if rr := do(http.MethodDelete, "/api/apps/lanes/openai", `{}`, false); rr.Code == http.StatusOK {
		t.Fatal("DELETE without the confirm token succeeded")
	}
	if rr := do(http.MethodDelete, "/api/apps/lanes/openai", `{}`, true); rr.Code != http.StatusOK || len(decode(rr).Lanes) != 0 {
		t.Fatalf("DELETE: %d %s", rr.Code, rr.Body)
	}
	if rr := do(http.MethodDelete, "/api/apps/lanes/openai", `{}`, true); rr.Code != http.StatusNotFound {
		t.Fatalf("DELETE missing = %d, want 404", rr.Code)
	}
}

// TestAppLanesBodyStatesWhereCapsCount (hosted AI gateway review L5): the S5
// body says where the lanes' app caps count spend from: "recorded" with
// [observability] on, "process" (with a note) when it is off, because then
// only this daemon's calls since it started count.
func TestAppLanesBodyStatesWhereCapsCount(t *testing.T) {
	cfg := config.Default()
	cfg.Observability.Enabled = false
	b := appLanesBodyOf(cfg)
	if b.CapSpend != applane.CapSpendProcess || !strings.Contains(b.CapSpendNote, "since it started") {
		t.Fatalf("observability off: cap_spend=%q note=%q", b.CapSpend, b.CapSpendNote)
	}
	cfg.Observability.Enabled = true
	b = appLanesBodyOf(cfg)
	if b.CapSpend != applane.CapSpendRecorded || b.CapSpendNote != "" {
		t.Fatalf("observability on: cap_spend=%q note=%q", b.CapSpend, b.CapSpendNote)
	}
}
