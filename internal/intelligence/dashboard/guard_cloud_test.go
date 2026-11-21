package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard/notify"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// B-G5 (plan docs/plans/dashboard-cli-parity-plan-2026-11-06.md, decision
// P-2): the [guard.cloud] consent card's route. The GET discloses what each
// feature sends where without any credential; the PUT writes only the
// switches and the judge's endpoint fields, behind the confirm token, and
// keeps every other line of config.toml.

const guardCloudWebhookCorpus = `# my guard settings
[guard]
enabled = true
mode = "observe"

[[guard.cloud.webhooks]]
url = "https://hooks.slack.com/services/T000/B000/SECRETPATH"
kind = "slack"

[[guard.cloud.webhooks]]
url = "https://events.pagerduty.com/v2/enqueue"
kind = "pagerduty"
routing_key = "PDROUTINGKEYSECRET"
min_severity = "critical"
`

func getGuardCloud(t *testing.T, s *Server) (guardCloudView, *http.Cookie) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/guard/cloud", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/guard/cloud: %d %s", rr.Code, rr.Body.String())
	}
	var v guardCloudView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			cookie = c
		}
	}
	return v, cookie
}

func putGuardCloud(t *testing.T, s *Server, query, body string, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	v, cookie := getGuardCloud(t, s)
	req := httptest.NewRequest(http.MethodPut, "/api/guard/cloud"+query, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if confirm {
		req.Header.Set(remoteConfirmHeader, v.ConfirmToken)
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func TestGuardCloud_StateDisclosesWithoutCredentials(t *testing.T) {
	s, _ := newSecretTestServer(t, guardCloudWebhookCorpus)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/guard/cloud", nil))
	body := rr.Body.String()
	for _, secret := range []string{"SECRETPATH", "PDROUTINGKEYSECRET", "/services/"} {
		if strings.Contains(body, secret) {
			t.Fatalf("the consent card's state leaks %q: %s", secret, body)
		}
	}
	v, _ := getGuardCloud(t, s)
	if v.CloudEnabled || v.Reputation.Active || v.LLMJudge.Active || v.Webhooks.Active {
		t.Fatalf("every feature is off by default (D1): %+v", v)
	}
	if !v.GuardActive || v.ConfirmToken == "" || v.ConfigEtag == "" {
		t.Fatalf("guard active, confirm token and etag: %+v", v)
	}
	if v.Reputation.Destination != notify.NPMRegistryBase || v.FieldLimit != notify.FieldLimit || v.PayloadMaxBytes != 4096 {
		t.Fatalf("destination and bounds come from the code: %+v", v)
	}
	if strings.Join(v.LLMJudge.Fields, ",") != strings.Join(notify.JudgeFields(), ",") ||
		strings.Join(v.Webhooks.Fields, ",") != strings.Join(notify.WebhookFields(), ",") {
		t.Fatalf("the disclosed fields are the builders' fields: %+v", v)
	}
	if v.LLMJudge.ApprovalTTLMinutes != 60 || v.LLMJudge.ConfidenceFloor != notify.JudgeConfidenceFloor {
		t.Fatalf("judge authority facts: %+v", v.LLMJudge)
	}
	want := []guardCloudWebhook{
		{Kind: "slack", Host: "hooks.slack.com", MinSeverity: "high"},
		{Kind: "pagerduty", Host: "events.pagerduty.com", MinSeverity: "critical", HasRoutingKey: true},
	}
	if len(v.Webhooks.Hooks) != len(want) {
		t.Fatalf("webhooks = %+v", v.Webhooks.Hooks)
	}
	for i := range want {
		if v.Webhooks.Hooks[i] != want[i] {
			t.Errorf("webhook %d = %+v, want %+v", i, v.Webhooks.Hooks[i], want[i])
		}
	}
}

func TestGuardCloud_WriteNeedsTheConfirmToken(t *testing.T) {
	s, path := newSecretTestServer(t, guardCloudWebhookCorpus)
	before, _ := os.ReadFile(path)
	rr := putGuardCloud(t, s, "", `{"cloud_enabled":true,"reputation_enabled":true}`, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("a write without the confirm token: %d %s", rr.Code, rr.Body.String())
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a refused write must leave config.toml untouched")
	}

	// A dry run writes nothing, so it needs no token, and it shows the diff.
	rr = putGuardCloud(t, s, "?dry_run=1", `{"cloud_enabled":true,"reputation_enabled":true}`, false)
	if rr.Code != http.StatusOK {
		t.Fatalf("dry run: %d %s", rr.Code, rr.Body.String())
	}
	m := decodeMap(t, rr)
	if m["dry_run"] != true || m["would_write"] != true || !strings.Contains(m["diff"].(string), "+") {
		t.Fatalf("dry run answers the diff: %v", m)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a dry run must leave config.toml untouched")
	}
}

func TestGuardCloud_TurnOnAndOffKeepsTheRestOfTheFile(t *testing.T) {
	s, path := newSecretTestServer(t, guardCloudWebhookCorpus)
	rr := putGuardCloud(t, s, "", `{"cloud_enabled":true,"reputation_enabled":true}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("turn on: %d %s", rr.Code, rr.Body.String())
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Guard.Cloud
	if !c.Enabled || !c.Reputation.Enabled || c.LLMJudge.Enabled || len(c.Webhooks) != 2 || c.Webhooks[1].RoutingKey != "PDROUTINGKEYSECRET" {
		t.Fatalf("saved block = %+v", c)
	}
	m := decodeMap(t, rr)
	state, _ := m["state"].(map[string]any)
	rep, _ := state["reputation"].(map[string]any)
	if rep["active"] != true {
		t.Fatalf("the response carries the saved state: %v", m)
	}
	// The reputation lookup reads the config per request: on at once.
	rep2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rep2, httptest.NewRequest(http.MethodGet, "/api/guard/mcp/reputation", nil))
	if decodeMap(t, rep2)["available"] != true {
		t.Fatalf("lookups available right after the consent: %s", rep2.Body.String())
	}
	rows, err := store.New(s.opts.DB).RecentRemoteAudit(context.Background(), 5)
	if err != nil || len(rows) == 0 || !strings.Contains(rows[0].Detail, "guard_cloud cloud=true reputation=true") {
		t.Fatalf("the consent is audited: %+v %v", rows, err)
	}

	// Turning off is one write, no other field needed.
	rr = putGuardCloud(t, s, "", `{"cloud_enabled":false}`, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("turn off: %d %s", rr.Code, rr.Body.String())
	}
	cfg, _ = config.Load(config.LoadOptions{GlobalPath: path})
	if cfg.Guard.Cloud.Enabled || len(cfg.Guard.Cloud.Webhooks) != 2 {
		t.Fatalf("off keeps the webhook list: %+v", cfg.Guard.Cloud)
	}
}

func TestGuardCloud_JudgeFieldsAreValidated(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
		msg  string
	}{
		{"judge on without an endpoint", `{"cloud_enabled":true,"llm_judge":{"enabled":true}}`, 400, "needs an endpoint"},
		{"plain http to another machine", `{"llm_judge":{"endpoint":"http://llm.example.com/v1/chat/completions"}}`, 400, "must use https"},
		{"credentials in the url", `{"llm_judge":{"endpoint":"https://u:p@llm.example.com/v1"}}`, 400, "user name or password"},
		{"not a url", `{"llm_judge":{"endpoint":"llm.example.com"}}`, 400, "full http(s) URL"},
		{"a key where the variable name goes", `{"llm_judge":{"api_key_env":"sk-live-123"}}`, 400, "NAME of an environment variable"},
		{"a webhook is never written here", `{"webhooks":[{"url":"https://x.example"}]}`, 400, "unknown field"},
		{"the payload cap is never written here", `{"payload_max_bytes":1}`, 400, "unknown field"},
		{"a local judge over http", `{"cloud_enabled":true,"llm_judge":{"enabled":true,"endpoint":"http://127.0.0.1:11434/v1/chat/completions","model":"llama3","api_key_env":"OLLAMA_KEY"}}`, 200, ""},
		{"a remote judge over https", `{"llm_judge":{"endpoint":"https://llm.example.com/v1/chat/completions"}}`, 200, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, path := newSecretTestServer(t, "[guard]\nenabled = true\n")
			before, _ := os.ReadFile(path)
			rr := putGuardCloud(t, s, "", tc.body, true)
			if rr.Code != tc.want || !strings.Contains(rr.Body.String(), tc.msg) {
				t.Fatalf("got %d %s, want %d containing %q", rr.Code, rr.Body.String(), tc.want, tc.msg)
			}
			if tc.want != http.StatusOK {
				if after, _ := os.ReadFile(path); string(after) != string(before) {
					t.Fatal("a refused save must leave config.toml untouched")
				}
			}
		})
	}
}

func TestGuardCloudEndpointRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		endpoint string
		ok       bool
	}{
		{"https://llm.example.com/v1/chat/completions", true},
		{"http://localhost:4000/v1/chat/completions", true},
		{"http://127.0.0.1:11434/v1/chat/completions", true},
		{"http://[::1]:8080/v1", true},
		{"http://gateway.localhost/v1", true},
		{"http://10.0.0.5/v1", false},
		{"ftp://llm.example.com", false},
		{"https://user@llm.example.com", false},
		{"/v1/chat/completions", false},
	}
	for _, tc := range cases {
		if got := guardCloudEndpointProblem(tc.endpoint) == ""; got != tc.ok {
			t.Errorf("%s: ok = %v, want %v (%s)", tc.endpoint, got, tc.ok, guardCloudEndpointProblem(tc.endpoint))
		}
	}
	shown, host := guardCloudDisplayEndpoint("https://u:p@llm.example.com/v1/chat?key=SECRET#x")
	if strings.Contains(shown, "SECRET") || strings.Contains(shown, "u:p") || host != "llm.example.com" {
		t.Fatalf("display endpoint = %q host %q", shown, host)
	}
}
