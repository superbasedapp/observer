package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/planlimits"
	"github.com/marmutapp/superbased-observer/internal/planlimitssvc"
)

func plansTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "observer.db")) + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func runPlans(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := newPlansCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// TestPlansCLI_ManualLifecycle adds, lists and removes a typed-in plan. A
// manual account has no secret, so the keychain is never opened.
func TestPlansCLI_ManualLifecycle(t *testing.T) {
	cfg := plansTestConfig(t)
	out, err := runPlans(t, "", "add", "cursor", "--config", cfg, "--source", "manual", "--label", "Pro",
		"--param", "unit=requests", "--param", "allowance=500", "--param", "used=120")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	m := regexp.MustCompile(`Added Cursor account ([0-9a-f]+)\.`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("add output: %s", out)
	}
	id := m[1]
	out, err = runPlans(t, "", "--config", cfg)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out, "Cursor") || !strings.Contains(out, "120 requests of 500 requests") {
		t.Fatalf("status output: %s", out)
	}
	out, err = runPlans(t, "", "status", "--json", "--config", cfg)
	if err != nil {
		t.Fatalf("status --json: %v", err)
	}
	var v struct {
		Accounts []struct{ ID string } `json:"accounts"`
		Keychain string                `json:"keychain"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("status --json is not JSON: %v\n%s", err, out)
	}
	if len(v.Accounts) != 1 || v.Accounts[0].ID != id || v.Keychain != "not opened" {
		t.Fatalf("status --json = %+v", v)
	}
	if out, err := runPlans(t, "", "usage", id, "--config", cfg); err != nil || !strings.Contains(out, "does not report daily usage") {
		t.Fatalf("usage of a manual account: %v %s", err, out)
	}
	if out, err := runPlans(t, "", "remove", id, "--config", cfg); err != nil || !strings.Contains(out, "Removed") {
		t.Fatalf("remove: %v %s", err, out)
	}
	if _, err := runPlans(t, "", "remove", id, "--config", cfg); err == nil {
		t.Fatal("removing an unknown account should fail")
	}
}

func TestPlansCLI_ExperimentalNeedsTheSwitch(t *testing.T) {
	cfg := plansTestConfig(t)
	_, err := runPlans(t, "", "add", "cursor", "--config", cfg, "--source", "cursor.app")
	if err == nil || !strings.Contains(err.Error(), "observer plans optin") {
		t.Fatalf("experimental add without the switch: %v", err)
	}
	if _, err := runPlans(t, "", "optin", "openrouter", "on", "--config", cfg); err == nil {
		t.Fatal("a provider with no experimental source cannot be switched on")
	}
	if out, err := runPlans(t, "", "optin", "cursor", "maybe", "--config", cfg); err == nil {
		t.Fatalf("optin needs on or off: %s", out)
	}
}

func TestPlansCLI_SourcesListsEveryProvider(t *testing.T) {
	out, err := runPlans(t, "", "sources")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"openrouter.api", "--secret key", "experimental", "automatic", "runs kiro-cli"} {
		if !strings.Contains(out, want) {
			t.Errorf("sources output lacks %q", want)
		}
	}
}

func TestReadSecretsReadsStdinInOrder(t *testing.T) {
	got, err := readSecrets(strings.NewReader("first\nsecond\n"), []string{"key", "mgmt"})
	if err != nil || got["key"] != "first" || got["mgmt"] != "second" {
		t.Fatalf("readSecrets = %v %v", got, err)
	}
	if _, err := readSecrets(strings.NewReader(""), []string{"key"}); err == nil {
		t.Fatal("a missing stdin line must fail, never an empty secret")
	}
}

func TestLazyKeysOpensOnlyOnUse(t *testing.T) {
	var opens atomic.Int32
	k := &lazyKeys{open: func() keystore.Store {
		opens.Add(1)
		return &keystore.MemStore{}
	}}
	if k.Backend() != "not opened" || opens.Load() != 0 {
		t.Fatal("Backend must not open the keychain")
	}
	if err := k.Set("account.a.key", "v"); err != nil {
		t.Fatal(err)
	}
	if v, _ := k.Get("account.a.key"); v != "v" || opens.Load() != 1 || k.Backend() != "memory" {
		t.Fatalf("after use: opens=%d backend=%s", opens.Load(), k.Backend())
	}
}

// --- status line feed -------------------------------------------------------------

const planSLPayload = `{"session_id":"s1","version":"2.1.0","model":{"id":"secret-model"},"workspace":{"current_dir":"/home/me/secret"},"cost":{"total_cost_usd":1.5},"rate_limits":{"five_hour":{"used_percentage":%d,"resets_at":4102444800}}}`

func TestForwardPlanStatusLine_ChangeOnlyAndNumbersOnly(t *testing.T) {
	var posts atomic.Int32
	var last []byte
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/plans/statusline" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request %s %s", r.URL.Path, r.Header.Get("Content-Type"))
		}
		last, _ = io.ReadAll(r.Body)
		posts.Add(1)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	dir := t.TempDir()
	now := time.Now()
	payload := func(pct int) []byte { return []byte(strings.Replace(planSLPayload, "%d", plansItoa(pct), 1)) }

	forwardPlanStatusLine(context.Background(), srv.URL, dir, payload(42), now)
	if posts.Load() != 1 {
		t.Fatalf("first reading: %d posts", posts.Load())
	}
	for _, leak := range []string{"secret-model", "/home/me/secret", "total_cost_usd", "1.5"} {
		if bytes.Contains(last, []byte(leak)) {
			t.Fatalf("forward carries %q: %s", leak, last)
		}
	}
	forwardPlanStatusLine(context.Background(), srv.URL, dir, payload(42), now)
	if posts.Load() != 1 {
		t.Fatal("an unchanged reading was forwarded again")
	}
	forwardPlanStatusLine(context.Background(), srv.URL, dir, payload(43), now)
	if posts.Load() != 2 {
		t.Fatal("a changed reading was not forwarded")
	}
	// A refused forward is retried next time (the state file is not advanced).
	status = http.StatusServiceUnavailable
	forwardPlanStatusLine(context.Background(), srv.URL, dir, payload(44), now)
	status = http.StatusNoContent
	forwardPlanStatusLine(context.Background(), srv.URL, dir, payload(44), now)
	if posts.Load() != 4 {
		t.Fatalf("a refused forward was not retried: %d posts", posts.Load())
	}
	// No rate_limits (an API-key user): nothing is sent.
	forwardPlanStatusLine(context.Background(), srv.URL, dir, []byte(`{"session_id":"s1"}`), now)
	if posts.Load() != 4 {
		t.Fatal("a payload without rate_limits was forwarded")
	}
	if _, err := os.Stat(filepath.Join(dir, planForwardStateFile)); err != nil {
		t.Fatalf("state file: %v", err)
	}
}

func plansItoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestPrintPlanUsage(t *testing.T) {
	at := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	r := planlimits.Reconcile(
		[]planlimits.UsageDay{{Day: "2026-10-30", Tokens: 136533390}, {Day: "2026-10-08", Tokens: 23252828}},
		map[string]int64{"2026-10-08": 21921453, "2026-10-09": 5},
		"2026-10-03", "2026-11-01")
	var out bytes.Buffer
	printPlanUsage(&out, planlimitssvc.UsageView{
		AccountID: "a1", Provider: planlimits.ProviderChatGPT, Available: true, Days: 30,
		FetchedAt: &at, Tools: []string{"codex"}, Reconciliation: &r,
	})
	s := out.String()
	for _, want := range []string{
		"ChatGPT and Codex usage by day, 2026-10-03 to 2026-11-01",
		"136,533,390", "21,921,453", "1,331,375", "94%", "none reported",
		"Not captured here: Codex cloud chats, other devices or sessions Observer did not run on.",
		"account-wide", "codex sessions for any login",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "$") || strings.Contains(s, "USD") {
		t.Errorf("usage is tokens only, never dollars:\n%s", s)
	}
	out.Reset()
	printPlanUsage(&out, planlimitssvc.UsageView{AccountID: "a1", Provider: planlimits.ProviderChatGPT, Available: true})
	if !strings.Contains(out.String(), "no daily usage read yet") {
		t.Errorf("before a reading: %s", out.String())
	}
	if got := planTokens(1234567); got != "1,234,567" {
		t.Errorf("planTokens = %s", got)
	}
}
