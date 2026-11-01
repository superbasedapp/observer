package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestBaseURLRewriteManagedPresets pins the pure half of CLI-8 (D13): a preset that
// points elsewhere is rewritten in place (every duplicate entry too), a
// preset equal to the launcher's value is kept, and a key the launcher does
// not inject is never touched.
func TestBaseURLRewriteManagedPresets(t *testing.T) {
	inject := map[string]string{
		"ANTHROPIC_BASE_URL": "http://127.0.0.1:8820",
		"OPENAI_BASE_URL":    "http://127.0.0.1:8820/v1",
	}
	env := []string{
		"PATH=/bin",
		"ANTHROPIC_BASE_URL=https://gateway.example.com",
		"OPENAI_BASE_URL=http://127.0.0.1:8820/v1",
		"ANTHROPIC_BASE_URL=https://other.example.com",
	}
	out, kept, rewrote := rewriteManagedPresets(env, inject, []string{"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "UNRELATED"})
	want := []string{
		"PATH=/bin",
		"ANTHROPIC_BASE_URL=http://127.0.0.1:8820",
		"OPENAI_BASE_URL=http://127.0.0.1:8820/v1",
		"ANTHROPIC_BASE_URL=http://127.0.0.1:8820",
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("env = %v", out)
	}
	if !reflect.DeepEqual(kept, []string{"OPENAI_BASE_URL", "UNRELATED"}) {
		t.Fatalf("kept = %v", kept)
	}
	if len(rewrote) != 1 || rewrote[0].Key != "ANTHROPIC_BASE_URL" || rewrote[0].Was != "https://other.example.com" {
		t.Fatalf("rewrote = %+v", rewrote)
	}
	if env[1] != "ANTHROPIC_BASE_URL=https://gateway.example.com" {
		t.Fatal("the caller's env slice was modified")
	}
}

// TestBaseURLManagedPresetRewrite: one case per row of the CLI-8 rule. Only a
// managed node whose organization owns the route, with a live proxy and a
// routed launch, rewrites; an individual node keeps the developer's preset.
func TestBaseURLManagedPresetRewrite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	live := "http://" + ln.Addr().String()
	dead := "http://127.0.0.1:1"

	inject := map[string]string{"ANTHROPIC_BASE_URL": live}
	env := []string{"ANTHROPIC_BASE_URL=https://gateway.example.com"}
	for _, tc := range []struct {
		name     string
		owns     bool
		proxyURL string
		presets  []string
		unrouted bool
		rewrite  bool
	}{
		{"managed, org owns the route", true, live, []string{"ANTHROPIC_BASE_URL"}, false, true},
		{"individual node keeps the preset", false, live, []string{"ANTHROPIC_BASE_URL"}, false, false},
		{"proxy not listening keeps the preset", true, dead, []string{"ANTHROPIC_BASE_URL"}, false, false},
		{"unrouted launch keeps the preset", true, live, []string{"ANTHROPIC_BASE_URL"}, true, false},
		{"no preset, nothing to do", true, live, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore := launchOrgOwnsRoute
			asked := false
			launchOrgOwnsRoute = func(context.Context, string) bool { asked = true; return tc.owns }
			defer func() { launchOrgOwnsRoute = restore }()
			var buf bytes.Buffer
			out, kept, rewrote := applyManagedPresetRewrite(context.Background(), &buf, "claude", "", tc.proxyURL, env, inject, tc.presets, tc.unrouted)
			if tc.rewrite {
				if envValue(out, "ANTHROPIC_BASE_URL") != live || len(kept) != 0 || !reflect.DeepEqual(rewrote, []string{"ANTHROPIC_BASE_URL"}) {
					t.Fatalf("out %v kept %v rewrote %v", out, kept, rewrote)
				}
				if !strings.Contains(buf.String(), "your organization routes AI tools through the Observer proxy") {
					t.Fatalf("no notice: %q", buf.String())
				}
				return
			}
			if envValue(out, "ANTHROPIC_BASE_URL") != "https://gateway.example.com" || len(rewrote) != 0 || buf.Len() != 0 {
				t.Fatalf("rewrote where it must not: out %v rewrote %v %q", out, rewrote, buf.String())
			}
			if (tc.presets == nil || tc.unrouted) && asked {
				t.Fatal("the governance posture was read when nothing could be rewritten")
			}
		})
	}
}

// TestManagedIntegrityVendorPolicyRisks (S-15, D17): a cached vendor policy that blocks
// Observer's MCP server or pins a tool's route crosses as a standing label
// located on the tool and the cache directory; a route veto where Observer
// writes no route does not cross, and nothing read from the cache does.
func TestManagedIntegrityVendorPolicyRisks(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".factory", "org-managed-settings.cache.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"managedSettings":{"mcpPolicy":{"enabled":true,"allowlist":[]},"modelPolicy":{"allowCustomModels":false}},"orgId":"org-secret-id"}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var rep orgcontract.ManagedIntegrityReport
	addVendorPolicyRisks(home, func(string) string { return "" }, &rep)
	if !reflect.DeepEqual(rep.CaptureRisks, []string{orgcontract.CaptureRiskVendorPolicyBlocksMCP}) {
		t.Fatalf("risks = %v", rep.CaptureRisks)
	}
	want := []orgcontract.CaptureRiskItem{{Risk: orgcontract.CaptureRiskVendorPolicyBlocksMCP, Tool: "droid", File: "~/.factory"}}
	if !reflect.DeepEqual(rep.CaptureRiskItems, want) {
		t.Fatalf("items = %+v", rep.CaptureRiskItems)
	}
	raw, _ := json.Marshal(rep)
	if bytes.Contains(raw, []byte("org-secret-id")) {
		t.Fatalf("a value read from the cache crossed: %s", raw)
	}
	var clean orgcontract.ManagedIntegrityReport
	addVendorPolicyRisks(t.TempDir(), nil, &clean)
	if len(clean.CaptureRisks) != 0 || len(clean.CaptureRiskItems) != 0 {
		t.Fatalf("an empty home reported %+v", clean)
	}
}

// TestBaseURLRewriteOnlyURLKeys (audit follow-up 4): a non-URL routing key
// the launcher also sets (a provider type, a model) keeps the developer's
// value; only a base URL is rewritten.
func TestBaseURLRewriteOnlyURLKeys(t *testing.T) {
	inject := map[string]string{
		"COPILOT_PROVIDER_BASE_URL": "http://127.0.0.1:8820/v1",
		"COPILOT_PROVIDER_TYPE":     "openai",
		"COPILOT_MODEL":             "gpt-5",
	}
	env := []string{"COPILOT_PROVIDER_BASE_URL=https://azure.example/openai", "COPILOT_PROVIDER_TYPE=azure", "COPILOT_MODEL=custom"}
	out, kept, rewrote := rewriteManagedPresets(env, inject, []string{"COPILOT_MODEL", "COPILOT_PROVIDER_BASE_URL", "COPILOT_PROVIDER_TYPE"})
	if len(rewrote) != 1 || rewrote[0].Key != "COPILOT_PROVIDER_BASE_URL" {
		t.Fatalf("rewrote = %+v", rewrote)
	}
	if !reflect.DeepEqual(kept, []string{"COPILOT_MODEL", "COPILOT_PROVIDER_TYPE"}) {
		t.Fatalf("kept = %v", kept)
	}
	if envValue(out, "COPILOT_PROVIDER_TYPE") != "azure" || envValue(out, "COPILOT_MODEL") != "custom" {
		t.Fatalf("a non-URL key was rewritten: %v", out)
	}
}

// TestBaseURLPrintableDropsSecrets (audit follow-up 4): the rewrite notice
// never prints userinfo, a query or a fragment.
func TestBaseURLPrintableDropsSecrets(t *testing.T) {
	for in, want := range map[string]string{
		"https://user:pass@gw.example/v1?api_key=sk-1#frag": "https://gw.example/v1",
		"https://gw.example/v1?":                            "https://gw.example/v1",
		"http://127.0.0.1:8820":                             "http://127.0.0.1:8820",
		"not a url":                                         "(a value that is not a URL)",
	} {
		got := printableBaseURL(in)
		if got != want || strings.Contains(got, "pass") || strings.Contains(got, "sk-1") {
			t.Errorf("printableBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
	var buf bytes.Buffer
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	live := "http://" + ln.Addr().String()
	restore := launchOrgOwnsRoute
	launchOrgOwnsRoute = func(context.Context, string) bool { return true }
	defer func() { launchOrgOwnsRoute = restore }()
	applyManagedPresetRewrite(context.Background(), &buf, "claude", "", live,
		[]string{"ANTHROPIC_BASE_URL=https://me:hunter2@gw.example/v1?token=abc"}, map[string]string{"ANTHROPIC_BASE_URL": live}, []string{"ANTHROPIC_BASE_URL"}, false)
	if s := buf.String(); s == "" || strings.Contains(s, "hunter2") || strings.Contains(s, "token=abc") {
		t.Fatalf("notice = %q", s)
	}
}

// TestBaseURLOrgOwnsRouteIndividualNode (audit follow-up 3): on a node with
// no verified managed org lock the posture check opens no database.
func TestBaseURLOrgOwnsRouteIndividualNode(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	db := filepath.Join(dir, "observer.db")
	if err := os.WriteFile(cfg, []byte("[observer]\ndb_path = \""+filepath.ToSlash(db)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if launchOrgOwnsRoute(context.Background(), cfg) {
		t.Fatal("an individual node read as org-owned routes")
	}
	if _, err := os.Stat(db); err == nil {
		t.Fatal("the route posture check opened a database on an individual node")
	}
}
