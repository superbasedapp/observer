package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
)

// guardBoundaryBody builds a complete guard-section body (the form always
// sends the whole object) with the given raw JSON for the two boundary lists.
func guardBoundaryBody(allowPaths, protectedBranches string) string {
	return `{"Enabled":true,"Mode":"observe","Strict":false,"RetentionDays":180,` +
		`"Rules":{"Disable":[],"UserPolicy":"","ProjectPolicy":"","OrgBundle":"","CEL":false},` +
		`"Boundary":{"AllowPaths":` + allowPaths + `,"ProtectedBranches":` + protectedBranches + `,"ProtectedPathClasses":[]},` +
		`"Taint":{"Enabled":true,"DecayTurns":10},` +
		`"Proxy":{"EgressScan":true,"EgressAction":"flag","EgressAllow":[],"ResponseScan":true,"InjectionHeuristics":true},` +
		`"MCP":{"Pinning":true,"PoisoningHeuristics":false},` +
		`"Budget":{"SessionUSD":5,"DailyUSD":40,"Hard":false},` +
		`"Alerts":{"Desktop":true,"MinSeverity":"warn"},` +
		`"Export":{"OTel":false},` +
		`"Dialects":{"Compile":true,"Targets":["claude-code"]},` +
		`"Cloud":{"Enabled":false,"PayloadMaxBytes":0},` +
		`"Prompt":{"Enabled":true,"Mode":"ask-once","HookLane":true,"ProxyLane":true,` +
		`"EnforceIndependent":true,"ReconsiderTTL":"30m","ReconsiderMinDelay":"3s","Allow":[],"SuppressInCode":true,` +
		`"MaxFindings":64,"Detectors":{}}}`
}

// TestGuardBoundaryNoneRoundTrip pins that the guard section save can
// express all three boundary states: engine defaults (null / no line),
// a custom list, and an explicit "none" ([]), and that config.toml and a
// reload keep nil distinct from empty.
func TestGuardBoundaryNoneRoundTrip(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	seed := "[observer]\nlog_level = \"info\"\n\n[guard]\nenabled = true\nmode = \"observe\"\n\n" +
		"[guard.boundary]\nallow_paths = [\"../sibling/**\"]\nprotected_branches = [\"release\"]\n"
	if err := os.WriteFile(cfgPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	put := func(body string) {
		t.Helper()
		rr := httptest.NewRecorder()
		server.Handler().ServeHTTP(rr,
			confirmedReq(t, server, httptest.NewRequest(http.MethodPut, "/api/config/section/guard", strings.NewReader(body))))
		if rr.Code != 200 {
			t.Fatalf("PUT guard: %d body=%s", rr.Code, rr.Body.String())
		}
	}
	read := func() (string, config.GuardBoundaryConfig) {
		t.Helper()
		raw, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		return string(raw), cfg.Guard.Boundary
	}
	hasLine := func(text, key string) bool {
		return regexp.MustCompile(`(?m)^\s*` + key + `\s*=`).MatchString(text)
	}

	// None for allow paths, defaults for branches.
	put(guardBoundaryBody(`[]`, `null`))
	text, b := read()
	if !regexp.MustCompile(`(?m)^\s*allow_paths\s*=\s*\[\s*\]`).MatchString(text) {
		t.Errorf("config.toml must hold allow_paths = []:\n%s", text)
	}
	if hasLine(text, "protected_branches") {
		t.Errorf("null protected_branches must leave no line:\n%s", text)
	}
	if b.AllowPaths == nil || len(b.AllowPaths) != 0 {
		t.Errorf("AllowPaths must reload as non-nil empty, got %#v", b.AllowPaths)
	}
	if b.ProtectedBranches != nil {
		t.Errorf("ProtectedBranches must reload as nil, got %#v", b.ProtectedBranches)
	}

	// Back to engine defaults for both: null removes the line.
	put(guardBoundaryBody(`null`, `null`))
	text, b = read()
	if hasLine(text, "allow_paths") || hasLine(text, "protected_branches") {
		t.Errorf("null lists must remove both lines:\n%s", text)
	}
	if b.AllowPaths != nil || b.ProtectedBranches != nil {
		t.Errorf("both lists must reload as nil, got %#v", b)
	}

	// None for branches, a custom list for paths.
	put(guardBoundaryBody(`["../x/**"]`, `[]`))
	text, b = read()
	if !hasLine(text, "protected_branches") || b.ProtectedBranches == nil || len(b.ProtectedBranches) != 0 {
		t.Errorf("protected_branches = [] must round-trip as non-nil empty: %#v\n%s", b.ProtectedBranches, text)
	}
	if len(b.AllowPaths) != 1 || b.AllowPaths[0] != "../x/**" {
		t.Errorf("custom AllowPaths lost: %#v", b.AllowPaths)
	}
}
