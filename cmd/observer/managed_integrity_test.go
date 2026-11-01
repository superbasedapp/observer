package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// TestCollectIntegritySignals asserts the boundary seam assembles coarse labels
// from the diag + proxyroute detectors: a cross-OS sibling observer.db becomes
// an "origin/os" label, and a claude route repointed off observer becomes the
// "claude-code" drifted-tool label. Only labels are produced (no paths).
func TestCollectIntegritySignals(t *testing.T) {
	nativeHome := t.TempDir()
	foreignHome := t.TempDir()

	// Daemon's own DB in the native home.
	daemonDir := filepath.Join(nativeHome, ".observer")
	if err := os.MkdirAll(daemonDir, 0o755); err != nil {
		t.Fatal(err)
	}
	daemonDB := filepath.Join(daemonDir, "observer.db")
	if err := os.WriteFile(daemonDB, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A cross-OS sibling observer.db in a foreign home.
	fdir := filepath.Join(foreignHome, ".observer")
	if err := os.MkdirAll(fdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fdir, "observer.db"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A drifted claude route in the native home.
	cdir := filepath.Join(nativeHome, ".claude")
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, "settings.json"),
		[]byte(`{"env":{"ANTHROPIC_BASE_URL":"https://api.anthropic.com"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	homes := []crossmount.HomeRoot{
		{Path: nativeHome, OS: "linux", Origin: "native"},
		{Path: foreignHome, OS: "windows", Origin: "wsl-mnt:marmu"},
	}
	report := collectIntegritySignalsFrom(daemonDB, nativeHome, "/current/observer", homes, maintainedRoutes)

	if len(report.SiblingDetail) != 1 || report.SiblingDetail[0] != "wsl-mnt/windows" {
		t.Errorf("siblings = %v, want [wsl-mnt/windows]", report.SiblingDetail)
	}
	if len(report.DriftedTools) != 1 || report.DriftedTools[0] != "claude-code" {
		t.Errorf("drifted = %v, want [claude-code]", report.DriftedTools)
	}
	if report.CaptureCheckVersion != 1 {
		t.Errorf("capture check version = %d, want 1", report.CaptureCheckVersion)
	}
	wire, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{nativeHome, foreignHome, "marmu", "/home/", "Users"} {
		if strings.Contains(string(wire), forbidden) {
			t.Errorf("managed-integrity wire leaked host identity/path %q: %s", forbidden, wire)
		}
	}
}

// TestCollectIntegritySignals_Clean: default-path daemon + observer-pointing
// route yields no evidence.
func TestCollectIntegritySignals_Clean(t *testing.T) {
	nativeHome := t.TempDir()
	// The kimi-code / qwen-code / crush readers resolve their config path
	// through env vars; pin them at this fixture host so the RUNNING
	// developer's own configs can never be inspected by this test.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(nativeHome, ".config"))
	t.Setenv("CRUSH_GLOBAL_CONFIG", "")
	t.Setenv("KIMI_CODE_HOME", "")
	t.Setenv("QWEN_HOME", "")
	daemonDir := filepath.Join(nativeHome, ".observer")
	if err := os.MkdirAll(daemonDir, 0o755); err != nil {
		t.Fatal(err)
	}
	daemonDB := filepath.Join(daemonDir, "observer.db")
	if err := os.WriteFile(daemonDB, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cdir := filepath.Join(nativeHome, ".claude")
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, "settings.json"),
		[]byte(`{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	homes := []crossmount.HomeRoot{{Path: nativeHome, OS: "linux", Origin: "native"}}
	report := collectIntegritySignalsFrom(daemonDB, nativeHome, "/current/observer", homes, noPostureRoutes)
	if len(report.SiblingDetail) != 0 || len(report.DriftedTools) != 0 {
		t.Errorf("clean host produced evidence: siblings=%v drifted=%v", report.SiblingDetail, report.DriftedTools)
	}

	// Track C item 2, corrected by adversarial finding P1-2: the SAME clean
	// host, read under an org that is authoritative over an enforcement point
	// here. claude-code is routed, and NO OTHER inspected tool is installed on
	// this fixture host — so there is still nothing to report. A single-tool
	// developer must not light up as a four-tool bypass the moment the
	// stricter reading ships.
	managed := collectIntegritySignalsFrom(daemonDB, nativeHome, "/current/observer", homes, maintainedRoutes)
	if len(managed.DriftedTools) != 0 {
		t.Errorf("managed+enforce host reported drift for tools that are not installed: %v", managed.DriftedTools)
	}

	// Install codex — its config is now ON the host and names no route. THAT
	// is the shape an enforcing managed node reads as drift.
	codexDir := filepath.Join(nativeHome, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"),
		[]byte("model = \"gpt-5\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	managed = collectIntegritySignalsFrom(daemonDB, nativeHome, "/current/observer", homes, maintainedRoutes)
	if len(managed.DriftedTools) != 1 || managed.DriftedTools[0] != "codex" {
		t.Errorf("drifted = %v, want [codex] (config present, route key gone)", managed.DriftedTools)
	}
	if managed.RouteDrift != len(managed.DriftedTools) {
		t.Errorf("RouteDrift = %d, want %d", managed.RouteDrift, len(managed.DriftedTools))
	}
	// With no route posture the organization wrote no route here, so the
	// same absent route key is the developer's own setup, not drift.
	if indiv := collectIntegritySignalsFrom(daemonDB, nativeHome, "/current/observer", homes, noPostureRoutes); len(indiv.DriftedTools) != 0 {
		t.Errorf("no posture reported drift for a route the organization never wrote: %v", indiv.DriftedTools)
	}
}

// maintainedRoutes / noPostureRoutes are the drift readings of a node whose
// routes are maintained and of a node with no route posture (ports not
// compared).
var (
	maintainedRoutes = proxyroute.DriftPolicy{Mode: proxyroute.DriftModeMaintained}
	noPostureRoutes  = proxyroute.DriftPolicy{Mode: proxyroute.DriftModeOrgRoutes}
)

// TestRouteDriftPolicyFollowsPosture pins T-900: the probe's drift reading
// follows govern.Effective.RoutePosture, one case per posture rule
// (govern/routeposture.go rules 1 to 5), and carries the daemon's own
// listener port for the T-901 port comparison.
func TestRouteDriftPolicyFollowsPosture(t *testing.T) {
	cases := []struct {
		name    string
		verdict govern.RoutePostureVerdict
		want    proxyroute.DriftMode
	}{
		{
			"rule 1, not managed or grant refused: only organization routes left in place",
			govern.RoutePostureVerdict{Posture: govern.RoutePostureNone, Source: govern.RoutePostureSourceNotManaged},
			proxyroute.DriftModeOrgRoutes,
		},
		{
			"rule 2, admin ON: maintained",
			govern.RoutePostureVerdict{Posture: govern.RoutePostureMaintain, Source: govern.RoutePostureSourceAdminOn},
			proxyroute.DriftModeMaintained,
		},
		{
			"rule 3, admin OFF: nothing is drift",
			govern.RoutePostureVerdict{Posture: govern.RoutePostureRelease, Source: govern.RoutePostureSourceAdminOff},
			proxyroute.DriftModeOff,
		},
		{
			"rule 4, unset with a proxy enforcement point: maintained",
			govern.RoutePostureVerdict{Posture: govern.RoutePostureMaintain, Source: govern.RoutePostureSourceEnforceDefault},
			proxyroute.DriftModeMaintained,
		},
		{
			"rule 5, unset without one (D-738 leaves routes in place): only organization routes",
			govern.RoutePostureVerdict{Posture: govern.RoutePostureNone, Source: govern.RoutePostureSourceNotRequired},
			proxyroute.DriftModeOrgRoutes,
		},
		{
			"a posture the table does not name reads on the loud side",
			govern.RoutePostureVerdict{Posture: "future"},
			proxyroute.DriftModeMaintained,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := routeDriftPolicy(tc.verdict, 9100, proxyroute.Selection{})
			if got.Mode != tc.want || got.ProxyPort != 9100 {
				t.Fatalf("routeDriftPolicy = %+v, want mode %q on port 9100", got, tc.want)
			}
		})
	}
	for _, p := range []govern.RoutePosture{govern.RoutePostureNone, govern.RoutePostureMaintain, govern.RoutePostureRelease} {
		if _, ok := routeDriftModes[p]; !ok {
			t.Errorf("posture %q has no routeDriftModes row", p)
		}
	}
}
