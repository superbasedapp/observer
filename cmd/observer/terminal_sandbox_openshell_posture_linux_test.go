//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// TestOpenShellGatewayDriftReadBack walks the read-back over a real state
// dir (lane O4): no managed gateway, Observer's own config, a config
// changed or removed outside Observer, a start in progress (the config is
// the current render, the record still the previous start's), and a record
// that does not parse. Then the seam turns a change into the closed
// capture-risk label and an unknown into the unknown check.
func TestOpenShellGatewayDriftReadBack(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "sandbox-openshell")
	render := func(sandboxopenshell.GatewayIdentity, string, string) (string, error) { return "rendered = 2\n", nil }
	classify := func() sandboxopenshell.GatewayDrift {
		d, _ := sandboxopenshell.ClassifyGatewayDrift(openShellGatewayDriftFacts(stateDir, render))
		return d
	}
	if got := classify(); got != sandboxopenshell.GatewayDriftNone {
		t.Fatalf("no state dir: %s", got)
	}
	installID, err := openShellInstallID(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := sandboxopenshell.IdentityFor(installID)
	if err != nil {
		t.Fatal(err)
	}
	l, err := sandboxopenshell.LayoutFor(stateDir, openShellDriftRuntimePlaceholder, id)
	if err != nil {
		t.Fatal(err)
	}
	// An install id alone (an external-mode run minted it) is no gateway.
	if got := classify(); got != sandboxopenshell.GatewayDriftNone {
		t.Fatalf("install id only: %s", got)
	}
	if err := os.MkdirAll(l.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(p, body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	started := "rendered = 1\n"
	rec, _ := json.Marshal(sandboxopenshell.GatewayRecord{Name: id.Name, Unit: id.Unit, ConfigDigest: sandboxopenshell.GatewayConfigDigest(started, "")})
	write(l.RecordPath, string(rec))
	write(l.ConfigPath, started)
	if got := classify(); got != sandboxopenshell.GatewayDriftMatch {
		t.Fatalf("Observer's own config: %s", got)
	}
	write(l.ConfigPath, "rendered = 2\n")
	if got := classify(); got != sandboxopenshell.GatewayDriftMatch {
		t.Fatalf("a start in progress (current render, previous record): %s", got)
	}
	write(l.ConfigPath, started+"enable_bind_mounts = false\n")
	if got := classify(); got != sandboxopenshell.GatewayDriftChanged {
		t.Fatalf("changed outside Observer: %s", got)
	}
	if err := os.Remove(l.ConfigPath); err != nil {
		t.Fatal(err)
	}
	if got := classify(); got != sandboxopenshell.GatewayDriftChanged {
		t.Fatalf("removed outside Observer: %s", got)
	}
	write(l.ConfigPath, started)
	write(l.RecordPath, "{not json")
	if got := classify(); got != sandboxopenshell.GatewayDriftUnknown {
		t.Fatalf("a record that does not parse: %s", got)
	}
	// The record and the config both removed while the gateway's own
	// database remains (a gateway ran here): changed (D0), never the clean
	// "no managed gateway". Without the database the dir is only what an
	// ensure made before a start: none (D1).
	write(l.DBPath, "")
	for _, p := range []string{l.RecordPath, l.ConfigPath} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	if got := classify(); got != sandboxopenshell.GatewayDriftChanged {
		t.Fatalf("record and config removed, database kept: %s", got)
	}
	if err := os.Remove(l.DBPath); err != nil {
		t.Fatal(err)
	}
	if got := classify(); got != sandboxopenshell.GatewayDriftNone {
		t.Fatalf("an empty gateway dir: %s", got)
	}

	// The seam: a change is the capture-risk label, an unknown the unknown
	// check, a clean reading nothing; never a path.
	prev := sandboxGatewayDriftObserved
	t.Cleanup(func() { sandboxGatewayDriftObserved = prev })
	for _, tc := range []struct {
		drift         sandboxGatewayDrift
		risk, unknown bool
	}{
		{sandboxGatewayDriftClean, false, false},
		{sandboxGatewayDriftChanged, true, false},
		{sandboxGatewayDriftUnknown, false, true},
	} {
		sandboxGatewayDriftObserved = func(string) sandboxGatewayDrift { return tc.drift }
		var rep orgcontract.ManagedIntegrityReport
		addSandboxGatewayPosture("", &rep)
		if got := slices.Contains(rep.CaptureRisks, orgcontract.CaptureRiskSandboxGatewayConfigDrift); got != tc.risk {
			t.Errorf("drift %d: risk label %v, want %v", tc.drift, got, tc.risk)
		}
		if got := slices.Contains(rep.UnknownChecks, orgcontract.CaptureUnknownSandboxGatewayConfig); got != tc.unknown {
			t.Errorf("drift %d: unknown check %v, want %v", tc.drift, got, tc.unknown)
		}
	}
	// The registered read-back is this driver's.
	if prev == nil {
		t.Fatal("the openshell driver did not register its read-back")
	}
}

// TestOpenShellGatewayDriftUnderItsOwnNamespace (integration of lanes O4
// and OC2): the read-back renders the current config under the namespace
// the recorded gateway runs under, so a gateway in its own namespace reads
// clean, whether its record stores the label or (written by the first OC2
// build) only a digest that matches it; a config whose namespace differs
// from what the gateway runs under reads changed.
func TestOpenShellGatewayDriftUnderItsOwnNamespace(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "sandbox-openshell")
	installID, err := openShellInstallID(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := sandboxopenshell.IdentityFor(installID)
	if err != nil {
		t.Fatal(err)
	}
	l, err := sandboxopenshell.LayoutFor(stateDir, openShellDriftRuntimePlaceholder, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(l.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	render := func(label string) string {
		t.Helper()
		s, err := openShellRenderGatewayConfig(id, label, "")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	own, def := render(id.Name), render(sandboxopenshell.DefaultSandboxLabel)
	write := func(rec sandboxopenshell.GatewayRecord, config string) {
		t.Helper()
		b, _ := json.Marshal(rec)
		if err := os.WriteFile(l.RecordPath, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(l.ConfigPath, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	classify := func() (sandboxopenshell.GatewayDrift, sandboxopenshell.GatewayDriftFacts) {
		f := openShellGatewayDriftFacts(stateDir, openShellRenderGatewayConfig)
		d, _ := sandboxopenshell.ClassifyGatewayDrift(f)
		return d, f
	}
	base := sandboxopenshell.GatewayRecord{Name: id.Name, Unit: id.Unit, DockerHost: "unix:///run/d.sock"}
	for _, tc := range []struct {
		why    string
		label  string
		digest string
		config string
		want   sandboxopenshell.GatewayDrift
		wanted bool
	}{
		// A start in progress (the record still names an earlier config):
		// only the render under the running namespace can match.
		{"own label recorded, config its render", id.Name, sandboxopenshell.GatewayConfigDigest("earlier = 1\n", base.DockerHost), own, sandboxopenshell.GatewayDriftMatch, true},
		{"no label, own-name digest, config its render", "", sandboxopenshell.GatewayConfigDigest(own, base.DockerHost), own, sandboxopenshell.GatewayDriftMatch, true},
		{"default label recorded, config its render", sandboxopenshell.DefaultSandboxLabel, sandboxopenshell.GatewayConfigDigest("earlier = 1\n", base.DockerHost), def, sandboxopenshell.GatewayDriftMatch, true},
		// The namespace in the config is not the one the gateway runs under.
		{"own label recorded, config in the default namespace", id.Name, sandboxopenshell.GatewayConfigDigest(own, base.DockerHost), def, sandboxopenshell.GatewayDriftChanged, false},
		{"default label recorded, config in its own namespace", sandboxopenshell.DefaultSandboxLabel, sandboxopenshell.GatewayConfigDigest(def, base.DockerHost), own, sandboxopenshell.GatewayDriftChanged, false},
	} {
		rec := base
		rec.SandboxLabel, rec.ConfigDigest = tc.label, tc.digest
		write(rec, tc.config)
		got, f := classify()
		if got != tc.want || f.MatchesWanted != tc.wanted {
			t.Errorf("%s: %s (matches wanted %v), want %s (%v)", tc.why, got, f.MatchesWanted, tc.want, tc.wanted)
		}
	}
}
