//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam/terminalsisolation"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestSandboxCLILoadsOrgFloors (O5 sweep G-H1, adversarial rows A8 and
// A13): a sandboxed CLI launch (`observer <tool> --observer-sandbox ...`)
// judges against the organization's isolation floors the daemon installed,
// read from the verified cache, so a gateway_modes = [managed_local] floor
// reaches every sandboxOrgFloors() reader (the probe's selection input and
// the openshell driver's floor() re-check). Before the fix this process
// judged against no floor. A floor that may be in force but cannot be read
// refuses the launch with org_floors_unreadable. Not parallel:
// process-wide floors.
func TestSandboxCLILoadsOrgFloors(t *testing.T) {
	prevCached, prevHere := sandboxCachedIsolationSpec, policyResourceInstalledHere.Load()
	t.Cleanup(func() {
		sandboxCachedIsolationSpec = prevCached
		policyResourceInstalledHere.Store(prevHere)
		isolationFloorsClear()
	})
	policyResourceInstalledHere.Store(false) // a CLI process
	isolationFloorsClear()
	spec := terminalsisolation.PolicySpec{GatewayModes: []string{"managed_local"}, FloorAcceptsBeta: true, Keys: []string{"gateway_modes", "floor_accepts_beta"}}
	sandboxCachedIsolationSpec = func(context.Context, config.Config) (terminalsisolation.PolicySpec, bool, error) {
		return spec, true, nil
	}
	if err := installCLIIsolationFloors(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	f := sandboxOrgFloors()
	if !f.InForce() || !slices.Equal(f.AllowedGatewayModes, []vocab.GatewayMode{vocab.GatewayManagedLocal}) {
		t.Fatalf("the CLI process did not install the cached gateway_modes floor: %+v", f)
	}

	// A withdrawal in the cache clears what an earlier read installed.
	sandboxCachedIsolationSpec = func(context.Context, config.Config) (terminalsisolation.PolicySpec, bool, error) {
		return terminalsisolation.PolicySpec{}, false, nil
	}
	if err := installCLIIsolationFloors(context.Background(), config.Default()); err != nil || sandboxOrgFloors().InForce() {
		t.Fatalf("no floor in the cache left a floor in force: %v %+v", err, sandboxOrgFloors())
	}

	// A daemon process keeps the floors it installed itself.
	policyResourceInstalledHere.Store(true)
	sandboxCachedIsolationSpec = func(context.Context, config.Config) (terminalsisolation.PolicySpec, bool, error) {
		t.Fatal("a daemon process read the cache")
		return terminalsisolation.PolicySpec{}, false, nil
	}
	if err := installCLIIsolationFloors(context.Background(), config.Default()); err != nil {
		t.Fatal(err)
	}
	policyResourceInstalledHere.Store(false)

	// Unreadable: the launch itself refuses, naming why, and runs nothing.
	sandboxCachedIsolationSpec = func(context.Context, config.Config) (terminalsisolation.PolicySpec, bool, error) {
		return terminalsisolation.PolicySpec{}, false, errors.Join(errOrgFloorsUnreadable, errors.New("sentinel"))
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "o.db")) + "\"\n" +
		"[components]\ndistro = \"developer\"\nadd = [\"terminals.sandbox\"]\n[terminal.sandbox]\nenabled = true\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	req := sandboxCLIRequest{Verb: "claude", Tool: "claude-code", Profile: "bwrap", ConfigPath: cfgPath}
	if code := runSandboxCLI(context.Background(), req, &stderr); code != sandboxCLIUnavailable || !strings.Contains(stderr.String(), "org_floors_unreadable") {
		t.Fatalf("unreadable floors: code %d %q", code, stderr.String())
	}
}

// TestSandboxFloorsDBOpenFailureNamesTheDatabase (O5 audit finding O5-A5):
// a node database that exists but does not open still fails closed (a
// floor may be recorded there), and the refusal names the node database
// and its path rather than blaming the organization. Tracker F-032: it
// stays a refusal on a node that was never enrolled (nothing outside the
// database proves that; with no [org_client] block at all, as here, the
// node still refuses), and it says how to recover.
func TestSandboxFloorsDBOpenFailureNamesTheDatabase(t *testing.T) {
	cfg := config.Default()
	cfg.Observer.DBPath = t.TempDir() // a directory: it exists and never opens as a database
	if cfg.OrgClient.Enabled || cfg.OrgClient.OrgServerURL != "" {
		t.Fatalf("the default config looks enrolled: %+v", cfg.OrgClient)
	}
	_, ok, err := sandboxCachedIsolationSpec(context.Background(), cfg)
	if ok || !errors.Is(err, errOrgFloorsUnreadable) {
		t.Fatalf("ok %v err %v, want an org_floors_unreadable refusal", ok, err)
	}
	for _, want := range []string{"node database", cfg.Observer.DBPath, "could not be read to check for organization floors", "observer doctor", "move the database file aside together with its -wal and -shm files", "observer.db-wal", "must enroll again"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not name %q", err, want)
		}
	}
}

// TestSandboxStatusSaysFloorsUnreadable (O5 audit finding O5-A5): when the
// floors cannot be read, `observer sandbox status` says every sandboxed
// launch refuses, so status never reads as launchable while launch refuses.
func TestSandboxStatusSaysFloorsUnreadable(t *testing.T) {
	cases := []struct {
		name, unreadable string
		want             bool
	}{
		{"readable floors print nothing", "", false},
		{"unreadable floors are said", "org_floors_unreadable: sentinel", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			st := sandboxStatusReport{Enabled: true, Egress: "proxy_only", Host: "linux", OrgFloorsUnreadable: tc.unreadable}
			if err := renderSandboxStatus(&out, st); err != nil {
				t.Fatal(err)
			}
			got := strings.Contains(out.String(), "Organization floors: org_floors_unreadable: sentinel; every sandboxed launch refuses")
			if got != tc.want {
				t.Fatalf("line shown %v, want %v:\n%s", got, tc.want, out.String())
			}
		})
	}
}
