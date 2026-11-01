//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

// TestTheOnlineFloorReachesTheInstallGate (SEC-E merge audit finding 3): an
// individual node that accepted the online-check disclosure sends nothing
// online once the org's privacy floor allow.online_checks = forbidden is in
// force: the install gate's online check (onlineReady, the Enabled input of
// every lookup service), the hook's settings file and the dashboard card all
// read the floored value, live and with no config edit.
func TestTheOnlineFloorReachesTheInstallGate(t *testing.T) {
	withSecurityScanningNode(t, false, config.DefaultSecurityConfig(), securityDepsComponent)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	writeFile(t, cfgPath, "[security.deps]\nonline = true\n")
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil || !cfg.Security.Deps.Online {
		t.Fatalf("load %v %+v", err, cfg.Security.Deps)
	}
	secDir := filepath.Join(dir, "security")
	live := newDepsLiveDeps(cfgPath, secDir, cfg.Security)
	live.setServing(true)
	shown := secfeed.Disclosure{Version: secfeed.DisclosureVersion, ShownAt: time.Now(), Surface: "cli", Verified: true}
	env := &depsEnv{cfg: cfg, live: live, disclose: shown}
	if !env.onlineReady() {
		t.Fatal("control: online checks run before the floor")
	}
	installFloor(t, `{"allow":{"online_checks":"forbidden"}}`, 1, true)
	if env.onlineReady() {
		t.Fatal("the daemon's online gate ignores allow.online_checks = forbidden")
	}
	if s := readDepsHookSettings(secDir); s.Ask || s.Online {
		t.Fatalf("the hook's settings still ask online under the floor: %+v", s)
	}
	if (&depsEnv{cfg: cfg, disclose: shown}).onlineReady() {
		t.Fatal("the loaded-config path ignores the floor")
	}
	if st := packageChecksStatus(context.Background(), cfg, cfgPath, true, false); st.Online {
		t.Fatal("the dashboard card shows online checks on under the floor")
	}
	// The floor leaves: online checks come back without a config edit.
	securityScanningClear()
	if !env.onlineReady() {
		t.Fatal("online checks did not come back when the floor was cleared")
	}
	if s := readDepsHookSettings(secDir); !s.Ask || !s.Online {
		t.Fatalf("the hook's settings were not rewritten after the floor left: %+v", s)
	}
}
