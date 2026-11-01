//go:build !sbo_omit_remote

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/remoteauth"
	"github.com/marmutapp/superbased-observer/internal/remotecfg"
)

// writeRemoteTestConfig writes a minimal config.toml pointing the DB (and thus
// the remote-secret file) into a temp dir, and returns the config path.
func writeRemoteTestConfig(t *testing.T) (cfgPath, dataDir string) {
	t.Helper()
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "observer.db")
	cfgPath = filepath.Join(tmp, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath, tmp
}

func runRemote(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRemoteCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// TestRemoteEnableProvisionsSecretAndConfig is the atomic-transaction happy path
// (plan §6): enable mints a hashed pairing secret (0600) and arms [remote] in
// tailscale mode with a loopback backend + the tailnet host on the allow-list.
func TestRemoteEnableProvisionsSecretAndConfig(t *testing.T) {
	cfgPath, dataDir := writeRemoteTestConfig(t)

	out, err := runRemote(t, "enable", "--tailscale", "--host", "box.tailnet-x.ts.net", "--config", cfgPath)
	if err != nil {
		t.Fatalf("remote enable: %v\n%s", err, out)
	}
	if !strings.Contains(out, "https://box.tailnet-x.ts.net/#pair=") {
		t.Errorf("enable did not print the pairing URL:\n%s", out)
	}
	if !strings.Contains(out, "tailscale serve") {
		t.Errorf("enable did not print the tailscale serve guidance:\n%s", out)
	}

	// Secret file exists, is 0600, and holds a valid argon2id hash.
	secretPath := filepath.Join(dataDir, "remote-secret")
	fi, err := os.Stat(secretPath)
	if err != nil {
		t.Fatalf("secret file missing: %v", err)
	}
	if perm := fi.Mode().Perm(); posixModes && perm != 0o600 {
		t.Errorf("secret file perm = %o, want 600", perm)
	}
	hashBytes, _ := os.ReadFile(secretPath)
	hash := strings.TrimSpace(string(hashBytes))
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("secret file does not hold an argon2id hash: %q", hash)
	}

	// Config armed correctly and re-validates.
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if !cfg.Remote.Enabled || !strings.EqualFold(cfg.Remote.Mode, "tailscale") {
		t.Errorf("remote not armed: %+v", cfg.Remote)
	}
	if !strings.HasPrefix(cfg.Remote.TailscaleBackendAddr, "127.0.0.1:") {
		t.Errorf("backend addr not a loopback port: %q", cfg.Remote.TailscaleBackendAddr)
	}
	found := false
	for _, h := range cfg.Remote.TrustedHosts {
		if h == "box.tailnet-x.ts.net" {
			found = true
		}
	}
	if !found {
		t.Errorf("tailnet host not added to trusted_hosts: %+v", cfg.Remote.TrustedHosts)
	}
	if cfg.Remote.AllowTerminal {
		t.Error("allow_terminal turned ON without --allow-terminal - execute tier must stay a separate opt-in")
	}
	if err := config.Validate(cfg); err != nil {
		t.Errorf("armed config fails validation: %v", err)
	}
}

// TestRemoteEnableRequiresHost pins that enable refuses when the tailnet host is
// unknown (no --host, no tailscale) rather than falling back to an open Host
// allow-list.
func TestRemoteEnableRequiresHost(t *testing.T) {
	cfgPath, _ := writeRemoteTestConfig(t)
	// Force detection to fail by pointing PATH at an empty dir (no tailscale).
	t.Setenv("PATH", t.TempDir())
	if _, err := runRemote(t, "enable", "--tailscale", "--config", cfgPath); err == nil {
		t.Error("enable without a resolvable tailnet host should refuse")
	}
}

// TestRemoteLANDeferred pins the operator decision: --lan refuses (Phase 3).
func TestRemoteLANDeferred(t *testing.T) {
	cfgPath, _ := writeRemoteTestConfig(t)
	if _, err := runRemote(t, "enable", "--lan", "--config", cfgPath); err == nil {
		t.Error("remote enable --lan should refuse (Phase 3 deferred)")
	}
}

// TestRemoteRotateChangesSecret pins that rotate mints a fresh hash (old one
// stops verifying) while keeping the file present.
func TestRemoteRotateChangesSecret(t *testing.T) {
	cfgPath, dataDir := writeRemoteTestConfig(t)
	if _, err := runRemote(t, "enable", "--tailscale", "--host", "box.ts.net", "--config", cfgPath); err != nil {
		t.Fatalf("enable: %v", err)
	}
	secretPath := filepath.Join(dataDir, "remote-secret")
	first, _ := os.ReadFile(secretPath)

	out, err := runRemote(t, "rotate", "--config", cfgPath)
	if err != nil {
		t.Fatalf("rotate: %v\n%s", err, out)
	}
	second, _ := os.ReadFile(secretPath)
	if strings.TrimSpace(string(first)) == strings.TrimSpace(string(second)) {
		t.Error("rotate did not change the pairing-secret hash")
	}
	if !strings.HasPrefix(strings.TrimSpace(string(second)), "$argon2id$") {
		t.Error("rotated secret is not an argon2id hash")
	}
}

// TestRemoteDisableRevokes pins that disable reverts to loopback-only and
// REMOVES the pairing secret (true revocation).
func TestRemoteDisableRevokes(t *testing.T) {
	cfgPath, dataDir := writeRemoteTestConfig(t)
	if _, err := runRemote(t, "enable", "--tailscale", "--host", "box.ts.net", "--config", cfgPath); err != nil {
		t.Fatalf("enable: %v", err)
	}
	secretPath := filepath.Join(dataDir, "remote-secret")
	if _, err := os.Stat(secretPath); err != nil {
		t.Fatalf("secret should exist after enable: %v", err)
	}

	if _, err := runRemote(t, "disable", "--config", cfgPath); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := os.Stat(secretPath); !os.IsNotExist(err) {
		t.Error("disable did not remove the pairing secret")
	}
	cfg, _ := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if cfg.Remote.Enabled || cfg.Remote.Mode != "off" {
		t.Errorf("disable did not revert to loopback-only: %+v", cfg.Remote)
	}
}

// TestRemoteEnableRoundTripsSecretVerification is an end-to-end credential check:
// the enable-printed fragment secret verifies against the stored hash.
func TestRemoteEnableRoundTripsSecretVerification(t *testing.T) {
	cfgPath, dataDir := writeRemoteTestConfig(t)
	out, err := runRemote(t, "enable", "--tailscale", "--host", "box.ts.net", "--config", cfgPath)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	// Extract the fragment secret from the printed URL.
	const marker = "#pair="
	i := strings.Index(out, marker)
	if i < 0 {
		t.Fatalf("no pairing URL in output:\n%s", out)
	}
	enc := strings.TrimSpace(strings.SplitN(out[i+len(marker):], "\n", 2)[0])

	hashBytes, _ := os.ReadFile(filepath.Join(dataDir, "remote-secret"))
	raw, err := remoteauth.DecodeSecret(enc)
	if err != nil {
		t.Fatalf("decode printed secret: %v", err)
	}
	if !remoteauth.VerifySecret(strings.TrimSpace(string(hashBytes)), raw) {
		t.Error("printed fragment secret does not verify against the stored hash")
	}
}

// TestRemoteEnableSatisfiesSubstratePredicate pins the Phase-2 contract with
// the §4.6 predicate: after `enable`, buildRemoteController returns a Ready()
// controller (secret + allow-list + rate limit assembled) — and after
// `disable`, it returns nil (fail closed) again.
func TestRemoteEnableSatisfiesSubstratePredicate(t *testing.T) {
	requireCompiled(t, "ui.dashboard")
	cfgPath, _ := writeRemoteTestConfig(t)
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if rc := buildRemoteController(cfg, nil); rc != nil {
		t.Fatal("controller non-nil before enable - must stay fail-closed by default")
	}

	if _, err := runRemote(t, "enable", "--tailscale", "--host", "box.ts.net", "--config", cfgPath); err != nil {
		t.Fatalf("enable: %v", err)
	}
	cfg, err = config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	rc := buildRemoteController(cfg, nil)
	if rc == nil || !rc.Ready() {
		t.Fatal("controller not Ready() after enable - Phase 2 must satisfy the §4.6 predicate")
	}
	found := false
	for _, h := range rc.AllowedHosts() {
		if h == "box.ts.net" {
			found = true
		}
	}
	if !found {
		t.Errorf("controller allow-list missing the tailnet host: %v", rc.AllowedHosts())
	}
	if _, err := runRemote(t, "disable", "--config", cfgPath); err != nil {
		t.Fatalf("disable: %v", err)
	}
	cfg, err = config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload after disable: %v", err)
	}
	if rc := buildRemoteController(cfg, nil); rc != nil {
		t.Error("controller non-nil after disable - must fail closed again")
	}
}

// TestBuildRemoteControllerCopiesAllowRemoteTerminalTakeover isolates the
// runtime-init default-on trap without opening a listener: both the default true
// and an explicit false must reach the controller before any dashboard toggle.
func TestBuildRemoteControllerCopiesAllowRemoteTerminalTakeover(t *testing.T) {
	requireCompiled(t, "ui.dashboard")
	cfgPath, dataDir := writeRemoteTestConfig(t)
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	raw, _, err := remoteauth.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	hash, err := remoteauth.HashSecret(raw)
	if err != nil {
		t.Fatalf("HashSecret: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "remote-secret"), []byte(hash), 0o600); err != nil {
		t.Fatalf("write pairing hash: %v", err)
	}
	cfg.Remote.Enabled = true
	cfg.Remote.BindAddr = "box.ts.net"

	for _, tc := range []struct {
		name string
		want bool
	}{
		{"default true", true},
		{"explicit false", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg.Remote.AllowRemoteTerminalTakeover = tc.want
			rc := buildRemoteController(cfg, nil)
			live, ok := rc.(interface{ AllowRemoteTerminalTakeover() bool })
			if !ok || live.AllowRemoteTerminalTakeover() != tc.want {
				t.Fatalf("controller takeover = (%v,%v), want %v", live, ok, tc.want)
			}
		})
	}
}

// TestRemoteEnableSeamMatchesCLI proves the extraction (plan §B): the CLI
// `observer remote enable` and a direct internal/remotecfg.Enable call arm an
// IDENTICAL [remote] config block and a 0600 secret — byte-identical arming
// from CLI and dashboard by construction (both call the one seam). The
// randomized backend port + secret bytes are excluded from the equality (they
// are, by design, fresh each call).
func TestRemoteEnableSeamMatchesCLI(t *testing.T) {
	const host = "box.tailnet-x.ts.net"

	// Path A: the CLI shell.
	cliCfgPath, cliDir := writeRemoteTestConfig(t)
	if _, err := runRemote(t, "enable", "--tailscale", "--host", host, "--config", cliCfgPath); err != nil {
		t.Fatalf("CLI enable: %v", err)
	}
	cliCfg, err := config.Load(config.LoadOptions{GlobalPath: cliCfgPath})
	if err != nil {
		t.Fatalf("reload CLI config: %v", err)
	}

	// Path B: the seam directly.
	seamCfgPath, seamDir := writeRemoteTestConfig(t)
	seamBase, err := config.Load(config.LoadOptions{GlobalPath: seamCfgPath})
	if err != nil {
		t.Fatalf("load seam base: %v", err)
	}
	if _, err := remotecfg.Enable(seamBase, seamCfgPath, remotecfg.EnableOptions{Host: host}); err != nil {
		t.Fatalf("seam Enable: %v", err)
	}
	seamCfg, err := config.Load(config.LoadOptions{GlobalPath: seamCfgPath})
	if err != nil {
		t.Fatalf("reload seam config: %v", err)
	}

	a, b := cliCfg.Remote, seamCfg.Remote
	if a.Enabled != b.Enabled || a.Mode != b.Mode || a.RequireTLS != b.RequireTLS ||
		a.AllowTerminal != b.AllowTerminal || a.RateLimitPerMin != b.RateLimitPerMin ||
		strings.Join(a.TrustedHosts, ",") != strings.Join(b.TrustedHosts, ",") {
		t.Errorf("CLI and seam arm different [remote] blocks:\n CLI=%+v\nseam=%+v", a, b)
	}
	// Both backends are loopback ports (value differs by design).
	if !strings.HasPrefix(a.TailscaleBackendAddr, "127.0.0.1:") || !strings.HasPrefix(b.TailscaleBackendAddr, "127.0.0.1:") {
		t.Errorf("backend addrs not loopback: CLI=%q seam=%q", a.TailscaleBackendAddr, b.TailscaleBackendAddr)
	}
	// Both secret files exist at 0600.
	for _, dir := range []string{cliDir, seamDir} {
		fi, err := os.Stat(filepath.Join(dir, "remote-secret"))
		if err != nil {
			t.Fatalf("secret missing in %s: %v", dir, err)
		}
		if perm := fi.Mode().Perm(); posixModes && perm != 0o600 {
			t.Errorf("secret perm in %s = %o, want 600", dir, perm)
		}
	}
}
