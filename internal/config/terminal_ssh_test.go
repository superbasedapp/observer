package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTerminalSSHDefaults pins the [terminal.ssh] defaults after the
// 2026-08-28 operator ruling (docs/plans/ssh-remote-profiles-plan-2026-08-27.md
// §3.1, amended): the surface is VISIBLE by default (Enabled=true) but the
// profile list is EMPTY on a fresh install, so it launches nothing until an
// operator authors a [[terminal.ssh.profiles]] entry — Enabled gates
// visibility, not authority.
func TestTerminalSSHDefaults(t *testing.T) {
	t.Parallel()
	d := Default().Terminal.SSH
	if !d.Enabled {
		t.Error("terminal.ssh.enabled defaults false — the surface should be visible by default (2026-08-28 ruling); use an empty Profiles list, not Enabled, to keep a fresh install inert")
	}
	if len(d.Profiles) != 0 {
		t.Errorf("terminal.ssh.profiles defaults non-empty: %+v", d.Profiles)
	}
	if d.ConnectTimeoutSeconds != 10 || d.KeepaliveSeconds != 30 {
		t.Errorf("timeout defaults drifted: %+v", d)
	}
}

// TestTerminalSSHPartialMerge pins the same partial-merge discipline
// [terminal.sandbox] relies on: a section that sets only `enabled` keeps the
// Default()-seeded timeouts.
func TestTerminalSSHPartialMerge(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	body := `
[terminal.ssh]
enabled = true

[[terminal.ssh.profiles]]
name = "demo-box"
label = "Client demo"
host = "demo.example.com"
user = "ubuntu"
port = 2222

[[terminal.ssh.profiles]]
name = "reverse-box"
host = "reverse.example.com"
reverse_proxy = true
reverse_proxy_port = 19999
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg := Default()
	if _, err := mergeTOMLFile(&cfg, cfgPath); err != nil {
		t.Fatalf("mergeTOMLFile: %v", err)
	}
	got := cfg.Terminal.SSH
	if !got.Enabled {
		t.Error("enabled = false after an explicit true")
	}
	if got.ConnectTimeoutSeconds != 10 || got.KeepaliveSeconds != 30 {
		t.Errorf("partial [terminal.ssh] lost the timeout defaults: %+v", got)
	}
	if len(got.Profiles) != 2 {
		t.Fatalf("profiles = %d, want 2", len(got.Profiles))
	}
	p := got.Profiles[0]
	if p.Name != "demo-box" || p.Host != "demo.example.com" || p.User != "ubuntu" || p.Port != 2222 || p.Label != "Client demo" {
		t.Errorf("profile decoded wrong: %+v", p)
	}
	if p.ReverseProxy || p.ReverseProxyPort != 0 {
		t.Errorf("a profile that never mentions reverse_proxy must stay default-off: %+v", p)
	}
	rp := got.Profiles[1]
	if !rp.ReverseProxy || rp.ReverseProxyPort != 19999 {
		t.Errorf("reverse_proxy / reverse_proxy_port did not decode: %+v", rp)
	}
	if err := Validate(cfg); err != nil {
		t.Errorf("Validate rejected a legitimate config: %v", err)
	}
}

// TestTerminalSSHValidateRejectsBadProfiles pins that a malformed profile is
// LOUD AT LOAD, not silent until the operator's first click — and that it is
// rejected even when the feature is switched off (same unconditional posture as
// validateTerminalSandbox).
func TestTerminalSSHValidateRejectsBadProfiles(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ssh  TerminalSSHConfig
		want string
	}{
		{
			name: "host beginning with a dash (ssh has no -- separator)",
			ssh:  TerminalSSHConfig{Profiles: []SSHProfileConfig{{Name: "a", Host: "-oProxyCommand=x"}}},
			want: "profiles[0]",
		},
		{
			name: "relative key path",
			ssh:  TerminalSSHConfig{Profiles: []SSHProfileConfig{{Name: "a", Host: "h", KeyPath: "rel/id"}}},
			want: "profiles[0]",
		},
		{
			name: "port out of range",
			ssh:  TerminalSSHConfig{Profiles: []SSHProfileConfig{{Name: "a", Host: "h", Port: 70000}}},
			want: "profiles[0]",
		},
		{
			name: "reverse_proxy_port out of range",
			ssh:  TerminalSSHConfig{Profiles: []SSHProfileConfig{{Name: "a", Host: "h", ReverseProxyPort: 70000}}},
			want: "profiles[0]",
		},
		{
			name: "duplicate names",
			ssh: TerminalSSHConfig{Profiles: []SSHProfileConfig{
				{Name: "a", Host: "h1"}, {Name: "a", Host: "h2"},
			}},
			want: "duplicate name",
		},
		{
			name: "negative connect timeout",
			ssh:  TerminalSSHConfig{ConnectTimeoutSeconds: -1},
			want: "connect_timeout_seconds",
		},
		{
			name: "negative keepalive",
			ssh:  TerminalSSHConfig{KeepaliveSeconds: -1},
			want: "keepalive_seconds",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Enabled stays FALSE: validation must not be gated on the master
			// switch, or a typo hides until the day someone flips it.
			err := validateTerminalSSH(tc.ssh)
			if err == nil {
				t.Fatalf("validateTerminalSSH accepted %+v", tc.ssh)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestSSHProfilesConversion pins the one translation point between the TOML
// shape and the pure package.
func TestSSHProfilesConversion(t *testing.T) {
	t.Parallel()
	c := TerminalSSHConfig{
		ConnectTimeoutSeconds: 5,
		KeepaliveSeconds:      15,
		Profiles: []SSHProfileConfig{
			{
				Name: "a", Label: "A", Host: "ha", User: "u", Port: 2222, KeyPath: "/k/id", Jump: "b.example.com",
				ReverseProxy: true, ReverseProxyPort: 19999,
			},
		},
	}
	ps := SSHProfiles(c)
	if len(ps) != 1 {
		t.Fatalf("SSHProfiles len = %d", len(ps))
	}
	p := ps[0]
	if p.Name != "a" || p.Label != "A" || p.Host != "ha" || p.User != "u" || p.Port != 2222 || p.KeyPath != "/k/id" || p.Jump != "b.example.com" {
		t.Fatalf("field dropped in conversion: %+v", p)
	}
	if !p.ReverseProxy || p.ReverseProxyPort != 19999 {
		t.Fatalf("ReverseProxy / ReverseProxyPort dropped in conversion: %+v", p)
	}
	if o := SSHOptions(c); o.ConnectTimeoutSeconds != 5 || o.KeepaliveSeconds != 15 {
		t.Fatalf("SSHOptions = %+v", o)
	}
	if SSHProfiles(TerminalSSHConfig{}) != nil {
		t.Error("SSHProfiles of an empty block should be nil")
	}
}
