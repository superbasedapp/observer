package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sshprofile"
)

// TestRunSSHUnknownProfile pins the honest "did you mean one of these"
// error path: an unknown profile name lists the configured names, exits 1,
// and self-prints to stderr (SilenceErrors: true means main.go never prints
// the returned error itself).
func TestRunSSHUnknownProfile(t *testing.T) {
	t.Parallel()
	cfgPath := writeSSHTestConfig(t, `
[terminal.ssh]
enabled = true

[[terminal.ssh.profiles]]
name = "alpha"
host = "alpha.example.com"

[[terminal.ssh.profiles]]
name = "beta"
host = "beta.example.com"
`)
	var out, errOut bytes.Buffer
	err := runSSH(context.Background(), "gamma", sshCmdOptions{
		configPath: cfgPath,
		stdout:     &out,
		stderr:     &errOut,
	})
	assertExitErr(t, err, 1)
	if got := errOut.String(); !strings.Contains(got, `unknown profile "gamma"`) ||
		!strings.Contains(got, "alpha") || !strings.Contains(got, "beta") {
		t.Fatalf("stderr = %q, want unknown-profile message listing alpha and beta", got)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", out.String())
	}
}

// TestRunSSHNoProfilesConfigured pins the honest empty-config message
// pointing at [[terminal.ssh.profiles]] and docs/ssh-terminals.md.
func TestRunSSHNoProfilesConfigured(t *testing.T) {
	t.Parallel()
	cfgPath := writeSSHTestConfig(t, `
[terminal.ssh]
enabled = true
`)
	var out, errOut bytes.Buffer
	err := runSSH(context.Background(), "anything", sshCmdOptions{
		configPath: cfgPath,
		stdout:     &out,
		stderr:     &errOut,
	})
	assertExitErr(t, err, 1)
	got := errOut.String()
	if !strings.Contains(got, "no [[terminal.ssh.profiles]] are configured") {
		t.Fatalf("stderr = %q, want the no-profiles-configured message", got)
	}
	if !strings.Contains(got, "docs/ssh-terminals.md") {
		t.Fatalf("stderr = %q, want a pointer at docs/ssh-terminals.md", got)
	}
}

// TestRunSSHDisabledSurface pins that both cfg.Terminal.Enabled=false and
// cfg.Terminal.SSH.Enabled=false independently refuse with an honest message
// rather than a silent unknown-profile error — matching the combined-gate
// convention (attach_standalone.go / launch_dashboard.go's
// terminalLaunchPolicy).
func TestRunSSHDisabledSurface(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
	}{
		{
			name: "terminal.ssh disabled",
			body: `
[terminal.ssh]
enabled = false

[[terminal.ssh.profiles]]
name = "alpha"
host = "alpha.example.com"
`,
		},
		{
			name: "terminal disabled",
			body: `
[terminal]
enabled = false

[terminal.ssh]
enabled = true

[[terminal.ssh.profiles]]
name = "alpha"
host = "alpha.example.com"
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfgPath := writeSSHTestConfig(t, tc.body)
			var out, errOut bytes.Buffer
			err := runSSH(context.Background(), "alpha", sshCmdOptions{
				configPath: cfgPath,
				stdout:     &out,
				stderr:     &errOut,
			})
			assertExitErr(t, err, 1)
			if got := errOut.String(); !strings.Contains(got, "disabled") {
				t.Fatalf("stderr = %q, want a disabled message", got)
			}
		})
	}
}

// TestRunSSHPrint pins that --print renders the SAME argv sshprofile.Argv
// composes for the dashboard's own Connect action, shell-quoted onto one
// line, without connecting.
func TestRunSSHPrint(t *testing.T) {
	t.Parallel()
	cfgPath := writeSSHTestConfig(t, `
[terminal.ssh]
enabled = true
connect_timeout_seconds = 7
keepalive_seconds = 20

[[terminal.ssh.profiles]]
name = "alpha"
host = "alpha.example.com"
user = "ubuntu"
port = 2222
`)
	var out, errOut bytes.Buffer
	err := runSSH(context.Background(), "alpha", sshCmdOptions{
		configPath: cfgPath,
		print:      true,
		stdout:     &out,
		stderr:     &errOut,
	})
	if err != nil {
		t.Fatalf("runSSH: %v (stderr=%q)", err, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", errOut.String())
	}

	profile := sshprofile.Profile{Name: "alpha", Host: "alpha.example.com", User: "ubuntu", Port: 2222}
	opts := sshprofile.Options{ConnectTimeoutSeconds: 7, KeepaliveSeconds: 20}
	wantArgv, err := sshprofile.Argv(profile, opts)
	if err != nil {
		t.Fatalf("sshprofile.Argv: %v", err)
	}
	want := shellJoinArgv(wantArgv) + "\n"
	if got := out.String(); got != want {
		t.Fatalf("--print output =\n%q\nwant\n%q", got, want)
	}
	// -R must never appear on the interactive path, regardless of profile
	// fields — the C1 argv is built by sshprofile.Argv, which never honors
	// ReverseProxy.
	if strings.Contains(out.String(), "-R") {
		t.Fatalf("--print output unexpectedly contains -R: %q", out.String())
	}
}

// TestRunSSHPrintAndTestMutuallyExclusive pins the flag-combination guard.
func TestRunSSHPrintAndTestMutuallyExclusive(t *testing.T) {
	t.Parallel()
	cfgPath := writeSSHTestConfig(t, `
[terminal.ssh]
enabled = true

[[terminal.ssh.profiles]]
name = "alpha"
host = "alpha.example.com"
`)
	var out, errOut bytes.Buffer
	err := runSSH(context.Background(), "alpha", sshCmdOptions{
		configPath: cfgPath,
		print:      true,
		test:       true,
		stdout:     &out,
		stderr:     &errOut,
	})
	assertExitErr(t, err, 1)
	if !strings.Contains(errOut.String(), "mutually exclusive") {
		t.Fatalf("stderr = %q, want a mutually-exclusive message", errOut.String())
	}
}

// TestRunSSHTestReportsRunFailureHonestly pins the --test CLI path's error
// handling: with no `ssh`/`ssh-keygen` reachable on PATH, the underlying
// sshforward.Manager.Test cannot even attempt the probe, and runSSHTest
// reports that honestly (rather than a false "auth: FAILED") and exits 1.
// The Manager.Test decision logic itself (known_hosts / auth verdicts via
// injected fakes) is already pinned by internal/sshforward's own tests
// (TestTestReportsAuthOK, TestTestReportsAuthFailureAsAResultNotAnError,
// etc.) — this test only exercises the CLI's wiring and reporting.
func TestRunSSHTestReportsRunFailureHonestly(t *testing.T) {
	emptyPathDir := t.TempDir()
	t.Setenv("PATH", emptyPathDir)

	cfgPath := writeSSHTestConfig(t, `
[terminal.ssh]
enabled = true

[[terminal.ssh.profiles]]
name = "alpha"
host = "alpha.example.com"
`)
	var out, errOut bytes.Buffer
	err := runSSH(context.Background(), "alpha", sshCmdOptions{
		configPath: cfgPath,
		test:       true,
		stdout:     &out,
		stderr:     &errOut,
	})
	assertExitErr(t, err, 1)
	if !strings.Contains(errOut.String(), "test failed to run") {
		t.Fatalf("stderr = %q, want a \"test failed to run\" message", errOut.String())
	}
}

// TestShellQuoteArg pins the local argv-quoting algorithm --print relies on:
// a deliberate duplicate of internal/launch/launch.go's unexported
// shellJoin/shellQuote (same character set), since that helper is private to
// its own package.
func TestShellQuoteArg(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"", "''"},
		{"alpha.example.com", "alpha.example.com"},
		{"-tt", "-tt"},
		{"BatchMode=no", "BatchMode=no"},
		{"has space", "'has space'"},
		{"it's", `'it'\''s'`},
		{"$(rm -rf /)", `'$(rm -rf /)'`},
	}
	for _, tc := range cases {
		if got := shellQuoteArg(tc.in); got != tc.want {
			t.Errorf("shellQuoteArg(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---- helpers ---------------------------------------------------------

func writeSSHTestConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ssh.db")
	cfgPath := filepath.Join(dir, "config.toml")
	full := "[observer]\n" +
		"db_path = \"" + filepath.ToSlash(dbPath) + "\"\n" +
		"log_level = \"error\"\n" +
		body
	if err := os.WriteFile(cfgPath, []byte(full), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

func assertExitErr(t *testing.T, err error, want int) {
	t.Helper()
	if err == nil {
		t.Fatalf("err = nil, want exit code %d", want)
	}
	var ee exitErr
	if !errors.As(err, &ee) {
		t.Fatalf("err = %v (%T), want exitErr", err, err)
	}
	if int(ee) != want {
		t.Fatalf("exit code = %d, want %d", int(ee), want)
	}
}
