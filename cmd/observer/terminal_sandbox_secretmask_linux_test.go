//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// maskedLaunchPaths is the workspace the two tests below plant: two secret
// files at different depths, the committed example, and a file that is not a
// secret.
func plantMaskWorkspace(t *testing.T, ws string) {
	t.Helper()
	for rel, body := range map[string]string{
		".env":                "TOP=SECRET\n",
		".env.example":        "TOP=example\n",
		"app/server.key":      "PRIVATE-KEY\n",
		"app/main.go":         "package main\n",
		"notes.txt":           "plain\n",
		"node_modules/x/.env": "VENDORED\n",
	} {
		p := filepath.Join(ws, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mkGitDir(t, ws)
}

// TestBwrapWrapArgvSecretMask composes a bwrap launch with the workspace
// secret mask off and on, against a stand-in bwrap on PATH: off, the argv is
// exactly what every existing launch builds (buildWrapArgv's), with no
// /dev/null bind for the workspace; on, it is that same argv plus one
// `--ro-bind /dev/null <file>` per secret file and nothing else.
func TestBwrapWrapArgvSecretMask(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "bwrap"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // G306: a test stand-in that must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	home := t.TempDir()
	setTestHome(t, home)
	if real, err := filepath.EvalSymlinks(home); err == nil {
		home = real
	}
	_ = os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	ws := filepath.Join(home, "proj")
	plantMaskWorkspace(t, ws)
	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	cfg.Terminal.Sandbox.Enabled = true
	exe, _ := os.Executable()
	rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, filepath.Join(home, ".observer"), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.applyDaemonConfig(cfg)

	plain, err := rt.buildWrapArgv("claude-code", ws, "runbwrapmask000001", true, "")
	if err != nil {
		t.Fatal(err)
	}
	off, rep, err := rt.buildWrapArgvMasked("claude-code", ws, "runbwrapmask000001", true, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plain, off) {
		t.Fatalf("buildWrapArgvMasked(false) differs from buildWrapArgv\n got: %v\nwant: %v", off, plain)
	}
	if rep.Enabled || secretMaskOutcome(rep) != nil {
		t.Fatalf("an unmasked launch reported a mask: %+v", rep)
	}
	for _, a := range off {
		if strings.HasPrefix(a, ws+"/") && strings.Contains(a, ".env") {
			t.Fatalf("the default argv names a workspace secret: %q", a)
		}
	}

	on, rep, err := rt.buildWrapArgvMasked("claude-code", ws, "runbwrapmask000001", true, "", true)
	if err != nil {
		t.Fatal(err)
	}
	// Remove each `--ro-bind /dev/null <secret>` triple: what is left is the
	// default argv, so the option only adds.
	var stripped []string
	maskedPaths := map[string]bool{filepath.Join(ws, ".env"): true, filepath.Join(ws, "app", "server.key"): true}
	for i := 0; i < len(on); i++ {
		if on[i] == "--ro-bind" && i+2 < len(on) && on[i+1] == "/dev/null" && maskedPaths[on[i+2]] {
			delete(maskedPaths, on[i+2])
			i += 2
			continue
		}
		stripped = append(stripped, on[i])
	}
	if len(maskedPaths) != 0 {
		t.Fatalf("the masked argv lacks the /dev/null bind for %v\n%v", maskedPaths, on)
	}
	if !slices.Equal(stripped, off) {
		t.Fatalf("the secret mask changed more than its own binds\n got: %v\nwant: %v", stripped, off)
	}
	out := secretMaskOutcome(rep)
	if out == nil || out.Masked != 2 || !out.Complete {
		t.Fatalf("outcome = %+v, want 2 files masked and complete (the example, .git and node_modules are left)", out)
	}
}

// TestBwrapSecretMaskLive is the live proof through the real launch path
// (Prepare -> host helper -> bwrap): inside the box a secret file cannot be
// read (bwrap binds /dev/null without device access, so a read fails and none
// of the content comes back), written, replaced or removed, the committed example and
// every other file read and write normally, a secret created after the launch
// is NOT masked (the stated limit), and the host's files are untouched.
func TestBwrapSecretMaskLive(t *testing.T) {
	bwrapUsableForTest(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH - skipping")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	observerDir := t.TempDir()
	ws := t.TempDir()
	plantMaskWorkspace(t, ws)

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := newSandboxRuntime(config.TerminalSandboxConfig{Enabled: true, HomeMode: "tmpfs", Egress: "host"}, nil, observerDir, exe, nil)
	if err != nil {
		t.Fatalf("newSandboxRuntime: %v", err)
	}
	res, err := rt.Prepare(context.Background(), termsvc.PrepareRequest{
		Tool: "claude-code", ProjectRoot: ws, WorkspaceSource: "live", MaskWorkspaceSecrets: true,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if res.SecretMask == nil || res.SecretMask.Masked != 2 || !res.SecretMask.Complete {
		t.Fatalf("SecretMask = %+v, want 2 files masked, complete", res.SecretMask)
	}
	script := `
W=` + ws + `
cd "$W"
echo "ENV=[$(cat .env 2>/dev/null)]"
echo "KEY=[$(cat app/server.key 2>/dev/null)]"
echo "EXAMPLE=[$(cat .env.example)]"
echo "NOTES=[$(cat notes.txt)]"
try() { if ( eval "$2" ) >/dev/null 2>&1; then echo "DONE $1"; else echo "BLOCKED $1"; fi; }
try readenv    "cat .env"
try readkey    "cat app/server.key"
try writeenv   "printf x > .env"
try appendkey  "printf x >> app/server.key"
try rmenv      "rm .env"
try mvenv      "mv .env .env.old"
try mvkey      "mv app/server.key app/server.key.old"
try writenote  "printf x > notes.txt"
try newsecret  "printf NEW > fresh.key"
echo "FRESH=[$(cat fresh.key 2>&1)]"
`
	out, err := runSandboxed(t, res.WrapArgv, home, script)
	if err != nil {
		t.Fatalf("sandboxed script failed: %v\n%s", err, out)
	}
	for _, want := range []string{"ENV=[]", "KEY=[]", "EXAMPLE=[TOP=example]", "NOTES=[plain]"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, name := range []string{"readenv", "readkey", "writeenv", "appendkey", "rmenv", "mvenv", "mvkey"} {
		if !strings.Contains(out, "BLOCKED "+name) {
			t.Errorf("%s was not refused for a masked file:\n%s", name, out)
		}
	}
	for _, name := range []string{"writenote", "newsecret"} {
		if !strings.Contains(out, "DONE "+name) {
			t.Errorf("%s was refused, but it is an ordinary write:\n%s", name, out)
		}
	}
	// The stated limit: a secret created after the launch is the box's own.
	if !strings.Contains(out, "FRESH=[NEW]") {
		t.Errorf("a file created after the launch should read back (it is not masked):\n%s", out)
	}
	// The host's files are intact.
	for rel, want := range map[string]string{".env": "TOP=SECRET\n", "app/server.key": "PRIVATE-KEY\n"} {
		b, err := os.ReadFile(filepath.Join(ws, filepath.FromSlash(rel)))
		if err != nil || string(b) != want {
			t.Errorf("host %s = %q (%v), want %q", rel, b, err, want)
		}
	}
}

// TestBwrapSecretMaskOffIsTheDefault: a launch that does not ask for the mask
// leaves the secrets readable (the behaviour before the option) and carries no
// outcome, so a caller can tell "not asked" from "asked and incomplete".
func TestBwrapSecretMaskOffIsTheDefault(t *testing.T) {
	bwrapUsableForTest(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH - skipping")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	ws := t.TempDir()
	plantMaskWorkspace(t, ws)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := newSandboxRuntime(config.TerminalSandboxConfig{Enabled: true, HomeMode: "tmpfs", Egress: "host"}, nil, t.TempDir(), exe, nil)
	if err != nil {
		t.Fatalf("newSandboxRuntime: %v", err)
	}
	res, err := rt.Prepare(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: ws, WorkspaceSource: "live"})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if res.SecretMask != nil {
		t.Fatalf("SecretMask = %+v, want nil when the launch did not ask", res.SecretMask)
	}
	out, err := runSandboxed(t, res.WrapArgv, home, `cat `+ws+`/.env`)
	if err != nil || !strings.Contains(out, "TOP=SECRET") {
		t.Fatalf("an unmasked launch must still read the file: %q (%v)", out, err)
	}
}
