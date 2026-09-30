//go:build linux

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// TestProtectPathTable pins the protected-path resolution rules
// (SR27-SBX-2): an existing path is protected in place, a missing one under
// a writable bind becomes a placeholder at its topmost missing component, a
// missing one nothing writable can reach is left alone, and a symlink inside
// a writable bind refuses the launch.
func TestProtectPathTable(t *testing.T) {
	rw := t.TempDir()
	other := t.TempDir()
	mk := func(p string, dir bool) {
		t.Helper()
		if dir {
			if err := os.MkdirAll(p, 0o700); err != nil {
				t.Fatal(err)
			}
			return
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mk(filepath.Join(rw, "config.toml"), false)
	mk(filepath.Join(rw, "attach"), true)
	mk(filepath.Join(rw, "gitfile-ws", ".git"), false) // a worktree/submodule gitfile
	mk(filepath.Join(other, "target.json"), false)
	mk(filepath.Join(other, "realdir"), true)
	if err := os.Symlink(filepath.Join(other, "target.json"), filepath.Join(rw, "settings.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "target.json"), filepath.Join(other, "link.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "realdir"), filepath.Join(rw, "linkdir")); err != nil {
		t.Fatal(err)
	}
	// A bind TARGET that is itself a symlink (e.g. ~/.codex -> /data/codex).
	stateLink := filepath.Join(t.TempDir(), "state")
	if err := os.Symlink(filepath.Join(other, "realdir"), stateLink); err != nil {
		t.Fatal(err)
	}
	roots := []string{rw, stateLink}

	tests := []struct {
		name    string
		row     protectedRow
		wantOK  bool
		want    sandbox.Overlay
		wantErr string
	}{
		{
			"existing file read-only",
			protectedRow{path: filepath.Join(rw, "config.toml"), kind: sandbox.OverlayReadOnly},
			true,
			sandbox.Overlay{Path: filepath.Join(rw, "config.toml"), Kind: sandbox.OverlayReadOnly},
			"",
		},
		{
			"existing dir hidden with a tmpfs",
			protectedRow{path: filepath.Join(rw, "attach"), kind: sandbox.OverlayHideFile},
			true,
			sandbox.Overlay{Path: filepath.Join(rw, "attach"), Kind: sandbox.OverlayHideDir},
			"",
		},
		{
			"missing file under rw gets a file placeholder",
			protectedRow{path: filepath.Join(rw, "guard-policy.toml"), kind: sandbox.OverlayReadOnly},
			true,
			sandbox.Overlay{Path: filepath.Join(rw, "guard-policy.toml"), Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderFile},
			"",
		},
		{
			"missing dir under rw gets a dir placeholder",
			protectedRow{path: filepath.Join(rw, "shims"), kind: sandbox.OverlayReadOnly, dir: true},
			true,
			sandbox.Overlay{Path: filepath.Join(rw, "shims"), Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderDir},
			"",
		},
		{
			"missing secret file placeholder stays hidden",
			protectedRow{path: filepath.Join(rw, "remote-secret"), kind: sandbox.OverlayHideFile},
			true,
			sandbox.Overlay{Path: filepath.Join(rw, "remote-secret"), Kind: sandbox.OverlayHideFile, Placeholder: sandbox.PlaceholderFile},
			"",
		},
		{
			"missing nested path: the topmost missing component becomes a dir placeholder",
			protectedRow{path: filepath.Join(rw, "ws", ".git", "config"), kind: sandbox.OverlayReadOnly},
			true,
			sandbox.Overlay{Path: filepath.Join(rw, "ws"), Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderDir},
			"",
		},
		{
			"missing .git in an existing workspace",
			protectedRow{path: filepath.Join(rw, "attach", ".git", "config"), kind: sandbox.OverlayReadOnly},
			true,
			sandbox.Overlay{Path: filepath.Join(rw, "attach", ".git"), Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderDir},
			"",
		},
		{
			"a gitfile ancestor is protected instead",
			protectedRow{path: filepath.Join(rw, "gitfile-ws", ".git", "config"), kind: sandbox.OverlayReadOnly},
			true,
			sandbox.Overlay{Path: filepath.Join(rw, "gitfile-ws", ".git"), Kind: sandbox.OverlayReadOnly},
			"",
		},
		{
			"missing outside every writable bind is left alone",
			protectedRow{path: filepath.Join(other, "nope", "settings.json"), kind: sandbox.OverlayReadOnly},
			false,
			sandbox.Overlay{},
			"",
		},
		{
			"symlink inside a writable bind refuses the launch",
			protectedRow{path: filepath.Join(rw, "settings.json"), kind: sandbox.OverlayReadOnly, remedy: remedyToolConfigWrites},
			false,
			sandbox.Overlay{},
			"is a symlink",
		},
		{
			"symlink outside every writable bind is left alone",
			protectedRow{path: filepath.Join(other, "link.json"), kind: sandbox.OverlayReadOnly},
			false,
			sandbox.Overlay{},
			"",
		},
		{
			"a symlinked parent inside a writable bind refuses",
			protectedRow{path: filepath.Join(rw, "linkdir", "hooks.json"), kind: sandbox.OverlayReadOnly},
			false,
			sandbox.Overlay{},
			"is a symlink",
		},
		{
			"a symlinked bind target is followed (the mount pins it)",
			protectedRow{path: filepath.Join(stateLink, "hooks.json"), kind: sandbox.OverlayReadOnly},
			true,
			sandbox.Overlay{Path: filepath.Join(stateLink, "hooks.json"), Kind: sandbox.OverlayReadOnly, Placeholder: sandbox.PlaceholderFile},
			"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := protectPath(tc.row, roots)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				if !strings.Contains(err.Error(), "Replace the symlink") {
					t.Errorf("refusal %q does not say how to fix it", err)
				}
				if strings.ContainsRune(err.Error(), '\u2014') {
					t.Errorf("em-dash in %q", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("protectPath = %+v ok=%v, want %+v ok=%v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestPlaceholderCreateAndRemove: the helper creates exactly the missing
// placeholders (never following a planted symlink), and afterwards removes
// only the ones that are still the inode it made, unchanged.
func TestPlaceholderCreateAndRemove(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	if err := os.WriteFile(p("existing.toml"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p("elsewhere"), p("planted.json")); err != nil {
		t.Fatal(err)
	}
	created, err := createPlaceholders(
		[]string{p("a.json"), p("b.toml"), p("c.toml"), p("existing.toml"), p("planted.json")},
		[]string{p("d1"), p("d2")},
	)
	if err != nil {
		t.Fatalf("createPlaceholders: %v", err)
	}
	if len(created) != 5 {
		t.Fatalf("created %d placeholders, want 5 (existing and planted skipped): %+v", len(created), created)
	}
	if b, _ := os.ReadFile(p("a.json")); string(b) != "{}\n" {
		t.Errorf("a.json = %q, want {}\\n", b)
	}
	if fi, _ := os.Stat(p("a.json")); fi.Mode().Perm() != 0o600 {
		t.Errorf("a.json mode %v", fi.Mode().Perm())
	}
	if _, err := os.Lstat(p("elsewhere")); !os.IsNotExist(err) {
		t.Errorf("a planted symlink was followed: %v", err)
	}

	// The host changes some of them while the sandbox runs.
	if err := os.WriteFile(p("b.toml"), []byte("[real]\n"), 0o600); err != nil { // in-place write
		t.Fatal(err)
	}
	if err := os.WriteFile(p("c.new"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(p("c.new"), p("c.toml")); err != nil { // atomic replace, same (empty) content
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p("d2"), "sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	removePlaceholders(created)
	for _, gone := range []string{"a.json", "d1"} {
		if _, err := os.Lstat(p(gone)); !os.IsNotExist(err) {
			t.Errorf("untouched placeholder %s left behind (%v)", gone, err)
		}
	}
	for _, kept := range []string{"b.toml", "c.toml", "d2", "existing.toml", "planted.json"} {
		if _, err := os.Lstat(p(kept)); err != nil {
			t.Errorf("%s removed although the host changed or owned it: %v", kept, err)
		}
	}
}

// TestBwrapIntegrationProtectsMissingPaths is the live SR27-SBX-2 proof for
// protected paths that do not exist at launch, run through the real Go
// launch path in this test binary (never the daemon): with every protected
// path absent, nothing inside the sandbox can create, replace or remove any
// of them; the placeholders read as "no config"; the writable state stays
// writable; and after the session every protected host path is absent
// again.
func TestBwrapIntegrationProtectsMissingPaths(t *testing.T) {
	bwrapUsableForTest(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH - skipping")
	}
	if err := exec.Command("bwrap", "--ro-bind", "/", "/", "--unshare-net", "--unshare-pid", "--proc", "/proc", "--", "true").Run(); err != nil {
		t.Skipf("bwrap cannot create network/pid namespaces here (%v) - skipping", err)
	}
	for _, egress := range []string{"none", "internet", "host"} {
		t.Run(egress, func(t *testing.T) {
			proxyPort, _ := pongListener(t)
			wrap, home, ws, obs := prepLiveWrapArgvTier(t, egress, proxyPort, func(home, _, _ string) {
				// The tool's state dir exists (so it is bound rw), its hook
				// config does not.
				if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
					t.Fatal(err)
				}
			})
			if wrap[1] != sandbox.HostVerb {
				t.Fatalf("placeholders need the host helper even for egress=%s: %v", egress, wrap[:3])
			}

			protected := []string{}
			for _, pp := range sandboxObserverSecrets {
				protected = append(protected, filepath.Join(obs, pp.Rel))
			}
			for _, pp := range sandboxObserverExecState {
				protected = append(protected, filepath.Join(obs, pp.Rel))
			}
			protected = append(protected, filepath.Join(home, ".claude", "settings.json"), filepath.Join(ws, ".git"))
			for _, p := range protected {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Fatalf("precondition: %s exists (%v)", p, err)
				}
			}

			script := fmt.Sprintf(`
O=%[1]q; W=%[2]q; S=%[3]q
try() { if ( eval "$2" ) 2>/dev/null; then echo "CREATED $1"; else echo "BLOCKED $1"; fi; }
try guard       "printf '[[rule]]\n' > $O/guard-policy.toml"
try governance  "printf '{\"schema\":1}' > $O/governance-effective.json"
try features    "printf '{}' > $O/features-effective.json"
try checksums   "printf x > $O/hook_checksums.json"
try config      "printf '[guard]\nenabled=false\n' > $O/config.toml"
try projpolicy  "touch $O/guard-project-policies/evil.toml"
try shims       "touch $O/shims/claude"
try browserhost "touch $O/browser-host/host.json"
try policyres   "touch $O/policy-resource/x"
try settings    "printf '{\"hooks\":{}}' > $S"
try gitconfig   "mkdir -p $W/.git/hooks && printf x > $W/.git/config"
try gitinit     "cd $W && command -v git >/dev/null && git init -q"
try secret      "printf hash > $O/remote-secret"
try locToken    "printf tok > $O/loc-editor-token"
try rmguard     "rm -f $O/guard-policy.toml"
try mvguard     "mv $O/guard-policy.toml $O/guard-policy.moved"
try rmgit       "rmdir $W/.git"
[ -f $O/guard-policy.toml ] && [ ! -s $O/guard-policy.toml ] && echo "EMPTY guard"
[ "$(cat $S)" = "{}" ] && echo "EMPTYOBJ settings"
touch $O/observer.db-probe && echo "RW observer"
touch $W/edited.txt && echo "RW workspace"
touch $HOME/.claude/projects.json && echo "RW toolstate"
`, obs, ws, filepath.Join(home, ".claude", "settings.json"))
			out, err := runSandboxed(t, wrap, home, script)
			if err != nil {
				t.Fatalf("sandboxed script failed: %v\n%s", err, out)
			}
			lines := map[string]bool{}
			sc := bufio.NewScanner(strings.NewReader(out))
			for sc.Scan() {
				lines[strings.TrimSpace(sc.Text())] = true
			}
			for _, name := range []string{
				"guard", "governance", "features", "checksums", "config", "projpolicy", "shims",
				"browserhost", "policyres", "settings", "gitconfig", "gitinit", "secret", "locToken", "rmguard", "mvguard", "rmgit",
			} {
				if !lines["BLOCKED "+name] {
					t.Errorf("%s was not blocked inside the sandbox:\n%s", name, out)
				}
			}
			for _, l := range []string{"EMPTY guard", "EMPTYOBJ settings", "RW observer", "RW workspace", "RW toolstate"} {
				if !lines[l] {
					t.Errorf("missing %q:\n%s", l, out)
				}
			}

			// After the session: every protected host path is absent again,
			// the writable state kept what the sandbox wrote.
			for _, p := range protected {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Errorf("host path %s exists after the session (%v)", p, err)
				}
			}
			for _, p := range []string{filepath.Join(obs, "observer.db-probe"), filepath.Join(ws, "edited.txt"), filepath.Join(home, ".claude", "projects.json")} {
				if _, err := os.Stat(p); err != nil {
					t.Errorf("writable-state write %s did not reach the host: %v", p, err)
				}
			}
		})
	}
}

// TestBwrapIntegrationHostIsolation is the live SR27-SBX-2 proof for host
// sockets, platform interop and host processes, through the real launch
// path in this test binary: inside the sandbox the per-user runtime dir and
// the WSL interop dir are empty, the socket-pointing environment is gone, a
// host PID cannot be signalled, the Docker socket is not a socket, and on a
// WSL2 host with interop enabled a Windows binary that a plain bwrap runs
// fine cannot be executed.
func TestBwrapIntegrationHostIsolation(t *testing.T) {
	bwrapUsableForTest(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH - skipping")
	}
	if err := exec.Command("bwrap", "--ro-bind", "/", "/", "--unshare-net", "--unshare-pid", "--proc", "/proc", "--", "true").Run(); err != nil {
		t.Skipf("bwrap cannot create network/pid namespaces here (%v) - skipping", err)
	}
	const winExe = "/mnt/c/Windows/System32/cmd.exe"
	interopLive := false
	if _, err := os.Stat(winExe); err == nil {
		// Control: prove interop really runs a Windows binary from inside a
		// PLAIN bwrap on this host, so the in-sandbox refusal below means
		// something.
		out, _ := exec.Command("timeout", "30", "bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
			"--chdir", "/", "--", winExe, "/c", "echo", "hi-from-windows").CombinedOutput()
		interopLive = strings.Contains(string(out), "hi-from-windows")
		t.Logf("interop control (plain bwrap) ran the Windows binary: %v", interopLive)
	}
	uid := os.Getuid()
	runUser := "/run/user/" + strconv.Itoa(uid)
	hostHasRunUser := false
	if ents, err := os.ReadDir(runUser); err == nil && len(ents) > 0 {
		hostHasRunUser = true
	}
	hostHasDockerSock := false
	if fi, err := os.Stat("/run/docker.sock"); err == nil && fi.Mode()&os.ModeSocket != 0 {
		hostHasDockerSock = true
	}

	for _, egress := range []string{"host", "internet"} {
		t.Run(egress, func(t *testing.T) {
			proxyPort, _ := pongListener(t)
			cfg := config.TerminalSandboxConfig{Enabled: true, HomeMode: "tmpfs", Egress: egress}
			if interopLive {
				// Make the Windows binary visible inside (the foreign-drive
				// mask would otherwise hide it), so what is tested is the
				// interop channel, not the mask.
				cfg.ExtraROBinds = []string{"/mnt/c/Windows/System32"}
			}
			wrap, home, _, _ := prepLiveWrapArgvCfg(t, cfg, proxyPort, nil)
			script := fmt.Sprintf(`
[ -z "$(ls -A %[1]s 2>/dev/null)" ] && echo "EMPTY runuser"
[ -z "$(ls -A /run/WSL 2>/dev/null)" ] && echo "EMPTY runwsl"
[ -z "${WSL_INTEROP+x}" ] && echo "UNSET WSL_INTEROP"
[ -z "${DBUS_SESSION_BUS_ADDRESS+x}" ] && echo "UNSET DBUS_SESSION_BUS_ADDRESS"
[ -z "${SSH_AUTH_SOCK+x}" ] && echo "UNSET SSH_AUTH_SOCK"
kill -0 %[2]d 2>/dev/null && echo "SIGNALLED host" || echo "NOSIGNAL host"
kill -0 1 2>/dev/null && echo "PID1 visible"
[ -S /run/docker.sock ] && echo "SOCKET docker" || echo "NOSOCKET docker"
n=0; for d in /proc/[0-9]*; do n=$((n+1)); done; echo "PROCS $n"
if [ -e %[3]q ]; then
  if timeout 20 %[3]q /c echo hi-from-windows 2>/dev/null | grep -q hi-from-windows; then echo "INTEROP ran"; else echo "INTEROP blocked"; fi
else
  echo "INTEROP absent"
fi
`, runUser, os.Getpid(), winExe)
			out, err := runSandboxed(t, wrap, home, script)
			if err != nil {
				t.Fatalf("sandboxed script failed: %v\n%s", err, out)
			}
			t.Logf("sandbox output:\n%s", out)
			want := func(l string) {
				t.Helper()
				if !strings.Contains(out, l+"\n") {
					t.Errorf("missing %q:\n%s", l, out)
				}
			}
			want("EMPTY runuser")
			want("EMPTY runwsl")
			want("UNSET WSL_INTEROP")
			want("UNSET DBUS_SESSION_BUS_ADDRESS")
			want("UNSET SSH_AUTH_SOCK")
			want("NOSIGNAL host")
			want("PID1 visible") // the namespace's own init, not the host's
			want("NOSOCKET docker")
			if interopLive {
				want("INTEROP blocked")
			}
			if !hostHasRunUser {
				t.Logf("host %s is empty or absent: the runuser assertion is vacuous here", runUser)
			}
			if !hostHasDockerSock {
				t.Logf("host has no /run/docker.sock: the docker assertion is vacuous here")
			}
			// A private PID namespace shows only the sandbox's own few
			// processes.
			for _, l := range strings.Split(out, "\n") {
				if strings.HasPrefix(l, "PROCS ") {
					if n, _ := strconv.Atoi(strings.TrimPrefix(l, "PROCS ")); n == 0 || n > 20 {
						t.Errorf("sandbox sees %d processes; a private PID namespace should see only its own few", n)
					}
				}
			}
		})
	}
}

// defaultGatewayIPv4 reads the host's IPv4 default gateway from
// /proc/net/route ("" when there is none). On WSL2 NAT it is the Windows
// host.
func defaultGatewayIPv4(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(l)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		return fmt.Sprintf("%d.%d.%d.%d", v&0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff)
	}
	return ""
}

// TestBwrapIntegrationGatewayRefusesPrivate is the live SR27-SBX-2 proof for
// private destinations through the real launch path in this test binary:
// from inside an internet-tier sandbox, a CONNECT through the egress gateway
// to the host's default gateway (on WSL2 NAT, the Windows host), to a
// Docker-bridge-like container address and to a tailnet address is refused
// with 403, and the refusal names the rule and the config key; with that
// container range allow-listed the gateway tries the dial instead (502 when
// nothing answers, never 403).
func TestBwrapIntegrationGatewayRefusesPrivate(t *testing.T) {
	bwrapUsableForTest(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH - skipping")
	}
	if err := exec.Command("bwrap", "--ro-bind", "/", "/", "--unshare-net", "--unshare-pid", "--proc", "/proc", "--", "true").Run(); err != nil {
		t.Skipf("bwrap cannot create network/pid namespaces here (%v) - skipping", err)
	}
	targets := []string{"172.17.0.2:5432", "100.100.100.100:443", "[fd12:3456::1]:443"}
	if gw := defaultGatewayIPv4(t); gw != "" {
		ip := net.ParseIP(gw)
		if ip != nil && ip.IsPrivate() {
			targets = append(targets, gw+":8081")
		} else {
			t.Logf("default gateway %s is not private; not asserting it", gw)
		}
	}
	connect := func(port int, target string) string {
		return fmt.Sprintf(`if exec 5<>/dev/tcp/127.0.0.1/%[1]d; then
  printf 'CONNECT %[2]s HTTP/1.1\r\nHost: %[2]s\r\nConnection: close\r\n\r\n' >&5
  resp=$(timeout 5 cat <&5 | tr -d '\r' | tr '\n' ' '); echo "RESULT %[2]s $resp"; exec 5>&-
fi
`, port, target)
	}
	run := func(t *testing.T, cidrs []string, targets []string) string {
		proxyPort, _ := pongListener(t)
		cfg := config.TerminalSandboxConfig{Enabled: true, HomeMode: "tmpfs", Egress: "internet", EgressAllowCIDRs: cidrs}
		wrap, home, _, _ := prepLiveWrapArgvCfg(t, cfg, proxyPort, nil)
		var script strings.Builder
		for _, tg := range targets {
			script.WriteString(connect(sandbox.GatewayPort(proxyPort), tg))
		}
		out, err := runSandboxed(t, wrap, home, script.String())
		if err != nil {
			t.Fatalf("sandboxed script failed: %v\n%s", err, out)
		}
		t.Logf("sandbox output:\n%s", out)
		return out
	}

	t.Run("refused by default", func(t *testing.T) {
		out := run(t, nil, targets)
		for _, tg := range targets {
			line := ""
			for _, l := range strings.Split(out, "\n") {
				if strings.HasPrefix(l, "RESULT "+tg+" ") {
					line = l
				}
			}
			if !strings.Contains(line, "HTTP/1.1 403") {
				t.Errorf("%s not refused with 403: %q", tg, line)
			}
			if !strings.Contains(line, "egress_allow_cidrs") || !strings.Contains(line, "refused by rule") {
				t.Errorf("%s refusal does not name the rule and the config key: %q", tg, line)
			}
		}
	})
	t.Run("allow-listed range is dialled", func(t *testing.T) {
		out := run(t, []string{"172.17.0.0/16"}, []string{"172.17.0.2:5432", "100.100.100.100:443"})
		for _, l := range strings.Split(out, "\n") {
			switch {
			case strings.HasPrefix(l, "RESULT 172.17.0.2:5432 "):
				if strings.Contains(l, " 403 ") {
					t.Errorf("allow-listed destination still refused: %q", l)
				}
			case strings.HasPrefix(l, "RESULT 100.100.100.100:443 "):
				if !strings.Contains(l, " 403 ") {
					t.Errorf("destination outside the allow-list not refused: %q", l)
				}
			}
		}
	})
}

// TestGuardPolicyPathsKeepTheirShape: the trusted per-project policy dir is
// protected as a DIRECTORY even when the user policy file is unset (the
// shape must come from the row, never from the slice position).
func TestGuardPolicyPathsKeepTheirShape(t *testing.T) {
	home := t.TempDir()
	observerDir := t.TempDir()
	workspace := t.TempDir()
	t.Setenv("HOME", home)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := newSandboxRuntime(config.TerminalSandboxConfig{Enabled: true, Egress: "none"}, nil, observerDir, exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	trusted := filepath.Join(rt.observerDir, "trusted-projects")
	full := config.Default()
	full.Guard.Rules.UserPolicy = ""
	full.Guard.Rules.TrustedProjectDir = trusted
	rt.applyDaemonConfig(full)
	ovs, err := rt.overlays(home, workspace, integration.SandboxSpec{})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range ovs {
		if o.Path == trusted {
			if o.Placeholder != sandbox.PlaceholderDir || o.Kind != sandbox.OverlayReadOnly {
				t.Fatalf("trusted dir overlay = %+v, want a read-only dir placeholder", o)
			}
			return
		}
	}
	t.Fatalf("trusted project dir %s not protected: %+v", trusted, ovs)
}
