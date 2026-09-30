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
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// pongListener serves "PONG" to every connection on 127.0.0.1:0 and counts
// the connections it accepted.
func pongListener(t *testing.T) (port int, accepted *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted = &atomic.Int64{}
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			accepted.Add(1)
			_, _ = c.Write([]byte("PONG\n"))
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, accepted
}

// plantProtected writes the files the SR27-SBX-1 overlays must cover.
func plantProtected(t *testing.T, home, workspace, observerDir string) {
	t.Helper()
	write := func(p, body string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(observerDir, "config.toml"), "# daemon config\n")
	write(filepath.Join(observerDir, "remote-secret"), "REMOTE-SECRET\n")
	write(filepath.Join(observerDir, "attach", "attach.lock"), "")
	write(filepath.Join(home, ".claude", "settings.json"), "{}\n")
	write(filepath.Join(workspace, ".git", "config"), "[core]\n")
	write(filepath.Join(workspace, ".git", "hooks", "pre-commit.sample"), "#!/bin/sh\n")
}

// runSandboxed runs script under wrap with an inherited fd 3 marker and
// returns the combined output.
func runSandboxed(t *testing.T, wrap []string, home, script string) (string, error) {
	t.Helper()
	fd3 := filepath.Join(t.TempDir(), "fd3")
	if err := os.WriteFile(fd3, []byte("FD3_MARKER\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(fd3)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	argv := append(append([]string(nil), wrap...), "bash", "-c", script)
	//nolint:gosec // argv is the Prepare-composed wrapper + the test's fixed script.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.ExtraFiles = []*os.File{f}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestBwrapIntegrationNetworkTiers is the SR27-SBX-1 live proof, run through
// the real Go launch path (sandboxRuntime.Prepare -> host helper -> bwrap ->
// guest helper) in this test binary, never through a running daemon. For
// each private-namespace tier it proves, from INSIDE the sandbox:
//   - the daemon's loopback control plane is unreachable (a host listener
//     standing in for the dashboard, and the real default port 8081, both
//     refuse; the stand-in records zero connections);
//   - the model proxy is reachable exactly when the tier forwards it;
//   - the egress gateway is present exactly for the internet tier, and it
//     refuses a CONNECT to the host's loopback dashboard with 403;
//   - the protected state is read-only (daemon config, the tool's hook
//     settings, the workspace repository config + hooks), the remote secret is
//     unreadable, the attach socket dir is empty, while the workspace, the
//     observer dir and the tool's own state stay writable;
//   - the trusted OOB fd 3 still reaches the inner command through both
//     helpers.
func TestBwrapIntegrationNetworkTiers(t *testing.T) {
	bwrapUsableForTest(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH (needed for /dev/tcp) - skipping")
	}
	if err := exec.Command("bwrap", "--ro-bind", "/", "/", "--unshare-net", "--", "true").Run(); err != nil {
		t.Skipf("bwrap cannot create a network namespace here (%v) - skipping", err)
	}

	tests := []struct {
		egress      string
		wantProxy   bool
		wantGateway bool
	}{
		{"internet", true, true},
		{"proxy_only", true, false},
		{"none", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.egress, func(t *testing.T) {
			proxyPort, proxyHits := pongListener(t)
			dashPort, dashHits := pongListener(t)

			wrap, home, workspace, observerDir := prepLiveWrapArgvTier(t, tc.egress, proxyPort,
				func(home, workspace, observerDir string) { plantProtected(t, home, workspace, observerDir) })

			gw := sandbox.GatewayPort(proxyPort)
			script := fmt.Sprintf(`
read -r line <&3 || { echo FD3_MISSING; exit 11; }
[ "$line" = "FD3_MARKER" ] || exit 12
probe() { (exec 4<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && echo "REACH $1" || echo "NOREACH $1"; }
probe %[1]d
probe %[2]d
probe 8081
probe %[3]d
if [ -n "$HTTPS_PROXY" ]; then echo "PROXYENV $HTTPS_PROXY"; fi
if exec 5<>/dev/tcp/127.0.0.1/%[3]d 2>/dev/null; then
  printf 'CONNECT 127.0.0.1:%[2]d HTTP/1.1\r\nHost: 127.0.0.1:%[2]d\r\n\r\n' >&5
  read -r status <&5; echo "GATEWAY $status"
fi
echo x >> %[4]q 2>/dev/null && echo "WROTE config" || echo "RO config"
echo x >> %[5]q 2>/dev/null && echo "WROTE settings" || echo "RO settings"
echo x >> %[6]q 2>/dev/null && echo "WROTE gitconfig" || echo "RO gitconfig"
touch %[7]q 2>/dev/null && echo "WROTE hooks" || echo "RO hooks"
cat %[8]q 2>/dev/null | grep -q REMOTE-SECRET && echo "READ secret" || echo "HIDDEN secret"
[ -z "$(ls -A %[9]q 2>/dev/null)" ] && echo "EMPTY attach" || echo "SEEN attach"
touch %[10]q && echo "RW workspace"
touch %[11]q && echo "RW observer"
touch %[12]q && echo "RW toolstate"
`,
				proxyPort, dashPort, gw,
				filepath.Join(observerDir, "config.toml"),
				filepath.Join(home, ".claude", "settings.json"),
				filepath.Join(workspace, ".git", "config"),
				filepath.Join(workspace, ".git", "hooks", "post-checkout"),
				filepath.Join(observerDir, "remote-secret"),
				filepath.Join(observerDir, "attach"),
				filepath.Join(workspace, "edited.txt"),
				filepath.Join(observerDir, "observer.db-test"),
				filepath.Join(home, ".claude", "projects.json"),
			)

			out, err := runSandboxed(t, wrap, home, script)
			if err != nil {
				t.Fatalf("sandboxed script failed: %v\n%s", err, out)
			}
			lines := map[string]bool{}
			sc := bufio.NewScanner(strings.NewReader(out))
			for sc.Scan() {
				lines[strings.TrimSpace(sc.Text())] = true
			}
			want := func(line string) {
				t.Helper()
				if !lines[line] {
					t.Errorf("missing %q in sandbox output:\n%s", line, out)
				}
			}

			// Control plane: never reachable in a private namespace.
			want("NOREACH " + strconv.Itoa(dashPort))
			want("NOREACH 8081")
			if n := dashHits.Load(); n != 0 {
				t.Errorf("the host dashboard stand-in accepted %d connections from inside the sandbox", n)
			}
			// Model proxy: reachable exactly when forwarded.
			if tc.wantProxy {
				want("REACH " + strconv.Itoa(proxyPort))
				if proxyHits.Load() == 0 {
					t.Errorf("the host proxy saw no connection although the tier forwards it")
				}
			} else {
				want("NOREACH " + strconv.Itoa(proxyPort))
			}
			// Egress gateway.
			if tc.wantGateway {
				want("REACH " + strconv.Itoa(gw))
				want(fmt.Sprintf("PROXYENV http://127.0.0.1:%d", gw))
				if !strings.Contains(out, "GATEWAY HTTP/1.1 403") {
					t.Errorf("gateway did not refuse a CONNECT to the host loopback:\n%s", out)
				}
			} else {
				want("NOREACH " + strconv.Itoa(gw))
			}
			// Protected state.
			for _, l := range []string{
				"RO config", "RO settings", "RO gitconfig", "RO hooks",
				"HIDDEN secret", "EMPTY attach", "RW workspace", "RW observer", "RW toolstate",
			} {
				want(l)
			}
			// The host socket dir is gone once the run ends.
			for i, a := range wrap {
				if a == "--sock-dir" && i+1 < len(wrap) {
					if _, serr := os.Stat(wrap[i+1]); !os.IsNotExist(serr) {
						t.Errorf("socket dir %s left behind (stat err %v)", wrap[i+1], serr)
					}
				}
			}
		})
	}
}

// TestSandboxAllowToolConfigWritesLiftsOnlyExecState: the opt-in re-opens the
// executed state but never the secrets.
func TestSandboxAllowToolConfigWritesLiftsOnlyExecState(t *testing.T) {
	home := t.TempDir()
	observerDir := t.TempDir()
	workspace := t.TempDir()
	t.Setenv("HOME", home)
	plantProtected(t, home, workspace, observerDir)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, allow := range []bool{false, true} {
		rt, err := newSandboxRuntime(config.TerminalSandboxConfig{Enabled: true, Egress: "none", AllowToolConfigWrites: allow},
			nil, observerDir, exe, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]sandbox.OverlayKind{}
		ovs, err := rt.overlays(home, workspace, integration.SandboxSpec{StateRW: []string{".claude"}, ProtectRO: []string{".claude/settings.json"}})
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range ovs {
			got[o.Path] = o.Kind
		}
		if got[filepath.Join(rt.observerDir, "remote-secret")] != sandbox.OverlayHideFile {
			t.Errorf("allow=%v: remote-secret not hidden: %v", allow, got)
		}
		if got[filepath.Join(rt.observerDir, "attach")] != sandbox.OverlayHideDir {
			t.Errorf("allow=%v: attach dir not hidden: %v", allow, got)
		}
		for _, p := range []string{
			filepath.Join(rt.observerDir, "config.toml"),
			filepath.Join(home, ".claude", "settings.json"),
			filepath.Join(workspace, ".git", "config"),
			filepath.Join(workspace, ".git", "hooks"),
		} {
			_, protected := got[p]
			if protected == allow {
				t.Errorf("allow=%v: %s protected=%v", allow, p, protected)
			}
		}
	}
}

// TestBwrapIntegrationInternetEgressLive is the positive half of the internet
// tier, opt-in because it needs real internet: with
// OBSERVER_SANDBOX_LIVE_INTERNET=1 it proves a sandboxed curl reaches a public
// HTTPS site through the egress gateway (HTTPS_PROXY) while the namespace
// itself has no route out.
func TestBwrapIntegrationInternetEgressLive(t *testing.T) {
	if os.Getenv("OBSERVER_SANDBOX_LIVE_INTERNET") != "1" {
		t.Skip("set OBSERVER_SANDBOX_LIVE_INTERNET=1 to run the live internet egress check")
	}
	bwrapUsableForTest(t)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not on PATH")
	}
	proxyPort, _ := pongListener(t)
	wrap, home, _, _ := prepLiveWrapArgvTier(t, "internet", proxyPort, nil)
	script := `
curl -sS -o /dev/null -w 'VIA_GATEWAY %{http_code}\n' --max-time 20 https://example.com/ || echo VIA_GATEWAY_FAILED
curl -sS -o /dev/null -w 'DIRECT %{http_code}\n' --noproxy '*' --max-time 5 https://example.com/ 2>/dev/null || echo DIRECT_BLOCKED
`
	out, err := runSandboxed(t, wrap, home, script)
	if err != nil {
		t.Fatalf("sandboxed curl failed: %v\n%s", err, out)
	}
	t.Logf("sandbox output:\n%s", out)
	if !strings.Contains(out, "VIA_GATEWAY 200") {
		t.Errorf("public HTTPS through the gateway did not succeed:\n%s", out)
	}
	if !strings.Contains(out, "DIRECT_BLOCKED") {
		t.Errorf("a direct (non-proxied) connection left the private namespace:\n%s", out)
	}
}

// TestBwrapIntegrationTeardownThroughHelpers extends the G12 teardown proof to
// the helper chain (host helper -> bwrap -> guest helper -> inner): a group
// SIGTERM reaps the run within 3s and leaves no orphaned inner process.
func TestBwrapIntegrationTeardownThroughHelpers(t *testing.T) {
	bwrapUsableForTest(t)
	if err := exec.Command("bwrap", "--ro-bind", "/", "/", "--unshare-net", "--", "true").Run(); err != nil {
		t.Skipf("bwrap cannot create a network namespace here (%v) - skipping", err)
	}
	proxyPort, _ := pongListener(t)
	wrap, home, _, _ := prepLiveWrapArgvTier(t, "internet", proxyPort, nil)
	const marker = "317.31"
	argv := append(append([]string(nil), wrap...), "sleep", marker)
	//nolint:gosec // Prepare-composed wrapper + fixed test argv.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for !sleepMarkerRunning(marker) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !sleepMarkerRunning(marker) {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		t.Fatal("inner process never started")
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatalf("kill -pgid: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		t.Fatal("helper chain not reaped within 3s of SIGTERM to the group")
	}
	time.Sleep(200 * time.Millisecond)
	if sleepMarkerRunning(marker) {
		t.Fatal("inner process survived the teardown (orphaned)")
	}
}

// sleepMarkerRunning scans /proc for a `sleep <marker>` process.
func sleepMarkerRunning(marker string) bool {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if len(parts) == 2 && filepath.Base(parts[0]) == "sleep" && parts[1] == marker {
			return true
		}
	}
	return false
}

// TestBwrapIntegrationHelperDeathKillsChain: SIGKILL to the host helper alone
// (no group signal) still takes the whole chain down via parent-death signals,
// so a crashed helper never leaves a tool running without its sockets.
func TestBwrapIntegrationHelperDeathKillsChain(t *testing.T) {
	bwrapUsableForTest(t)
	if err := exec.Command("bwrap", "--ro-bind", "/", "/", "--unshare-net", "--", "true").Run(); err != nil {
		t.Skipf("bwrap cannot create a network namespace here (%v) - skipping", err)
	}
	proxyPort, _ := pongListener(t)
	wrap, home, _, _ := prepLiveWrapArgvTier(t, "internet", proxyPort, nil)
	const marker = "318.31"
	argv := append(append([]string(nil), wrap...), "sleep", marker)
	//nolint:gosec // Prepare-composed wrapper + fixed test argv.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !sleepMarkerRunning(marker) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !sleepMarkerRunning(marker) {
		_ = cmd.Process.Kill()
		t.Fatal("inner process never started")
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	deadline = time.Now().Add(3 * time.Second)
	for sleepMarkerRunning(marker) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if sleepMarkerRunning(marker) {
		t.Fatal("inner process outlived a SIGKILLed host helper")
	}
}
