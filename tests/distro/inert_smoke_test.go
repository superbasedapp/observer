//go:build linux

package distro

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// smokeBinary returns the observer binary under test, or skips: the harness
// starts a real daemon, so it never runs by accident.
func smokeBinary(t *testing.T) string {
	t.Helper()
	if os.Getenv("SBO_DISTRO_SMOKE") != "1" {
		t.Skip("set SBO_DISTRO_SMOKE=1 and SBO_DISTRO_BIN to run the distro smoke harness (it starts a daemon)")
	}
	bin := os.Getenv("SBO_DISTRO_BIN")
	if bin == "" {
		t.Skip("SBO_DISTRO_BIN is not set")
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("SBO_DISTRO_BIN: %v", err)
	}
	return abs
}

// nonCoreNodeIDs is every optional node component of the catalog: removing
// all of them is the most inert selection a node can have.
func nonCoreNodeIDs() []string {
	var out []string
	for _, c := range components.ForBinary(components.BinaryNode) {
		if c.Class != components.ClassCore {
			out = append(out, c.ID)
		}
	}
	sort.Strings(out)
	return out
}

// automaticTCPPorts is every loopback TCP listener the catalog says a
// component opens automatically, keyed by component, with the config key
// that moves it. The harness moves each to a free port.
func automaticTCPListeners() map[string]string {
	out := map[string]string{}
	for _, c := range components.ForBinary(components.BinaryNode) {
		for _, l := range c.Surface.Listeners {
			if l.Proto == "tcp" && l.Trigger == components.TriggerAutomatic && l.ConfigKey != "" {
				out[c.ID] = l.ConfigKey
			}
		}
	}
	return out
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// daemon is one running `observer start`.
type daemon struct {
	cmd *exec.Cmd
	// home is the daemon's HOME; its ~/.observer holds what it wrote.
	home string
	mu   sync.Mutex
	out  bytes.Buffer
}

func (d *daemon) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.out.Write(p)
}

func (d *daemon) output() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.out.String()
}

// startDaemon runs `observer start` with its own HOME and config.
func startDaemon(t *testing.T, bin, configTOML string) *daemon {
	t.Helper()
	return startDaemonIn(t, bin, configTOML, t.TempDir())
}

// startDaemonIn is startDaemon with a chosen HOME (a short one keeps the
// owner-only unix sockets under the OS's 107-byte path limit).
func startDaemonIn(t *testing.T, bin, configTOML, home string) *daemon {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".observer"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(home, ".observer", "config.toml")
	if err := os.WriteFile(cfgPath, []byte(configTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &daemon{home: home}
	d.cmd = exec.Command(bin, "start", "--config", cfgPath, "--no-open") //nolint:gosec // G204: the test's own binary and temp path.
	d.cmd.Env = []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin",
		"TMPDIR=" + home,
	}
	d.cmd.Dir = home
	d.cmd.Stdout, d.cmd.Stderr = d, d
	if err := d.cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	t.Cleanup(func() { d.stop(t) })
	return d
}

// stop sends SIGTERM and, after a bound, SIGKILL.
func (d *daemon) stop(t *testing.T) {
	t.Helper()
	if d.cmd.Process == nil || d.cmd.ProcessState != nil {
		return
	}
	_ = d.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = d.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(45 * time.Second):
		_ = d.cmd.Process.Kill()
		<-done
		t.Logf("daemon did not stop on SIGTERM within 45s; killed")
	}
}

// listeningTCPPorts returns the TCP ports the process holds a LISTEN socket
// on: /proc/<pid>/net/tcp{,6} rows in state 0A whose inode is one of the
// process's own socket file descriptors.
func listeningTCPPorts(pid int) (map[int]bool, error) {
	inodes := map[string]bool{}
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	ents, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		link, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		if ino, ok := strings.CutPrefix(link, "socket:["); ok {
			inodes[strings.TrimSuffix(ino, "]")] = true
		}
	}
	ports := map[int]bool{}
	for _, f := range []string{"tcp", "tcp6"} {
		fh, err := os.Open(fmt.Sprintf("/proc/%d/net/%s", pid, f))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 || fields[3] != "0A" || !inodes[fields[9]] {
				continue
			}
			_, portHex, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			if p, err := strconv.ParseInt(portHex, 16, 32); err == nil {
				ports[int(p)] = true
			}
		}
		_ = fh.Close()
	}
	return ports, nil
}

// alive fails the test unless the daemon is running (not exited, not a
// zombie): an exited process holds no sockets, so a listener check on it
// would pass vacuously.
func (d *daemon) alive(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", d.cmd.Process.Pid))
	if err != nil {
		t.Fatalf("daemon is gone: %v; output:\n%s", err, d.output())
	}
	// The state is the first field after the parenthesised command name.
	if i := bytes.LastIndexByte(raw, ')'); i < 0 || i+2 >= len(raw) || raw[i+2] == 'Z' || raw[i+2] == 'X' {
		t.Fatalf("daemon exited; output:\n%s", d.output())
	}
}

// inertConfig removes every optional component except keep, and selects
// keep: a stamped edition starts from its own default set, where a kept
// component may be off by default (terminals.sandbox on developer, the
// security module on managed), so removing the rest alone would leave it
// inactive (RB1 gate). On a plain build the add list changes nothing.
func inertConfig(t *testing.T, keep ...string) (string, map[string]int) {
	t.Helper()
	kept := map[string]bool{}
	var added []string
	for _, k := range keep {
		kept[k] = true
		added = append(added, strconv.Quote(k))
	}
	var quoted []string
	for _, id := range nonCoreNodeIDs() {
		if !kept[id] {
			quoted = append(quoted, strconv.Quote(id))
		}
	}
	return baseConfig(t, "[components]\nadd = ["+strings.Join(added, ", ")+"]\nremove = ["+strings.Join(quoted, ", ")+"]\n")
}

// settledListeners waits for the component start report, gives every
// start-time goroutine time to bind what it would bind, and returns the
// daemon's TCP listeners.
func settledListeners(t *testing.T, d *daemon) []int {
	t.Helper()
	waitFor(t, d, 90*time.Second, "the component start report", func() bool {
		return strings.Contains(d.output(), "compiled components active")
	})
	time.Sleep(8 * time.Second)
	d.alive(t)
	got, err := listeningTCPPorts(d.cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	d.alive(t)
	var ps []int
	for p := range got {
		ps = append(ps, p)
	}
	sort.Ints(ps)
	return ps
}

func waitFor(t *testing.T, d *daemon, bound time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		if d.cmd.ProcessState != nil {
			t.Fatalf("daemon exited while waiting for %s; output:\n%s", what, d.output())
		}
		if ok() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s; output:\n%s", bound, what, d.output())
}

// baseConfig moves every automatic listener the catalog declares to a free
// port, turns hook auto-registration off and adds extra.
func baseConfig(t *testing.T, extra string) (string, map[string]int) {
	t.Helper()
	ports := map[string]int{}
	var b strings.Builder
	b.WriteString("[observer.hooks]\nauto_register = false\n\n")
	for comp, key := range automaticTCPListeners() {
		p := freePort(t)
		ports[comp] = p
		section, field, ok := strings.Cut(key, ".")
		if !ok || strings.Contains(field, ".") {
			t.Fatalf("listener config key %q of %s is not section.field; extend the harness", key, comp)
		}
		switch field {
		case "port":
			fmt.Fprintf(&b, "[%s]\n%s = %d\n\n", section, field, p)
		default:
			fmt.Fprintf(&b, "[%s]\n%s = \"127.0.0.1:%d\"\n\n", section, field, p)
		}
	}
	b.WriteString(extra)
	return b.String(), ports
}

// TestInertSelectionOpensNoListener is the L2 smoke check (plan 4: an
// inactive component binds no listener). The control run (no [components]
// block) must show every automatic listener the catalog declares, which
// proves the harness sees listeners at all; the inert run (every optional
// component removed) must hold no TCP listener.
func TestInertSelectionOpensNoListener(t *testing.T) {
	bin := smokeBinary(t)
	rep := binaryReport(t, bin)
	stamped := rep.Distro.Valid() && rep.Distro != components.DistroFull

	t.Run("control: legacy selection opens the catalog's automatic listeners", func(t *testing.T) {
		if stamped {
			t.Skipf("a %s distro build starts from its distro, not the legacy set: TestDistroDefaultListeners covers it", rep.Distro)
		}
		cfg, ports := baseConfig(t, "")
		if len(ports) == 0 {
			t.Fatal("the catalog declares no automatic TCP listener; the control proves nothing")
		}
		d := startDaemon(t, bin, cfg)
		waitFor(t, d, 90*time.Second, "every automatic listener", func() bool {
			got, err := listeningTCPPorts(d.cmd.Process.Pid)
			if err != nil {
				return false
			}
			for _, p := range ports {
				if !got[p] {
					return false
				}
			}
			return true
		})
	})

	t.Run("inert: every optional component removed opens no listener", func(t *testing.T) {
		cfg, _ := inertConfig(t)
		d := startDaemon(t, bin, cfg)
		if ps := settledListeners(t, d); len(ps) != 0 {
			t.Fatalf("an all-inert selection still listens on TCP ports %v; output:\n%s", ps, d.output())
		}
	})

	// The same measurement with one listener-owning component kept must
	// see exactly that listener, so the empty result above is a measurement
	// and not a blind spot.
	t.Run("one kept: only capture.proxy active opens exactly the proxy listener", func(t *testing.T) {
		if !reportCompiled(rep)["capture.proxy"] {
			t.Skipf("the %s distro does not offer capture.proxy", rep.Distro)
		}
		cfg, ports := inertConfig(t, "capture.proxy")
		want, ok := ports["capture.proxy"]
		if !ok {
			t.Fatal("the catalog no longer declares the proxy's automatic listener; update the harness")
		}
		d := startDaemon(t, bin, cfg)
		ps := settledListeners(t, d)
		if len(ps) != 1 || ps[0] != want {
			t.Fatalf("listeners %v, want exactly [%d]; output:\n%s", ps, want, d.output())
		}
	})
}

// TestSecurityModuleInertWhenInactive is the security pillar's L2 smoke
// check (security pillar plan section 4.3, SECP-1): with the module
// inactive the daemon writes no posture key and opens no quick-scan
// endpoint; with it active (and guard, which it requires) both appear, so
// the empty result is a measurement. Removing the ModuleActive gate on
// the module's loops fails the inactive half.
func TestSecurityModuleInertWhenInactive(t *testing.T) {
	bin := smokeBinary(t)
	rep := binaryReport(t, bin)
	if !reportCompiled(rep)["security"] {
		t.Skipf("the %s distro does not offer the security module", rep.Distro)
	}
	keyOf := func(d *daemon) string {
		return filepath.Join(d.home, ".observer", "security", "posture", "posture.key")
	}
	sockOf := func(d *daemon) string {
		return filepath.Join(d.home, ".observer", "security", "attach", "attach.sock")
	}
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	shortHome := func(t *testing.T) string {
		h, err := os.MkdirTemp("/tmp", "sbo")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(h) })
		return h
	}

	t.Run("active: the posture key and the quick-scan endpoint appear", func(t *testing.T) {
		cfg, _ := inertConfig(t, "security", "guard")
		d := startDaemonIn(t, bin, cfg, shortHome(t))
		waitFor(t, d, 90*time.Second, "the security posture key and endpoint", func() bool {
			return exists(keyOf(d)) && exists(sockOf(d))
		})
	})
	t.Run("inactive: no posture key and no quick-scan endpoint", func(t *testing.T) {
		cfg, _ := inertConfig(t, "guard")
		d := startDaemonIn(t, bin, cfg, shortHome(t))
		settledListeners(t, d)
		if exists(keyOf(d)) || exists(sockOf(d)) {
			t.Fatalf("an inactive security module wrote %s or %s; output:\n%s", keyOf(d), sockOf(d), d.output())
		}
	})
}

// TestSandboxModuleInertWhenInactive is the sandbox module's absence proof
// with a real daemon (sandbox plan v2 section 11.4): with the Sandboxes and
// VMs module active the probe route answers, and with it inactive the route
// answers 404 component_not_installed and the daemon starts no sandbox
// helper process. Removing the route guard (or the catalog's route row)
// fails the inactive half.
func TestSandboxModuleInertWhenInactive(t *testing.T) {
	bin := smokeBinary(t)
	rep := binaryReport(t, bin)
	if !reportCompiled(rep)["terminals.sandbox"] {
		t.Skipf("the %s distro does not offer the sandbox module", rep.Distro)
	}
	dashboardOwner := ""
	for comp, key := range automaticTCPListeners() {
		if key == "dashboard.addr" {
			dashboardOwner = comp
		}
	}
	if dashboardOwner == "" {
		t.Fatal("no component declares the dashboard listener")
	}
	probe := func(t *testing.T, port int) (int, string) {
		t.Helper()
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/terminal/sandbox", port))
		if err != nil {
			return 0, err.Error()
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	// helperRunning looks for a sandbox-host helper of THIS binary (lane
	// sbx-p2, P-017 (g): the old pattern matched any observer on the box).
	helperRunning := func(d *daemon) bool {
		out, _ := exec.Command("pgrep", "-f", bin+" sandbox-host").Output() //nolint:gosec // G204: the test's own binary path
		return len(bytes.TrimSpace(out)) > 0
	}
	t.Run("active: the probe route answers", func(t *testing.T) {
		cfg, ports := inertConfig(t, dashboardOwner, "terminals", "isolation", "terminals.sandbox")
		d := startDaemon(t, bin, cfg)
		var code int
		var body string
		waitFor(t, d, 90*time.Second, "the sandbox probe route", func() bool {
			code, body = probe(t, ports[dashboardOwner])
			return code == http.StatusOK
		})
		if strings.Contains(body, "component_not_installed") {
			t.Fatalf("an active module answered %s", body)
		}
	})
	t.Run("inactive: 404 component_not_installed and no helper", func(t *testing.T) {
		cfg, ports := inertConfig(t, dashboardOwner, "terminals")
		d := startDaemon(t, bin, cfg)
		var code int
		var body string
		waitFor(t, d, 90*time.Second, "the dashboard", func() bool {
			code, body = probe(t, ports[dashboardOwner])
			return code != 0
		})
		if code != http.StatusNotFound || !strings.Contains(body, "component_not_installed") {
			t.Fatalf("an inactive sandbox module answered %d %s", code, body)
		}
		// The half that tests the claim (P-017 (g)): ASK for a sandboxed
		// launch through the CLI, the path that would start the helper, and
		// prove it is refused for the inactive module and no helper starts.
		cfgPath := filepath.Join(d.home, ".observer", "config.toml")
		cli := exec.Command(bin, "claude", "--observer-sandbox", "bwrap", "--config", cfgPath) //nolint:gosec // G204: the test's own binary and temp path.
		cli.Env = []string{"HOME=" + d.home, "PATH=/usr/bin:/bin", "TMPDIR=" + d.home}
		cli.Dir = d.home
		out, err := cli.CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 3 || !strings.Contains(string(out), "not active") {
			t.Fatalf("a sandboxed CLI launch with the module inactive: err %v output %q", err, out)
		}
		if helperRunning(d) {
			t.Fatal("an observer sandbox-host process runs with the module inactive")
		}
	})
}
