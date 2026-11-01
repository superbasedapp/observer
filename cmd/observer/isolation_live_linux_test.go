//go:build linux && !sbo_omit_isolation

package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/isolation"
)

// TestIsolationOneShotLive runs a real program through the isolation
// engine's one-shot shape under bwrap (roadmap F0-11, JSP-12) and checks
// the four properties from inside the run: ~/.observer is not reachable
// (hidden, so not readable and not writable), the project is read-only,
// the output and cache directories are writable, and the host loopback is
// unreachable (egress none).
func TestIsolationOneShotLive(t *testing.T) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap not on PATH")
	}
	if err := exec.Command(bwrap, "--ro-bind", "/", "/", "--unshare-net", "--unshare-pid", "--proc", "/proc", "--", "true").Run(); err != nil {
		t.Skipf("bwrap cannot create the namespaces here (%v)", err)
	}
	sh, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not on PATH")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	home := t.TempDir()
	obs := filepath.Join(home, ".observer")
	project := filepath.Join(home, "src", "proj")
	runDir := t.TempDir()
	out, cache := filepath.Join(runDir, "out"), filepath.Join(runDir, "cache")
	for _, d := range []string{obs, project, out, cache} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(obs, "posture.json"), []byte("SECRET-POSTURE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "main.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := isolation.New(isolation.Host{Bwrap: bwrap, Home: home, ObserverDir: obs}, extrun.OneShotDirs{Project: project, Output: out, Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	script := strings.Join([]string{
		`cat ` + obs + `/posture.json 2>/dev/null | grep -q SECRET && echo "READ observer" || echo "HIDDEN observer"`,
		`touch ` + obs + `/dirty 2>/dev/null && [ -e ` + obs + `/dirty ] && echo "WROTE observer" || echo "NOWRITE observer"`,
		`cat main.go >/dev/null && echo "READ project"`,
		`touch main.go 2>/dev/null && echo "WROTE project" || echo "RO project"`,
		`echo ok > ` + out + `/result.sarif && echo "WROTE output"`,
		`echo ok > ` + cache + `/c && echo "WROTE cache"`,
		`(exec 4<>/dev/tcp/127.0.0.1/` + port + `) 2>/dev/null && echo "REACH loopback" || echo "NOREACH loopback"`,
	}, "\n")
	wrapped, err := p.Wrap(context.Background(), extrun.Plan{Path: sh, Args: []string{"-c", script}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, wrapped.Path, wrapped.Args...) //nolint:gosec // the test's own fixed script under the planner's argv
	cmd.Dir = wrapped.Dir
	got, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("one-shot run failed: %v\n%s", err, got)
	}
	for _, want := range []string{"HIDDEN observer", "READ project", "RO project", "WROTE output", "WROTE cache", "NOREACH loopback"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	if _, err := os.Stat(filepath.Join(obs, "dirty")); err == nil {
		t.Error("the run wrote into the real ~/.observer")
	}
	if b, _ := os.ReadFile(filepath.Join(out, "result.sarif")); string(b) != "ok\n" {
		t.Errorf("output not on the host: %q", b)
	}
}
