package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/winrelay"
)

// freeLoopbackPort returns a 127.0.0.1 port nothing listens on.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

// stubRelayHome points the relay's home rule at home (or err) for one test.
func stubRelayHome(t *testing.T, home string, err error) {
	t.Helper()
	prev := relayHome
	relayHome = func() (string, error) { return home, err }
	t.Cleanup(func() { relayHome = prev })
}

// TestRelayWriterAndReadersShareTheJournal pins audit item 4: the journal
// the relay writes is the one the Windows-host reader reads, by one rule,
// with no flag to move it.
func TestRelayWriterAndReadersShareTheJournal(t *testing.T) {
	home := t.TempDir()
	stubRelayHome(t, home, nil)
	path, err := relayJournalPath()
	if err != nil {
		t.Fatal(err)
	}
	dirs := diag.RelayJournalDirs("windows", home, false, nil, nil)
	if len(dirs) != 1 || filepath.Join(dirs[0], winrelay.JournalFile) != path {
		t.Fatalf("writer %q, readers %v", path, dirs)
	}
	if newRelayCmd().Commands()[0].Flags().Lookup("journal") != nil {
		t.Fatal("observer relay serve must not take a journal flag")
	}
}

// TestRelayServeRefusesWhileGated pins DEC-12 for the relay: `observer relay
// serve` names the live checks and binds nothing until they pass.
func TestRelayServeRefusesWhileGated(t *testing.T) {
	port := freeLoopbackPort(t)
	err := runRelayServe(context.Background(), relayServeOptions{
		configPath: filepath.Join(t.TempDir(), "config.toml"),
		port:       port, proxyPort: 8820,
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "built, waiting on live check LC6 and LC14") {
		t.Fatalf("serve while gated = %v, want the live-check refusal", err)
	}
	ln, lerr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if lerr != nil {
		t.Fatalf("the gated relay must not have bound its port: %v", lerr)
	}
	_ = ln.Close()
}

// TestRelayServeBelowTheGate runs the real serve path: it binds the IPv4
// loopback, refuses its own port as the proxy's, and stops with its context.
func TestRelayServeBelowTheGate(t *testing.T) {
	prev := runLiveGatedRelay
	runLiveGatedRelay = true
	t.Cleanup(func() { runLiveGatedRelay = prev })
	home := t.TempDir()
	stubRelayHome(t, home, nil)

	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	port := freeLoopbackPort(t)
	if err := runRelayServe(context.Background(), relayServeOptions{configPath: cfgPath, port: port, proxyPort: port}, &bytes.Buffer{}); err == nil {
		t.Fatal("a relay on the proxy's port must be refused")
	}
	stubRelayHome(t, "", errors.New("isolated"))
	if err := runRelayServe(context.Background(), relayServeOptions{configPath: cfgPath, port: port, proxyPort: 8820}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "where the doctor and the managed report read it") {
		t.Fatalf("a relay with no real home must be refused, got %v", err)
	}
	stubRelayHome(t, home, nil)

	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- runRelayServe(ctx, relayServeOptions{configPath: cfgPath, port: port, proxyPort: 8820}, &out)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay never listened: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop with its context")
	}
}

func TestRelayStatusNamesTheGate(t *testing.T) {
	var out bytes.Buffer
	if err := runRelayStatus(time.Now(), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"built, waiting on live check LC6 and LC14", "http://127.0.0.1:8829/r/claude-code"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status output lacks %q:\n%s", want, out.String())
		}
	}
}

// TestRelayLeavesTheHookGateFailClosed pins D12's second half: the relay
// fails open for model TRAFFIC only and changes nothing about the hook gate.
// With the daemon down (its last posture stale) on a node whose guard
// enforces, a gate hook that cannot evaluate still blocks: the in-WSL hook
// decides from the config itself and needs neither the daemon nor the
// relay. (With WSL itself down, wsl.exe cannot start the hook and the host
// tool decides from the bridge's exit code; that case is live check LC6 and
// docs/security.md HOOKFAIL-4, outside the relay.)
func TestRelayLeavesTheHookGateFailClosed(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	writeFileT(t, cfgPath, fmt.Sprintf("[observer]\ndb_path = %q\n[guard]\nenabled = true\nmode = \"enforce\"\n", filepath.ToSlash(filepath.Join(dir, "o.db"))))
	key, err := guardposture.LoadOrCreateKey(guardposture.KeyPath(cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	p := enforcedPosture
	p.Managed, p.TenancyRecorded = true, true
	p.WrittenAt = time.Now().Add(-10 * time.Minute) // the daemon stopped minutes ago
	if _, err := guardposture.Write(guardposture.PosturePath(cfgPath), p, key); err != nil {
		t.Fatal(err)
	}
	if got := hookPostureFailsClosed(cfgPath, cfgPath, integration.HookCapToolGate); !got.FailsClosed {
		t.Fatal("with the daemon down, an enforcing node's tool gate must still fail closed")
	}
}
