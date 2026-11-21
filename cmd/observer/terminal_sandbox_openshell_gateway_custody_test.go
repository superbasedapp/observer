//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// TestOpenShellGatewayCustodyRecordNames pins that every custody record
// is a valid keystore name (the planner cannot import the keystore).
func TestOpenShellGatewayCustodyRecordNames(t *testing.T) {
	id, err := sandboxopenshell.IdentityFor("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range sandboxopenshell.CustodyRecordNames(id) {
		if !keystore.ValidName(n) {
			t.Fatalf("custody record %q is not a keystore name", n)
		}
	}
}

// TestOpenShellGatewayCustodyAdapter round-trips the PKI and the KEK
// through the adapter over a memory keystore, and checks a missing record
// reads as no custody, not an error.
func TestOpenShellGatewayCustodyAdapter(t *testing.T) {
	id, _ := sandboxopenshell.IdentityFor("0123456789abcdef0123456789abcdef")
	c := openShellCustody{s: &keystore.MemStore{}}
	if _, ok, err := c.Load("gateway.none"); ok || err != nil {
		t.Fatalf("a missing record: ok %v err %v", ok, err)
	}
	files := map[string][]byte{}
	for _, f := range sandboxopenshell.PKIFiles {
		files[f] = []byte("SENTINEL " + f)
	}
	if err := sandboxopenshell.SavePKI(c, id, files); err != nil {
		t.Fatal(err)
	}
	got, err := sandboxopenshell.LoadPKI(c, id)
	if err != nil || !bytes.Equal(got["ca.key"], files["ca.key"]) {
		t.Fatalf("round trip: %v", err)
	}
	kek, err := sandboxopenshell.LoadOrCreateKEK(c, id, bytes.NewReader(bytes.Repeat([]byte{9}, sandboxopenshell.KEKBytes)))
	if err != nil || kek == "" {
		t.Fatalf("kek: %v", err)
	}
	// A fail-closed keystore refuses every save.
	if err := sandboxopenshell.SavePKI(openShellCustody{s: keystore.FailClosed()}, id, files); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("a fail-closed store saved: %v", err)
	}
}

// TestOpenShellGatewayKeystoreRetry (lane OC, audit finding O2-W1): a
// locked keychain is probed once per process, again only when a pass
// marked the outcome stale and the backoff (doubling, capped) has passed;
// keys pinned to the owner-only file store never probe the keychain.
func TestOpenShellGatewayKeystoreRetry(t *testing.T) {
	oldProbe, oldFile, oldNow, oldLate := openShellGatewayKeystore, openShellGatewayFileKeystore, openShellKeystoreNow, openShellKeystoreLate
	t.Cleanup(func() {
		openShellGatewayKeystore, openShellGatewayFileKeystore, openShellKeystoreNow, openShellKeystoreLate = oldProbe, oldFile, oldNow, oldLate
	})
	late := uint64(0)
	openShellKeystoreLate = func() uint64 { return late }
	probes := 0
	reason := keystore.ReasonProbeTimeout
	openShellGatewayKeystore = func(string) (keystore.Store, string) { probes++; return &keystore.MemStore{}, reason }
	fileStore := &keystore.MemStore{}
	openShellGatewayFileKeystore = func(string) keystore.Store { return fileStore }
	now := time.Unix(1_800_000_000, 0)
	openShellKeystoreNow = func() time.Time { return now }
	dir := t.TempDir()
	t.Cleanup(func() { openShellGatewayKeystores.Delete(dir) })
	open := func() string { _, r := openShellGatewayKeystoreCached(dir, ""); return r }

	steps := []struct {
		name    string
		forget  bool
		advance time.Duration
		probes  int
	}{
		{name: "the first open probes", probes: 1},
		{name: "a second open without a stale mark does not", probes: 1},
		{name: "stale, within the first backoff: no probe", forget: true, advance: 30 * time.Second, probes: 1},
		{name: "the first backoff passed: probe", advance: 31 * time.Second, probes: 2},
		{name: "stale again, one minute later: the backoff doubled", forget: true, advance: time.Minute, probes: 2},
		{name: "two minutes in: probe", advance: time.Minute, probes: 3},
		{name: "stale, the next backoff is four minutes", forget: true, advance: 3 * time.Minute, probes: 3},
		{name: "four minutes in: probe", advance: time.Minute, probes: 4},
	}
	for _, s := range steps {
		if s.forget {
			openShellGatewayKeystoreForget(dir)
		}
		now = now.Add(s.advance)
		if r := open(); r != keystore.ReasonProbeTimeout || probes != s.probes {
			t.Fatalf("%s: reason %q, %d probes, want %d", s.name, r, probes, s.probes)
		}
	}
	// Audit finding OC-A4: a probe given up on answered late (the keychain
	// was unlocked): the next open probes at once, inside the backoff and
	// with no stale mark, and the keychain is in use.
	reason = ""
	late++
	now = now.Add(time.Second)
	if r := open(); r != "" || probes != 5 {
		t.Fatalf("after a late success: reason %q, %d probes", r, probes)
	}
	late++
	if r := open(); r != "" || probes != 5 {
		t.Fatalf("a late success re-probes a usable outcome: reason %q, %d probes", r, probes)
	}
	// Pinned to the owner-only file store: no probe, the file store.
	reason = keystore.ReasonProbeTimeout
	ks, r := openShellGatewayKeystoreCached(t.TempDir(), sandboxopenshell.CustodyOwnerFile)
	if ks != keystore.Store(fileStore) || r != openShellReasonPinnedOwnerFile || probes != 5 || openShellKeychainLocked(r) {
		t.Fatalf("pinned owner_file: %v %q, %d probes", ks, r, probes)
	}
}

// TestOpenShellKeystoreBackoff: one row per backoff step, capped.
func TestOpenShellKeystoreBackoff(t *testing.T) {
	for _, tc := range []struct {
		fails int
		want  time.Duration
	}{{0, time.Minute}, {1, time.Minute}, {2, 2 * time.Minute}, {3, 4 * time.Minute}, {4, 8 * time.Minute}, {5, 10 * time.Minute}, {40, 10 * time.Minute}} {
		if got := openShellKeystoreBackoff(tc.fails); got != tc.want {
			t.Errorf("fails %d: %s, want %s", tc.fails, got, tc.want)
		}
	}
}

// TestOpenShellGatewayLoopRunningFor (lane OC): the daemon-ownership read
// takes no lock (a lifecycle pass reads it while it holds the gateway's
// file lock, so it must not wait on a reconcile holding the loop's mutex).
func TestOpenShellGatewayLoopRunningFor(t *testing.T) {
	lp := &openShellGatewayLoopT{}
	if lp.runningFor("/s") {
		t.Fatal("an idle loop runs for nothing")
	}
	dir := "/s"
	lp.running.Store(&dir)
	lp.mu.Lock()
	done := make(chan bool, 1)
	go func() { done <- lp.runningFor("/s") && !lp.runningFor("/other") }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("runningFor read the wrong dir")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runningFor waited on the loop's mutex")
	}
	lp.mu.Unlock()
}

// TestOpenShellGatewayKeystoreServiceOnTheRow pins that the row's
// KeystoreServices capability field names the planner's keystore service,
// so `observer uninstall --all` removes the managed gateway's keychain
// entries through the row, in every build.
func TestOpenShellGatewayKeystoreServiceOnTheRow(t *testing.T) {
	row, ok := sandboxbackend.Get(sandboxbackend.BackendOpenShell)
	if !ok || !slices.Contains(row.KeystoreServices, sandboxopenshell.GatewayKeystoreService) {
		t.Fatalf("the row's KeystoreServices %v does not name %s", row.KeystoreServices, sandboxopenshell.GatewayKeystoreService)
	}
	if !slices.Contains(staticKeystoreServices(), sandboxopenshell.GatewayKeystoreService) {
		t.Fatal("uninstall's service list does not read the row's field")
	}
}
