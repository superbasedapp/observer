//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// terminal_sandbox_openshell_egress_drops_test.go pins lane OC's fix round
// 1 of the OCSF hold and the dropped counts (audit findings OC-A1, OC-A3
// and OC-A8); the cases began as the audit's probes.

// egressHeldCount counts the held entries of box id, and all of them.
func egressHeldCount(g *openShellOCSFIngest, id string) (int, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, p := range g.pending {
		if p.d.SandboxID == id {
			n++
		}
	}
	return n, len(g.pending)
}

// egressNoRetry keeps the hold's retry pass from running on its own.
func egressNoRetry(t *testing.T) {
	t.Helper()
	old := openShellOCSFRetry
	openShellOCSFRetry = time.Hour
	t.Cleanup(func() { openShellOCSFRetry = old })
}

// TestOpenShellOCSFPostFloodKeepsEarlyBurst is audit finding OC-A1's first
// probe: a real box's burst of 10 denials held before a flood of 600
// one-entry made-up ids keeps all 10 (a later id never evicts an earlier
// one's entry), every flood record past the hold's total is counted, and
// the earlier box may still grow to its per-id bound by evicting later
// ids' entries.
func TestOpenShellOCSFPostFloodKeepsEarlyBurst(t *testing.T) {
	egressNoRetry(t)
	g, _, _ := egressTestIngest(t, sandboxopenshell.RunEgress{Tier: vocab.TierInternet, Hosts: []string{"api.github.com"}})
	now := time.Unix(1793000000, 0)
	g.now = func() time.Time { return now }
	ctx := context.Background()
	real := "0a415311-0000-4000-8000-00000000beaf"
	_ = g.handle(ctx, egressTestExportN(real, 0, 10))
	for i := 0; i < 600; i++ {
		now = now.Add(time.Millisecond)
		_ = g.handle(ctx, egressTestExport(egressFakeID(1000+i), "w-"+strconv.Itoa(i), "", "x.example"))
	}
	if n, total := egressHeldCount(g, real); n != 10 || total != openShellOCSFHoldTotal {
		t.Fatalf("after the flood: real box holds %d (want 10), hold %d", n, total)
	}
	g.mu.Lock()
	counted := g.unattributed
	g.mu.Unlock()
	if want := 10 + 600 - openShellOCSFHoldTotal; counted != want {
		t.Fatalf("%d drops counted, want %d", counted, want)
	}
	now = now.Add(time.Millisecond)
	_ = g.handle(ctx, egressTestExportN(real, 100, 10))
	if n, total := egressHeldCount(g, real); n != openShellOCSFHoldPerBox || total != openShellOCSFHoldTotal {
		t.Fatalf("the earlier box grew to %d (want %d), hold %d", n, openShellOCSFHoldPerBox, total)
	}
}

// TestOpenShellOCSFSaturatedDroppedIDsAreUncertain is audit finding
// OC-A1's second probe: a forger fills the hold and the table of dropped
// box ids, then a real box's denial is dropped with its claimed id not
// remembered. It is counted as uncertain against the run that was waiting
// for its box id (its helper holds the run dir, no box id recorded), so
// the run never reads as complete; a run not waiting is charged nothing.
func TestOpenShellOCSFSaturatedDroppedIDsAreUncertain(t *testing.T) {
	egressNoRetry(t)
	g, stateDir, _ := egressTestIngest(t, sandboxopenshell.RunEgress{Tier: vocab.TierInternet, Hosts: []string{"api.github.com"}})
	const waiting = "-RunSENTINEL0000_real"
	oldHeld := openShellOCSFRunHeld
	openShellOCSFRunHeld = func(dir string) bool { return filepath.Base(dir) == waiting }
	t.Cleanup(func() { openShellOCSFRunHeld = oldHeld })
	if err := os.MkdirAll(openShellRunDir(stateDir, waiting), 0o700); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	drops, uncertain := map[string]int{}, map[string]int{}
	g.dropSink = func() func(sandboxrelayd.RunRecord, egressRefusalDropCount) {
		return func(rr sandboxrelayd.RunRecord, n egressRefusalDropCount) {
			mu.Lock()
			defer mu.Unlock()
			drops[rr.RunID] += n.Dropped
			uncertain[rr.RunID] += n.Uncertain
		}
	}
	now := time.Unix(1793000000, 0)
	g.now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < openShellOCSFHoldTotal+openShellOCSFDroppedIDs; i++ {
		now = now.Add(time.Microsecond)
		_ = g.handle(ctx, egressTestExport(egressFakeID(10000+i), "s-"+strconv.Itoa(i), "", "x.example"))
	}
	real := "0a415311-0000-4000-8000-00000000beaf"
	now = now.Add(time.Millisecond)
	_ = g.handle(ctx, egressTestExport(real, "r-1", "", "early.example"))
	egressTestRunDir(t, stateDir, waiting, real, sandboxopenshell.RunEgress{Tier: vocab.TierInternet, Hosts: []string{"api.github.com"}})
	g.summarize()
	mu.Lock()
	defer mu.Unlock()
	if uncertain[waiting] != 1 || drops[waiting] != 0 || uncertain[egressTestRun] != 0 {
		t.Fatalf("dropped %v uncertain %v; want the waiting run's one uncertain drop", drops, uncertain)
	}
}

// TestOpenShellOCSFDropsAfterRunEndKeepTheRowsRunID is audit finding
// OC-A3's probe: a bound run drops denials past its rate bound, then ends
// (its relay record removed) before the summary; its dropped count lands
// under the terminal run id its rows carry, and every refusal the receiver
// did not write is counted there (audit finding OC-A2).
func TestOpenShellOCSFDropsAfterRunEndKeepTheRowsRunID(t *testing.T) {
	g, _, _ := egressTestIngest(t, sandboxopenshell.RunEgress{Tier: vocab.TierInternet, Hosts: []string{"api.github.com"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeRefusalStore{}
	r := newEgressRefusalReceiver(ctx, f, nil)
	g.sink = func() func(sandboxrelayd.RunRecord, sandboxrelay.EgressRefusalReport) { return r.OnEgressRefusal }
	g.dropSink = func() func(sandboxrelayd.RunRecord, egressRefusalDropCount) { return r.OnDropped }
	rec := sandboxrelayd.RunRecord{V: sandboxrelayd.RecordVersion, RunID: egressTestRun, Tool: "claude-code", BoxSecret: bytes.Repeat([]byte{1}, sandboxrelay.SecretSize), LinkSecret: bytes.Repeat([]byte{2}, sandboxrelay.SecretSize), CreatedAt: time.Now(), TerminalRunID: "term-1"}
	if err := sandboxrelayd.WriteRun(g.observerDir, rec); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	g.now = func() time.Time { return now }
	sent := openShellOCSFPerRunPerSecond + 20
	_ = g.handle(context.Background(), egressTestExportN(egressTestBox, 0, sent))
	if err := sandboxrelayd.RemoveRun(g.observerDir, egressTestRun); err != nil {
		t.Fatal(err)
	}
	g.summarize()
	waitForRefusal(t, func() bool {
		d, _ := f.dropCounts()
		return len(f.all())+d["term-1"] == sent
	})
	d, _ := f.dropCounts()
	for _, row := range f.all() {
		if row.RunID != "term-1" {
			t.Fatalf("a row under %q", row.RunID)
		}
	}
	if len(d) != 1 {
		t.Fatalf("dropped counts %v, want only term-1", d)
	}
}

// TestOpenShellOCSFUnattributedNeverNegative is audit finding OC-A8: an id
// dropped in one summary window and charged to its run in the next takes
// nothing off that window's unattributed count, so another id's drop in
// it is still logged.
func TestOpenShellOCSFUnattributedNeverNegative(t *testing.T) {
	egressNoRetry(t)
	g, stateDir, _ := egressTestIngest(t, sandboxopenshell.RunEgress{Tier: vocab.TierInternet})
	var log egressTestLog
	g.logger = slog.New(slog.NewTextHandler(&log, nil))
	g.dropSink = func() func(sandboxrelayd.RunRecord, egressRefusalDropCount) {
		return func(sandboxrelayd.RunRecord, egressRefusalDropCount) {}
	}
	now := time.Unix(1793000000, 0)
	g.now = func() time.Time { return now }
	x, y := egressFakeID(1), egressFakeID(2)
	g.mu.Lock()
	g.countDropLocked(x)
	g.mu.Unlock()
	g.summarize()
	now = now.Add(time.Minute)
	egressTestRunDir(t, stateDir, "-RunSENTINEL0000_x", x, sandboxopenshell.RunEgress{Tier: vocab.TierInternet})
	g.mu.Lock()
	g.countDropLocked(y)
	g.mu.Unlock()
	g.summarize()
	lines := strings.Split(strings.TrimSpace(log.String()), "\n")
	var unattributed []string
	for _, l := range lines {
		if strings.Contains(l, "box ids no run names") {
			unattributed = append(unattributed, l)
		}
	}
	if len(unattributed) != 2 || !strings.Contains(unattributed[1], "dropped=1") {
		t.Fatalf("unattributed lines %q", unattributed)
	}
}

// TestOpenShellOCSFUnnamedDenialIsCounted (O5 audit finding O5-A6): a real
// denial whose destination name cannot be recorded (an underscore label,
// a wildcard) never reaches the refusal page, but it is counted as its
// run's dropped denial, once per uid, so require_refusal_audit's "every
// refusal is audited" has no silent hole. A box no run dir names yet is
// counted the way a dropped held record is, and charged to its run once
// its id is recorded.
func TestOpenShellOCSFUnnamedDenialIsCounted(t *testing.T) {
	egressNoRetry(t)
	g, stateDir, got := egressTestIngest(t, sandboxopenshell.RunEgress{Tier: vocab.TierInternet, Hosts: []string{"api.github.com"}})
	var mu sync.Mutex
	drops := map[string]int{}
	g.dropSink = func() func(sandboxrelayd.RunRecord, egressRefusalDropCount) {
		return func(rr sandboxrelayd.RunRecord, n egressRefusalDropCount) {
			mu.Lock()
			defer mu.Unlock()
			drops[rr.RunID] += n.Dropped
		}
	}
	now := time.Unix(1793000000, 0)
	g.now = func() time.Time { return now }
	ctx := context.Background()
	cases := []struct {
		box, uid, host string
	}{
		{egressTestBox, "u-1", "a_b.example.com"},
		{egressTestBox, "u-2", "*.example.com"},
		{egressTestBox, "u-2", "*.example.com"}, // the same uid again: counted once
	}
	for _, tc := range cases {
		_ = g.handle(ctx, egressTestExport(tc.box, tc.uid, "", tc.host))
	}
	late := "0a415311-0000-4000-8000-00000000a6a6"
	_ = g.handle(ctx, egressTestExport(late, "u-3", "", "c_d.example.com"))
	if r := got(); len(r) != 0 {
		t.Fatalf("an unnamed denial reached the refusal page: %+v", r)
	}
	egressTestRunDir(t, stateDir, "-RunSENTINEL0000_a6a6", late, sandboxopenshell.RunEgress{Tier: vocab.TierInternet})
	g.summarize()
	mu.Lock()
	defer mu.Unlock()
	if drops[egressTestRun] != 2 || drops["-RunSENTINEL0000_a6a6"] != 1 || len(drops) != 2 {
		t.Fatalf("dropped counts %v", drops)
	}
}
