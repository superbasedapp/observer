//go:build !sbo_omit_security && !sbo_omit_security_trust && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
)

// TestSandboxRelayGateIsDaemonStarted (item 10, and lane SEC-TRUST4 item
// 2e): the relay gate the daemon starts for an in-box launch checks the box
// directory the relay started it in (relayChildDir, read back with
// os.Getwd), never another; it never asks (its stdin is the evidence),
// refuses an ask naming where to accept, refuses to run without the channel
// record, and sets no checked marker in its own environment.
func TestSandboxRelayGateIsDaemonStarted(t *testing.T) {
	cfgPath, _ := daemonTrustSetup(t, "enforce")
	untrusted := writeTrustRepo(t, untrustedHookRepo)
	clean := writeTrustRepo(t, map[string]string{"README.md": "# x\n"})

	// The walk itself.
	err := sandboxGateWalk(context.Background(), cfgPath, "claude-code", budgetLaunchEvidence{}, untrusted, "")
	if err == nil || !strings.Contains(err.Error(), "S-701") || !strings.Contains(err.Error(), "observer security trust accept --all --dir "+untrusted) {
		t.Fatalf("untrusted box directory: %v, want the unattended refusal", err)
	}
	if err := sandboxGateWalk(context.Background(), cfgPath, "claude-code", budgetLaunchEvidence{}, clean, ""); err != nil {
		t.Fatalf("clean box directory refused (the process's own directory was read?): %v", err)
	}

	// The wiring: the executor starts the gate in relayChildDir(run, cwd),
	// the gate reads that directory back with os.Getwd.
	run := sandboxrelayd.RunRecord{
		RunID: "r1", Tool: "claude-code", ProjectRoot: untrusted, WorkspaceDir: untrusted,
		Roots: []string{untrusted, clean}, Delivery: sandboxrelayd.DeliveryLive,
	}
	record := func() (relayChildRecord, error) { return relayChildRecord{V: 1, RunID: run.RunID}, nil }
	gate := func(cwd string) (int, string) {
		t.Helper()
		t.Chdir(relayChildDir(run, cwd))
		var stderr bytes.Buffer
		code := runSandboxGateWith(context.Background(), "claude-code", cfgPath, strings.NewReader(`{}`), &stderr, record, os.Getwd)
		return code, stderr.String()
	}
	if code, out := gate(clean); code != 0 {
		t.Fatalf("box cwd in a clean root: exit %d %s", code, out)
	}
	if code, out := gate(untrusted); code != 1 || !strings.Contains(out, "S-701") {
		t.Fatalf("box cwd in the untrusted root: exit %d %s", code, out)
	}
	// A cwd outside the run's roots is not followed: the gate runs in the
	// workspace (here the untrusted root), so it refuses.
	if code, out := gate(t.TempDir()); code != 1 || !strings.Contains(out, "S-701") {
		t.Fatalf("box cwd outside the roots: exit %d %s, want the workspace checked", code, out)
	}
	var stderr bytes.Buffer
	if code := runSandboxGateWith(context.Background(), "claude-code", cfgPath, strings.NewReader(`{}`), &stderr,
		func() (relayChildRecord, error) { return relayChildRecord{}, errors.New("no channel") }, os.Getwd); code != 2 {
		t.Fatalf("no channel record: exit %d %s", code, stderr.String())
	}
	if os.Getenv(repoTrustCheckedEnv) != "" {
		t.Fatal("the gate set the checked marker in its own environment")
	}
}

// TestSandboxRelayGateCloneHonoursSourceAccepts (plans decision log P-037
// finding 2): a sandboxed clone's relay gate honours the accepts the
// developer gave the source repository, which the run record names
// (relayRunTrustAcceptRoot), while it still reads the clone's own files: an
// accepted source lets the clone launch under enforce, and an unaccepted
// change inside the clone still refuses, naming the source as where to
// accept, never the throwaway workspace.
func TestSandboxRelayGateCloneHonoursSourceAccepts(t *testing.T) {
	ctx := context.Background()
	cfgPath, _ := daemonTrustSetup(t, "enforce")
	source, clone := writeTrustRepo(t, untrustedHookRepo), writeTrustRepo(t, untrustedHookRepo)
	run := sandboxrelayd.RunRecord{
		RunID: "r2", Tool: "claude-code", ProjectRoot: source, WorkspaceDir: clone,
		Roots: []string{clone}, Delivery: sandboxrelayd.DeliveryCopy, CopyHostPath: clone,
	}
	if got := relayRunTrustAcceptRoot(run); got != source {
		t.Fatalf("copy run accept root %q, want the source %q", got, source)
	}
	live := run
	live.Delivery, live.WorkspaceDir = sandboxrelayd.DeliveryLive, source
	if got := relayRunTrustAcceptRoot(live); got != "" {
		t.Fatalf("live run accept root %q, want none", got)
	}

	// Not accepted yet: refused, and the refusal names the source.
	err := sandboxGateWalk(ctx, cfgPath, "claude-code", budgetLaunchEvidence{}, clone, relayRunTrustAcceptRoot(run))
	if err == nil || !strings.Contains(err.Error(), "observer security trust accept --all --dir "+source) {
		t.Fatalf("unaccepted source: %v, want a refusal naming the source", err)
	}
	if strings.Contains(err.Error(), "--dir "+clone) {
		t.Fatalf("the refusal names the throwaway workspace: %v", err)
	}

	// The developer accepts the source.
	st := openTrustTestDBFromConfig(t, cfgPath)
	res, err := sectrust.Check(ctx, sectrust.OSFS(source), sectrust.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcceptSecTrustItems(ctx, guard.HashProjectRoot(source), secTrustItems(res), "cli:test", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := sandboxGateWalk(ctx, cfgPath, "claude-code", budgetLaunchEvidence{}, clone, relayRunTrustAcceptRoot(run)); err != nil {
		t.Fatalf("clone of an accepted source refused: %v", err)
	}
	// The same clone checked on its own accepts (no accept root) refuses.
	if err := sandboxGateWalk(ctx, cfgPath, "claude-code", budgetLaunchEvidence{}, clone, ""); err == nil {
		t.Fatal("a clone with no accept root honoured the source's accepts")
	}

	// The gate process takes the accept root from its channel record
	// (rec.TrustAcceptRoot), never from the box: with the record's root the
	// clone launches, and the same record without it refuses (SEC-TRUST4
	// merge audit finding 3: passing "" there would fail this).
	gateWith := func(rec relayChildRecord) (int, string) {
		var stderr bytes.Buffer
		code := runSandboxGateWith(ctx, "claude-code", cfgPath, strings.NewReader(`{}`), &stderr,
			func() (relayChildRecord, error) { return rec, nil }, func() (string, error) { return clone, nil })
		return code, stderr.String()
	}
	if code, out := gateWith(relayChildRecord{V: 1, RunID: run.RunID, TrustAcceptRoot: relayRunTrustAcceptRoot(run)}); code != 0 {
		t.Fatalf("relay gate with the record's accept root: exit %d %s", code, out)
	}
	if code, out := gateWith(relayChildRecord{V: 1, RunID: run.RunID}); code != 1 || !strings.Contains(out, "S-701") {
		t.Fatalf("relay gate with no accept root in its record: exit %d %s, want the refusal", code, out)
	}

	// An unaccepted change inside the clone still refuses: the walk reads
	// the clone's files.
	if err := os.WriteFile(filepath.Join(clone, ".claude", "settings.json"),
		[]byte(`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"sh .github/other.sh"}]}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	err = sandboxGateWalk(ctx, cfgPath, "claude-code", budgetLaunchEvidence{}, clone, relayRunTrustAcceptRoot(run))
	if err == nil || !strings.Contains(err.Error(), "S-701") || !strings.Contains(err.Error(), "--dir "+source) {
		t.Fatalf("a changed hook inside the clone: %v, want an S-701 refusal naming the source", err)
	}
	// What the clone raised is recorded under the clone's own hash, never
	// in the source's list.
	recs, _ := st.ListSecTrustItems(ctx, guard.HashProjectRoot(source))
	for _, r := range recs {
		if strings.Contains(r.ItemKey, "other.sh") || !r.Accepted() {
			t.Fatalf("clone items landed in the source's list: %+v", r)
		}
	}
}
