//go:build !sbo_omit_security

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/secipc"
)

// security_provenance_nudge.go is the latency half of the AI change record
// (security plan 7.10 "Latency", lane SEC-F2B): when the hook allows an
// agent's commit while the provenance loop runs, it tells the daemon over
// the security IPC (secipc.KindCommitNudge, one line one way), and the
// daemon watches that repository's HEAD for a bounded time and scans it the
// moment it moves, so the record is made seconds after the commit instead
// of on the commit scanner's next 120 s tick. Nothing here blocks the hook:
// the send is bounded by secipc.NudgeBudget and never waits for an answer.

// provenanceActiveFlag is the file the provenance loop keeps while it runs;
// the hook stats it (one stat) before it nudges.
func provenanceActiveFlag(layoutDir string) string {
	return filepath.Join(layoutDir, "provenance", "active")
}

// provenanceNudgeTarget is an agent commit the hook will nudge for once
// guard and the commit gate allowed it.
type provenanceNudgeTarget struct{ layoutDir, root string }

// provenanceNudgeCandidate is this hook process's pending nudge.
var provenanceNudgeCandidate atomic.Pointer[provenanceNudgeTarget]

// provenanceHoldNudge holds a nudge for root when the provenance loop runs
// (its flag exists). Called from provenanceNoteAgentCommit, before guard
// decides; provenanceSendNudge sends it on the allow path.
func provenanceHoldNudge(layoutDir, root string) {
	if _, err := os.Stat(provenanceActiveFlag(layoutDir)); err != nil {
		return
	}
	provenanceNudgeCandidate.Store(&provenanceNudgeTarget{layoutDir: layoutDir, root: root})
}

// provenanceSendNudge sends the held nudge, bounded; a failure only means
// the record waits for the next tick.
func provenanceSendNudge() {
	n := provenanceNudgeCandidate.Swap(nil)
	if n == nil {
		return
	}
	ep, err := secipc.Endpoint(n.layoutDir)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), secipc.NudgeBudget)
	defer cancel()
	_ = secipc.SendCommitNudge(ctx, ep, n.root)
}

// The daemon's watch after a nudge: HEAD is read every
// provenanceNudgePoll for at most provenanceNudgeWait, and at most
// provenanceNudgeMaxWatch repositories are watched at once (a flood of
// nudges is dropped, the tick still covers them).
const (
	provenanceNudgePoll     = 2 * time.Second
	provenanceNudgeWait     = 2 * time.Minute
	provenanceNudgeMaxWatch = 8
)

// provenanceNudger is the daemon side: one bounded watch per repository.
type provenanceNudger struct {
	ctx  context.Context
	head func(ctx context.Context, root string) string
	// scan scans root's commits now (the live commit scanner's ScanNow).
	scan       func(ctx context.Context, root string) error
	poll, wait time.Duration
	mu         sync.Mutex
	watching   map[string]bool
}

// newProvenanceNudger is the production nudger (security_module.go's
// secipc.Options.Nudge), a no-op while the provenance loop is not running.
func newProvenanceNudger(ctx context.Context) secipc.CommitNudger {
	n := &provenanceNudger{ctx: ctx, head: provenanceHead, scan: provenanceScanNow, poll: provenanceNudgePoll, wait: provenanceNudgeWait, watching: map[string]bool{}}
	return func(root string) {
		if provenanceRT.Load() == nil {
			return
		}
		n.take(root)
	}
}

// take starts a watch of root unless one runs or the cap is reached.
func (n *provenanceNudger) take(root string) bool {
	n.mu.Lock()
	if n.watching[root] || len(n.watching) >= provenanceNudgeMaxWatch {
		n.mu.Unlock()
		return false
	}
	n.watching[root] = true
	n.mu.Unlock()
	go n.watch(root)
	return true
}

// watch scans root once its HEAD moves from what it was when the nudge
// came (the hook nudges before the commit runs), or gives up.
func (n *provenanceNudger) watch(root string) {
	defer func() {
		n.mu.Lock()
		delete(n.watching, root)
		n.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(n.ctx, n.wait)
	defer cancel()
	start := n.head(ctx, root)
	t := time.NewTicker(n.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if h := n.head(ctx, root); h != "" && h != start {
			err := n.scan(ctx, root)
			if errors.Is(err, commitscan.ErrScanInProgress) {
				// A tick is scanning it already: let it finish, then once more.
				select {
				case <-ctx.Done():
				case <-time.After(n.poll):
					_ = n.scan(ctx, root)
				}
			}
			return
		}
	}
}

// provenanceHead reads root's HEAD ("" when unreadable).
func provenanceHead(ctx context.Context, root string) string {
	out, _, err := gitview.RunReadOnlyTimeout(ctx, root, 4096, provenanceHookGitTimeout, "rev-parse", "--verify", "--quiet", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// provenanceScanNow scans root through the live commit scanner, whose
// per-commit seam makes the record.
func provenanceScanNow(ctx context.Context, root string) error {
	sc, svc := liveCommitScanner.Load(), provenanceRT.Load()
	if sc == nil || svc == nil {
		return nil
	}
	id, err := svc.st.ProjectIDForRoot(ctx, root)
	if err != nil || id == 0 {
		return err
	}
	_, err = sc.ScanNow(ctx, commitscan.Root{ProjectID: id, RootPath: commitScanRoot(root)})
	return err
}

// provenanceMarkActive keeps the loop's flag for the hook while it runs.
func provenanceMarkActive(layoutDir string) func() {
	flag := provenanceActiveFlag(layoutDir)
	if layoutDir == "" || os.MkdirAll(filepath.Dir(flag), 0o700) != nil || os.WriteFile(flag, []byte("1\n"), 0o600) != nil {
		return func() {}
	}
	return func() { _ = os.Remove(flag) }
}
