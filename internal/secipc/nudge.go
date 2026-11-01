package secipc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/localipc"
)

// The commit nudge request kind (security plan 7.10 "Latency", lane
// SEC-F2B): when the hook allows an agent's commit, it tells the daemon to
// scan that repository's commits soon, so the AI change record does not
// wait for the commit scanner's 120 s tick. It rides the quick-scan
// endpoint on its own kind and is one line one way: the hook writes it and
// closes, never waits for an answer, and the daemon never blocks on it (a
// daemon that predates the kind answers bad_request, which nobody reads).

const (
	// KindCommitNudge names the nudge request.
	KindCommitNudge = "commit_nudge"
	// nudgeVersion is the nudge request's wire version.
	nudgeVersion = 1
	// NudgeBudget bounds the hook's dial and write.
	NudgeBudget = 150 * time.Millisecond
)

type nudgeWireRequest struct {
	V           int    `json:"v"`
	Kind        string `json:"kind"`
	ProjectRoot string `json:"project_root"`
}

// CommitNudger takes a nudge for an allowed project root. It must return at
// once (the daemon starts its own bounded work).
type CommitNudger func(projectRoot string)

// nudgeRequestOf reports whether raw is a nudge request.
func nudgeRequestOf(raw []byte) (nudgeWireRequest, bool) {
	var q nudgeWireRequest
	if json.Unmarshal(raw, &q) != nil || q.Kind != KindCommitNudge {
		return nudgeWireRequest{}, false
	}
	return q, true
}

// takeNudge hands an accepted nudge to n: the right version, an absolute
// root the allow check accepts. Anything else is dropped.
func takeNudge(q nudgeWireRequest, n CommitNudger, allow func(string) bool) bool {
	if n == nil || q.V != nudgeVersion || q.ProjectRoot == "" || !filepath.IsAbs(q.ProjectRoot) {
		return false
	}
	if allow != nil && !allow(q.ProjectRoot) {
		return false
	}
	n(q.ProjectRoot)
	return true
}

// serveNudgeConn takes one nudge; nothing is written back.
func serveNudgeConn(conn net.Conn, q nudgeWireRequest, o Options) {
	_ = conn.Close()
	takeNudge(q, o.Nudge, o.AllowRoot)
}

// SendCommitNudge writes one nudge for projectRoot to the endpoint and
// closes, bounded by NudgeBudget; it never reads an answer.
func SendCommitNudge(ctx context.Context, endpoint, projectRoot string) error {
	deadline := time.Now().Add(NudgeBudget)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn, err := localipc.DefaultTransport().Dial(ctx, endpoint, time.Until(deadline))
	if err != nil {
		return fmt.Errorf("secipc.SendCommitNudge: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(deadline)
	line, err := json.Marshal(nudgeWireRequest{V: nudgeVersion, Kind: KindCommitNudge, ProjectRoot: projectRoot})
	if err != nil {
		return fmt.Errorf("secipc.SendCommitNudge: %w", err)
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("secipc.SendCommitNudge: %w", err)
	}
	return nil
}
