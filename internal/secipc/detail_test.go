package secipc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestUnknownAnswerCarriesItsDetail: an unknown scan's reason and numbers
// cross the wire, with the budget the request asked for (not the smaller
// one the scanner was handed), so the commit gate can say "timed out after
// 2 s on 31 files"; a clean or blocking answer carries none.
func TestUnknownAnswerCarriesItsDetail(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	ep := serve(t, func(_ context.Context, r hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
		if r.ProjectRoot == root+"clean" {
			return hookctx.QuickScanResult{Verdict: policy.QuickScanClean, Detail: policy.QuickScanDetail{Reason: "stray"}}, nil
		}
		return hookctx.QuickScanResult{Verdict: policy.QuickScanUnknown, Detail: policy.QuickScanDetail{
			Reason: policy.QuickScanReasonBudget, Budget: 1900 * time.Millisecond, Elapsed: 1900 * time.Millisecond, Files: 31,
		}}, nil
	})
	req := hookctx.QuickScanRequest{ProjectRoot: root, Form: policy.GitWrite{Form: policy.GitWriteCommit}}
	res, err := Ask(context.Background(), ep, req, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := policy.QuickScanDetail{Reason: policy.QuickScanReasonBudget, Budget: 2 * time.Second, Elapsed: 1900 * time.Millisecond, Files: 31}
	if res.Verdict != policy.QuickScanUnknown || res.Detail != want {
		t.Fatalf("Ask = %+v, want unknown with %+v", res, want)
	}
	req.ProjectRoot = root + "clean"
	res, err = Ask(context.Background(), ep, req, 2*time.Second)
	if err != nil || res.Verdict != policy.QuickScanClean || res.Detail != (policy.QuickScanDetail{}) {
		t.Fatalf("clean Ask = %+v, %v; want clean with no detail", res, err)
	}
}

// TestEndpointReasonsCarryTheBudget: the endpoint's own unknown answers
// name the reason and the budget the request asked for.
func TestEndpointReasonsCarryTheBudget(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	rootJSON, _ := json.Marshal(root)
	raw := []byte(`{"v":1,"project_root":` + string(rootJSON) + `,"form":"commit","budget_ms":40}`)
	slow := func(ctx context.Context, _ hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
		<-ctx.Done()
		return hookctx.QuickScanResult{Verdict: policy.QuickScanClean}, nil
	}
	got := answer(context.Background(), raw, slow, nil).decode()
	if got.Verdict != policy.QuickScanUnknown || got.Detail.Reason != policy.QuickScanReasonOverBudget || got.Detail.Budget != 40*time.Millisecond {
		t.Fatalf("over budget = %+v", got)
	}
	got = answer(context.Background(), raw, slow, func(string) bool { return false }).decode()
	if got.Detail.Reason != policy.QuickScanReasonRootNotAllowed {
		t.Fatalf("refused root = %+v", got)
	}
	// A reason past its cap is cut, never carried whole.
	long := response{V: Version, Verdict: "unknown", Reason: string(make([]byte, 500))}
	if r := long.decode(); len(r.Detail.Reason) != maxReasonBytes {
		t.Fatalf("reason length = %d, want %d", len(r.Detail.Reason), maxReasonBytes)
	}
}

// TestBudgetRunsFromTheAccept: the scan's budget is counted from when the
// endpoint took the connection, so time spent before the scan (reading the
// request, checking its root) comes out of it. Before, the scanner got the
// whole budget after that, ran past the hook's own deadline (the budget
// from its dial plus 250 ms), and its answer was lost: the hook read an
// unknown answer with no reason every time.
func TestBudgetRunsFromTheAccept(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	rootJSON, _ := json.Marshal(root)
	raw := []byte(`{"v":1,"project_root":` + string(rootJSON) + `,"form":"commit","budget_ms":1000}`)
	slow := func(ctx context.Context, _ hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
		<-ctx.Done()
		return hookctx.QuickScanResult{Verdict: policy.QuickScanClean}, nil
	}
	start := time.Now()
	got := answerAt(context.Background(), raw, slow, nil, start.Add(-time.Second)).decode()
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("a request whose budget was spent before the scan waited %s", took)
	}
	if got.Detail.Reason != policy.QuickScanReasonOverBudget {
		t.Fatalf("spent budget = %+v", got)
	}
}

// TestAskTimeoutNamesItsReason: a daemon that takes the request and never
// answers gives Ask an error the hook context seam turns into an unknown
// answer saying the scan timed out, with the budget.
func TestAskTimeoutNamesItsReason(t *testing.T) {
	t.Parallel()
	if !localipc.Supported() {
		t.Skip("no owner-only IPC transport on this platform")
	}
	dir, err := os.MkdirTemp("", "secipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, ep, err := Listen(filepath.Join(dir, "security"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = readLine(conn)
		time.Sleep(2 * time.Second)
	}()
	_, err = Ask(context.Background(), ep, hookctx.QuickScanRequest{ProjectRoot: dir}, 100*time.Millisecond)
	if err == nil {
		t.Fatal("a daemon that never answers must be an error")
	}
	got := hookctx.QuickScanFailure(err)
	if got.Verdict != policy.QuickScanUnknown || got.Detail.Reason != policy.QuickScanReasonOverBudget || got.Detail.Budget != 100*time.Millisecond {
		t.Fatalf("QuickScanFailure(%v) = %+v", err, got)
	}
}

// TestUnknownAnswerNamesItsGit (R3-86): which git read the change crosses
// the wire with the detail; a value outside the closed set is dropped, and
// an older peer's answer (no field) reads as the host's git.
func TestUnknownAnswerNamesItsGit(t *testing.T) {
	t.Parallel()
	for _, git := range []string{policy.QuickScanGitWindows, policy.QuickScanGitDrvFs, policy.QuickScanGitDrvFsFallback} {
		in := hookctx.QuickScanResult{Verdict: policy.QuickScanUnknown, Detail: policy.QuickScanDetail{Reason: policy.QuickScanReasonBudget, Git: git}}
		raw, err := json.Marshal(encodeResult(in, ""))
		if err != nil {
			t.Fatal(err)
		}
		var resp response
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatal(err)
		}
		if got := resp.decode().Detail.Git; got != git {
			t.Fatalf("git %q crossed as %q", git, got)
		}
	}
	forged := response{V: Version, Verdict: "unknown", Reason: policy.QuickScanReasonGit, Git: "windows_git; rm -rf /"}
	if got := forged.decode().Detail.Git; got != "" {
		t.Fatalf("an unknown git value crossed: %q", got)
	}
	var old response
	if err := json.Unmarshal([]byte(`{"v":1,"verdict":"unknown","reason":"budget"}`), &old); err != nil {
		t.Fatal(err)
	}
	if got := old.decode().Detail.Git; got != "" {
		t.Fatalf("an older peer's answer names git %q", got)
	}
}
