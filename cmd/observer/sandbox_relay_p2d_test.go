//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// TestRelayHealthByRunStaysBounded (P-040, milestone 1c): each lowered run
// adds its live health to relayHealthByRun (the run pill's source), and the
// daemon's run-end sweep removes it again, so across many runs the map holds
// only the runs still live.
func TestRelayHealthByRunStaysBounded(t *testing.T) {
	obs := relayShortDir(t)
	ws := t.TempDir()
	d := &sandboxrelayd.Daemon{
		ObserverDir: obs, Rules: relayRules, Peer: sandboxrelayd.PeerSameUser, SweepInterval: -1,
		Exec: func(context.Context, sandboxrelayd.RunRecord, sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
			return sandboxrelay.HookResponse{}, nil
		},
		OnHealth: relayOnHealth(nil, nil),
		OnRunEnd: relayOnRunEnd,
	}
	link := filepath.Join(obs, "link.sock")
	ln, err := net.Listen("unix", link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = d.Serve(ctx, ln) }()
	dial := func(ctx context.Context) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "unix", link)
	}

	const runs = 40
	ids := make([]string, 0, runs)
	refuse := func(rec sandboxrelayd.RunRecord) {
		t.Helper()
		msg, err := sandboxrelay.EncodeHookRequest(sandboxrelay.HookRequest{
			Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "PostToolUse"}, Stdin: []byte(`{"cwd":"/etc"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer rcancel()
		if _, err := sandboxrelayd.LinkRoundTrip(rctx, dial, rec, msg, sandboxrelay.DefaultConnLimits); err != nil {
			t.Fatal(err)
		}
	}
	for i := range runs {
		rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{
			RunID: fmt.Sprintf("p2d-%d", i), Tool: "claude-code", ProjectRoot: ws, WorkspaceDir: ws, Roots: []string{ws},
			TerminalRunID: fmt.Sprintf("term-p2d-%d", i),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
			t.Fatal(err)
		}
		refuse(rec)
		ids = append(ids, rec.TerminalRunID)
	}
	d.FlushHealth()
	held := func() int {
		n := 0
		for _, id := range ids {
			if _, ok := relayHealthByRun.Load(id); ok {
				n++
			}
		}
		return n
	}
	if n := held(); n != runs {
		t.Fatalf("%d live runs on the pill, want %d", n, runs)
	}
	// Every run but the last ends: their helpers removed the records.
	for i := range runs - 1 {
		if err := sandboxrelayd.RemoveRun(obs, fmt.Sprintf("p2d-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := d.Sweep(); n != runs-1 {
		t.Fatalf("the sweep ended %d runs, want %d", n, runs-1)
	}
	d.FlushHealth()
	if n := held(); n != 1 {
		t.Fatalf("%d runs on the pill after the sweep, want only the live one", n)
	}
	if _, ok := relayHealthByRun.Load(ids[runs-1]); !ok {
		t.Fatal("the sweep dropped a live run's health")
	}
	relayOnRunEnd(sandboxrelayd.RunRecord{TerminalRunID: ids[runs-1]})
}

// TestRelayGateDriftIsTheRegistryRow (P-040, milestone 2a): the comparison
// is the run's tool's registry row and the gate event its tool gate
// binding; a tool with no declared comparison is not compared.
func TestRelayGateDriftIsTheRegistryRow(t *testing.T) {
	g := relayGateDrift()
	if spec, ok := g.Spec("claude-code"); !ok || spec.PayloadCallID == "" {
		t.Fatalf("claude-code: %+v %v", spec, ok)
	}
	for _, tool := range []string{"codex", "no-such-tool"} {
		if _, ok := g.Spec(tool); ok {
			t.Errorf("%s: compared without a grounded row", tool)
		}
	}
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"claude-code", "PreToolUse"}, true},
		{[]string{"claude-code", "PostToolUse"}, false},
		{[]string{"claude-code", "UserPromptSubmit"}, false},
		{[]string{"claude-code"}, false},
	} {
		if got := g.IsGate(sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: tc.args}); got != tc.want {
			t.Errorf("%v: gate %v, want %v", tc.args, got, tc.want)
		}
	}
}
