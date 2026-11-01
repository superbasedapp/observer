//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// TestRelayBlocksCarryTheStderrBlockHeader pins DEC-1 on the sandbox relay's
// two block answers (a refused invocation, an unreachable relay): on every
// wired gate binding whose host shows stderr as the block reason, stderr is
// "Blocked by Observer guard:", a space and then the reason, exactly once;
// on every other gate binding the header never appears (Observer's
// diagnostic line stays there instead).
func TestRelayBlocksCarryTheStderrBlockHeader(t *testing.T) {
	const header = "Blocked by Observer guard:"
	checked, withHeader := 0, 0
	for _, c := range integration.Capabilities() {
		for _, b := range c.Hook.Bindings {
			if !b.Cap.IsGate() || !b.Wired {
				continue
			}
			tool, event := c.Tool, b.NativeEvent
			plan := provisionalHookFailurePlan(tool, event, "")
			if !plan.Gated {
				continue
			}
			reply, ok := hook.BuildFailClosedReply(plan.Dialect, "x")
			if !ok {
				continue
			}
			checked++
			if reply.StderrReason {
				withHeader++
			}

			ans := relayRefusalAnswer(tool, event, true, sandboxrelay.RefusedPath)
			checkRelayStderr(t, tool+":"+event+" refused", string(ans.Stderr), reply.StderrReason, header, relayRefusedReason)
			if strings.Contains(string(ans.Stdout), header) {
				t.Errorf("%s:%s refused: the header reached stdout %q", tool, event, ans.Stdout)
			}

			var out, errb bytes.Buffer
			relayFailure(tool, event, sandboxrelay.HookRequest{}, errors.New("dial: refused"), &out, &errb)
			checkRelayStderr(t, tool+":"+event+" unreachable", errb.String(), reply.StderrReason, header, relayUnreachableReason)
			if strings.Contains(out.String(), header) {
				t.Errorf("%s:%s unreachable: the header reached stdout %q", tool, event, out.String())
			}
		}
	}
	if checked == 0 || withHeader == 0 || withHeader == checked {
		t.Fatalf("checked %d gate bindings, %d with a stderr reason: want both kinds covered", checked, withHeader)
	}
}

func checkRelayStderr(t *testing.T, name, got string, stderrReason bool, header, reason string) {
	t.Helper()
	if stderrReason {
		if want := header + " " + reason + "\n"; got != want {
			t.Errorf("%s: stderr = %q, want %q", name, got, want)
		}
		return
	}
	if strings.Contains(got, header) {
		t.Errorf("%s: stderr = %q, want no block header on a host that does not show stderr as the reason", name, got)
	}
}
