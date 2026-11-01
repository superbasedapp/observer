//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
)

// answerRun is an enforce-mode launch in a repository with an unaccepted
// committed hook (an S-701 ask), whose terminal answers with line.
func answerRun(t *testing.T, line string, asked *string) (*launchGateRun, *repoTrustDeps, string) {
	t.Helper()
	st, _ := trustTestStore(t)
	root := writeTrustRepo(t, untrustedHookRepo)
	deps := &repoTrustDeps{
		mode: policy.ModeEnforce, store: st,
		ask: func(string) bool { t.Fatal("the y/N ask ran although an answer line was offered"); return false },
		answer: func(q string) string {
			*asked = q
			return line
		},
	}
	r := &launchGateRun{
		ctx: context.Background(), tool: "claude-code",
		launchDir:    func() (string, error) { return root, nil },
		repoTrustFor: func(*launchGateRun) *repoTrustDeps { return deps },
	}
	return r, deps, root
}

// TestTerminalAskOffersAccept (item 5): the terminal ask lists the items
// that carry a digest and offers "a". "a" records the accept the way the
// CLI and the dashboard do (who and when) and launches; the next launch is
// the accepted S-705 flag with no question. "y" is a pass for this one
// launch and records nothing. No answer refuses.
func TestTerminalAskOffersAccept(t *testing.T) {
	t.Run("accept", func(t *testing.T) {
		var asked string
		r, deps, root := answerRun(t, "a\n", &asked)
		if s := gateRepoTrust(r); s.outcomes() != launchGateAllow {
			t.Fatalf("answer a: %+v, want the launch to go on", s)
		}
		if !strings.Contains(asked, "untrusted hook_command: .claude/settings.json hooks.SessionStart") || !strings.Contains(asked, "a = accept") {
			t.Fatalf("question %q does not list the item and the accept answer", asked)
		}
		// The excerpt and the files the command runs, as the dashboard shows
		// them (SEC-TRUST4 item 2d).
		if !strings.Contains(asked, "\n      sh .github/boot.sh") || !strings.Contains(asked, "runs .github/boot.sh (their bytes are part of the digest)") {
			t.Fatalf("question %q does not show the excerpt and the files the command runs", asked)
		}
		recs, err := deps.store.ListSecTrustItems(context.Background(), guard.HashProjectRoot(root))
		if err != nil || len(recs) == 0 || !recs[0].Accepted() || !strings.HasPrefix(recs[0].AcceptedBy, "terminal:") {
			t.Fatalf("recorded %+v (%v), want an accept by the terminal", recs, err)
		}
		deps.answer = func(string) string { t.Fatal("asked again after the accept"); return "" }
		if s := gateRepoTrust(r); s.outcomes() != launchGateAllow|launchGateWarn || !strings.Contains(s.warn, "S-705") {
			t.Fatalf("next launch: %+v, want the accepted S-705 flag", s)
		}
	})
	t.Run("yes", func(t *testing.T) {
		var asked string
		r, deps, root := answerRun(t, "yes", &asked)
		if s := gateRepoTrust(r); s.outcomes() != launchGateAllow {
			t.Fatalf("answer yes: %+v", s)
		}
		recs, _ := deps.store.ListSecTrustItems(context.Background(), guard.HashProjectRoot(root))
		for _, rec := range recs {
			if rec.Accepted() {
				t.Fatalf("a one-launch yes recorded an accept: %+v", rec)
			}
		}
		deps.answer = func(string) string { return "" }
		if s := gateRepoTrust(r); s.refuse == nil {
			t.Fatalf("after a yes, the next launch with no answer: %+v, want a refusal", s)
		}
	})
	t.Run("no answer", func(t *testing.T) {
		var asked string
		r, _, _ := answerRun(t, "", &asked)
		if s := gateRepoTrust(r); s.refuse == nil || !strings.Contains(s.refuse.Error(), "S-701") {
			t.Fatalf("no answer: %+v, want the refusal", s)
		}
	})
	t.Run("no answer line falls back to y/N", func(t *testing.T) {
		var asked string
		r, deps, _ := answerRun(t, "", &asked)
		deps.answer = nil
		called := false
		deps.ask = func(q string) bool { called = strings.Contains(q, "Launch anyway?"); return true }
		if s := gateRepoTrust(r); s.outcomes() != launchGateAllow || !called {
			t.Fatalf("y/N ask: %+v (asked %v)", s, called)
		}
	})
}

// TestBoundedAnswer: the answer line comes back as typed; no answer within
// the wait is "" (a refusal), said on the terminal.
func TestBoundedAnswer(t *testing.T) {
	var out bytes.Buffer
	if got := boundedAnswer(strings.NewReader("a\n"), &out, 5*time.Second, "[y/a/N]")("q?"); got != "a" || !strings.Contains(out.String(), "q? [y/a/N]") {
		t.Fatalf("answer %q, out %q", got, out.String())
	}
	if askAnswerOf(" Accept ") != askAnswerAccept || askAnswerOf("Y") != askAnswerYes || askAnswerOf("x") != askAnswerNo {
		t.Fatal("answer table")
	}
	r, w := io.Pipe()
	t.Cleanup(func() {
		// The timed-out read stays pending for a later question; drop it so
		// no other test takes it over.
		askReader.mu.Lock()
		askReader.pending = nil
		askReader.mu.Unlock()
		_ = w.Close()
	})
	out.Reset()
	if got := boundedAnswer(r, &out, 20*time.Millisecond, "[y/a/N]")("q?"); got != "" || !strings.Contains(out.String(), "no answer within") {
		t.Fatalf("timed out answer %q, out %q", got, out.String())
	}
}

// TestTrustReviewLinesAreTerminalSafe: a file name or command a repository
// chose cannot send an escape sequence or a bidirectional override to the
// developer's terminal through the question.
func TestTrustReviewLinesAreTerminalSafe(t *testing.T) {
	got := trustReviewLines(sectrust.Reason{
		Code: "hook_command", Level: sectrust.LevelUntrusted, File: ".claude/settings\x1b[2J.json", Key: "hooks.x",
		Excerpt: "sh run\u202e.sh \x1b]0;owned\x07", Indicators: []string{"downloads with curl"},
	})
	if strings.ContainsAny(got, "\x1b\x07\u202e") {
		t.Fatalf("control characters reached the question: %q", got)
	}
	if !strings.Contains(got, "untrusted hook_command: .claude/settings?[2J.json hooks.x") || !strings.Contains(got, "it downloads with curl") {
		t.Fatalf("lines %q", got)
	}
}
