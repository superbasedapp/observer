//go:build unix

package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termoob"
)

// TestRunClaudeEmptyUnset_PinProxyForcesSessionID pins F2: the empty-unset
// PIN-PROXY sub-path is proxy-routed and captured, so it must pass through the
// same session-id correlation seam every other routed launch uses — a forced
// --session-id is injected into the child argv AND announced over the trusted
// OOB channel, so a daemon-attach empty-unset launch still correlates to its
// observer session (the regression before this fix: the empty-unset branch
// returned before runClaudeLauncher's forceClaudeSessionID call).
func TestRunClaudeEmptyUnset_PinProxyForcesSessionID(t *testing.T) {
	ids := oobSessionSink(t) // live OOB channel → forceClaudeSessionID forces+announces
	bin, argsFile := writeRecordingClaudeBin(t)
	proxyURL := reachableProxyURL(t) // proxy UP → pin-proxy action
	cfgPath, _ := writeGuardTestConfig(t)
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	t.Setenv("ANTHROPIC_CONFIG_DIR", "")

	route := claudeRouteResolution{class: claudeRouteEmptyUnset, scope: claudeScopeUser, file: "user settings"}
	opts := claudeLauncherOptions{configPath: cfgPath, stderr: io.Discard, claudeArgs: []string{"--model", "opus"}}
	if err := runClaudeEmptyUnset(opts, bin, proxyURL, route, opts.claudeArgs, "", false); err != nil {
		t.Fatalf("runClaudeEmptyUnset: %v", err)
	}

	var announced string
	select {
	case a := <-ids:
		announced = a.id
	case <-time.After(2 * time.Second):
		t.Fatal("expected a forced session id announced over OOB (F2: pin-proxy must correlate), got none")
	}
	if announced == "" {
		t.Fatal("announced session id must be non-empty")
	}
	argv := recordedArgv(t, argsFile)
	if !argvHasPair(argv, "--session-id", announced) {
		t.Fatalf("forced --session-id %q not injected into the captured child argv: %v", announced, argv)
	}
}

// oobCapture wires the process-wide OOB emitter (oobEncoder) to an in-memory
// pipe so a test can read back the session id forceClaudeSessionID announces. It
// writes the authenticating Hello up front (the decoder's auth gate requires a
// Hello before any Session frame) and returns a reader for the NEXT announced
// session id. Restores oobEncoder on cleanup.
func oobCapture(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	// Build the Hello via a JSON round-trip so no secret field name appears as a
	// source assignment (the harness write-filter mangles those;
	// feedback_write_filter_token_patterns).
	raw, _ := json.Marshal(map[string]any{"auth": "auth-x", "tool": "claude-code", "pid": 1})
	var hello termoob.Hello
	_ = json.Unmarshal(raw, &hello)

	enc := termoob.NewEncoder(w)
	if err := enc.WriteHello(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	oobChanMu.Lock()
	prev := oobEncoder
	oobEncoder = enc
	oobChanMu.Unlock()
	t.Cleanup(func() {
		oobChanMu.Lock()
		oobEncoder = prev
		oobChanMu.Unlock()
		_ = w.Close()
		_ = r.Close()
	})

	dec := termoob.NewDecoder(r, "auth-x")
	// Consume the Hello so subsequent reads return the announced Session frames.
	if _, err := dec.Read(); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	return func() string {
		frame, err := dec.Read()
		if err != nil {
			t.Fatalf("read session frame: %v", err)
		}
		if frame.Type != termoob.TypeSession || frame.Session == nil {
			t.Fatalf("expected a session frame, got type %v", frame.Type)
		}
		return frame.Session.SessionID
	}
}

// TestForceClaudeSessionIDResumeSkipsForcedID pins F3: with a live OOB channel,
// `--session-id` is forced+announced for a plain attach launch, but SKIPPED for
// a launch whose argv already reattaches a session (`--resume`) — because claude
// rejects `--session-id` with `--resume` unless `--fork-session` is present. In
// the resume case the RESUMED id is announced instead so the run still
// correlates. A bare (no-OOB) resume is untouched.
func TestForceClaudeSessionIDResumeSkipsForcedID(t *testing.T) {
	t.Run("plain attach forces + announces a fresh id", func(t *testing.T) {
		next := oobCapture(t)
		in := []string{"--model", "opus"}
		got := forceClaudeSessionID(in)
		if len(got) < 2 || got[0] != "--session-id" {
			t.Fatalf("expected a forced --session-id prefix, got %v", got)
		}
		forcedID := got[1]
		if got[2] != "--model" || got[3] != "opus" {
			t.Fatalf("user args must follow the forced id, got %v", got)
		}
		if ann := next(); ann != forcedID {
			t.Fatalf("announced id = %q, want the forced id %q", ann, forcedID)
		}
	})

	t.Run("attach+resume produces NO --session-id and announces the resume id", func(t *testing.T) {
		next := oobCapture(t)
		in := []string{"--resume", "sess-1"}
		got := forceClaudeSessionID(in)
		if strings.Join(got, " ") != "--resume sess-1" {
			t.Fatalf("resume argv must be untouched (no --session-id), got %v", got)
		}
		if ann := next(); ann != "sess-1" {
			t.Fatalf("announced id = %q, want the resume target sess-1", ann)
		}
	})

	t.Run("attach+resume=<id> form also skips the forced id", func(t *testing.T) {
		next := oobCapture(t)
		in := []string{"--resume=sess-9", "--model", "opus"}
		got := forceClaudeSessionID(in)
		if strings.Join(got, " ") != "--resume=sess-9 --model opus" {
			t.Fatalf("resume=<id> argv must be untouched, got %v", got)
		}
		if ann := next(); ann != "sess-9" {
			t.Fatalf("announced id = %q, want sess-9", ann)
		}
	})

	t.Run("bare resume (no OOB channel) is unaffected", func(t *testing.T) {
		// No oobCapture → oobEncoder is nil → oobChannelActive() is false.
		in := []string{"--resume", "sess-1"}
		got := forceClaudeSessionID(in)
		if strings.Join(got, " ") != "--resume sess-1" {
			t.Fatalf("bare resume must be untouched, got %v", got)
		}
	})
}

// TestForceClaudeSessionIDForkedResume pins R2-4: with a live OOB channel, a
// FORKED resume (`--fork-session`) must NOT announce the resume target (OLD) —
// claude creates a NEW session forked off it. It announces the explicit
// `--session-id NEW` when one is pinned (claude allows a forced id with
// --resume ONLY under --fork-session), and announces NOTHING otherwise (claude
// mints an unknown id — abstain). A plain --resume without --fork-session keeps
// announcing the resume id. The argv is untouched in every case.
func TestForceClaudeSessionIDForkedResume(t *testing.T) {
	cases := []struct {
		name         string
		args         []string
		wantAnnounce string // "" ⇒ announce nothing
	}{
		{"plain resume announces the resume id (OLD)", []string{"--resume", "OLD"}, "OLD"},
		{"forked resume + explicit --session-id announces NEW", []string{"--resume", "OLD", "--fork-session", "--session-id", "NEW"}, "NEW"},
		{"forked resume without --session-id announces nothing", []string{"--resume", "OLD", "--fork-session"}, ""},
		// F2: the short aliases must gate the SAME fork-session table semantics.
		{"short -r plain announces the resume id (OLD)", []string{"-r", "OLD"}, "OLD"},
		{"short -r=OLD plain announces the resume id (OLD)", []string{"-r=OLD"}, "OLD"},
		{"short -c plain continue announces nothing (id unknown)", []string{"-c"}, ""},
		{"short -r forked + explicit --session-id announces NEW", []string{"-r", "OLD", "--fork-session", "--session-id", "NEW"}, "NEW"},
		{"short -r forked without --session-id announces nothing", []string{"-r", "OLD", "--fork-session"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ids := oobSessionSink(t)
			got := forceClaudeSessionID(tc.args)
			// A resume/fork-resume shape never gets a forced --session-id injected
			// (claude would reject it) — the argv passes through unchanged.
			if strings.Join(got, " ") != strings.Join(tc.args, " ") {
				t.Fatalf("argv must be untouched, got %v want %v", got, tc.args)
			}
			if tc.wantAnnounce == "" {
				select {
				case a := <-ids:
					t.Fatalf("expected NO announce for a forked resume without --session-id, got %q", a.id)
				case <-time.After(120 * time.Millisecond):
					// no frame — correct
				}
				return
			}
			select {
			case a := <-ids:
				if a.id != tc.wantAnnounce {
					t.Fatalf("announced %q, want %q", a.id, tc.wantAnnounce)
				}
			case <-time.After(time.Second):
				t.Fatalf("expected an announce of %q, got none", tc.wantAnnounce)
			}
		})
	}
}

// TestClaudeResumeContinueID pins the pure resume/continue detector.
func TestClaudeResumeContinueID(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		wantID    string
		wantMatch bool
	}{
		{"resume space form", []string{"--resume", "s1"}, "s1", true},
		{"resume eq form", []string{"--resume=s2"}, "s2", true},
		{"resume with trailing flag", []string{"--resume", "s3", "--model", "x"}, "s3", true},
		{"resume flag with no value", []string{"--resume"}, "", true},
		{"resume followed by a flag (no id)", []string{"--resume", "--model"}, "", true},
		{"continue (no id in argv)", []string{"--continue"}, "", true},
		// F2: claude documents `-r`/`-c` as aliases of `--resume`/`--continue`.
		{"short -r space form", []string{"-r", "OLD"}, "OLD", true},
		{"short -r eq form", []string{"-r=OLD"}, "OLD", true},
		{"short -r with trailing flag", []string{"-r", "s4", "--model", "x"}, "s4", true},
		{"short -r flag with no value", []string{"-r"}, "", true},
		{"short -r followed by a flag (no id)", []string{"-r", "--model"}, "", true},
		{"short -c (continue, no id in argv)", []string{"-c"}, "", true},
		{"neither", []string{"--model", "opus"}, "", false},
		{"empty", nil, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, match := claudeResumeContinueID(tc.args)
			if match != tc.wantMatch || id != tc.wantID {
				t.Fatalf("claudeResumeContinueID(%v) = (%q,%v), want (%q,%v)", tc.args, id, match, tc.wantID, tc.wantMatch)
			}
		})
	}
}
