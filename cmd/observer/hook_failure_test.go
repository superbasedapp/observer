package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// failureHarness isolates one failure-semantics run: a fresh reply state, a
// captured reply target, an exit recorder behind the hookOSExit seam, all
// restored on cleanup so no other test sees a failure-owned stdout.
type failureHarness struct {
	stdout bytes.Buffer
	stderr bytes.Buffer
	mu     sync.Mutex
	exits  []int
}

func (h *failureHarness) exit(code int) {
	h.mu.Lock()
	h.exits = append(h.exits, code)
	h.mu.Unlock()
}

func (h *failureHarness) exitCodes() []int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]int(nil), h.exits...)
}

func newFailureHarness(t *testing.T, plan hookFailurePlan) *failureHarness {
	t.Helper()
	h := &failureHarness{}
	resetHookInvocationState()
	hookReplyMu.Lock()
	hookPlanPtr.Store(&plan)
	hookReplyOut = &h.stdout
	hookReplyMu.Unlock()
	prevExit := hookOSExit
	hookOSExit = h.exit
	t.Cleanup(func() {
		hookOSExit = prevExit
		hookReplyMu.Lock()
		hookReplyOut = nil
		hookReplyMu.Unlock()
		resetHookInvocationState()
	})
	return h
}

// writePosture writes guard-posture.json beside configPath, stamped now
// when p carries no WrittenAt (a fresh posture, T-050).
func writePosture(t *testing.T, configPath string, p guardposture.Posture) {
	t.Helper()
	if p.WrittenAt.IsZero() {
		p.WrittenAt = time.Now()
	}
	key, err := guardposture.LoadOrCreateKey(guardposture.KeyPath(configPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guardposture.Write(guardposture.PosturePath(configPath), p, key); err != nil {
		t.Fatal(err)
	}
}

var enforcedPosture = guardposture.Posture{
	Enforced: true, Source: guardposture.SourceOrg, Generation: "7",
	GateCaps: []string{string(integration.HookCapToolGate), string(integration.HookCapPromptGate)},
}

// claudePreToolDeny is the exact Claude Code PreToolUse block for reason.
func claudePreToolDeny(reason string) string {
	return fmt.Sprintf(`{"decision":"block","reason":%q,"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":%q}}`+"\n", reason, reason)
}

// TestHookFailureSemantics is the section 5.7 matrix: capability x posture
// x failure kind x dialect -> stdout bytes, exit code, spool line. A gate
// capability under an enforced posture blocks in its dialect's exact shape
// and spools one record; every other cell is today's fail-open behaviour.
func TestHookFailureSemantics(t *testing.T) {
	type dialectRow struct {
		name, tool, event string
		cap               integration.HookCap
		// block returns the exact fail-closed stdout for reason; nil = the
		// dialect blocks by exit code alone.
		block        func(reason string) string
		blockCode    int
		stderrReason bool
	}
	dialects := []dialectRow{
		{name: "claude PreToolUse JSON", tool: "claude-code", event: "pre-tool", cap: integration.HookCapToolGate, block: claudePreToolDeny},
		{name: "claude UserPromptSubmit exit 2", tool: "claude-code", event: "user-prompt-submit", cap: integration.HookCapPromptGate, blockCode: 2, stderrReason: true},
		{
			name: "cursor beforeShellExecution", tool: "cursor", event: "beforeShellExecution", cap: integration.HookCapToolGate,
			block: func(string) string { return `{"permission":"deny","continue":true}` + "\n" },
		},
		{
			name: "codex prompt", tool: "codex", event: "UserPromptSubmit", cap: integration.HookCapPromptGate, blockCode: 2, stderrReason: true,
			block: func(r string) string {
				return fmt.Sprintf(`{"decision":"block","reason":%q,"hookSpecificOutput":{"hookEventName":"UserPromptSubmit"}}`+"\n", r)
			},
		},
		{name: "qoder exit-code-only", tool: "qoder", event: "UserPromptSubmit", cap: integration.HookCapPromptGate, blockCode: 2, stderrReason: true},
		{
			name: "gemini BeforeAgent", tool: "gemini-cli", event: "BeforeAgent", cap: integration.HookCapPromptGate, blockCode: 2, stderrReason: true,
			block: func(r string) string {
				return fmt.Sprintf(`{"decision":"deny","reason":%q,"systemMessage":%q}`+"\n", r, r)
			},
		},
		{name: "claude SessionStart lifecycle", tool: "claude-code", event: "session-start", cap: integration.HookCapSessionLifecycle},
		// Hook-parity Lane D: the plugin dialects (JSON only, exit 0; the
		// plugin maps the deny onto its host's block).
		{name: "plugin tool gate (opencode)", tool: "opencode", event: "tool.execute.before", cap: integration.HookCapToolGate, block: pluginDeny},
		{name: "plugin tool gate (pi)", tool: "pi", event: "tool_call", cap: integration.HookCapToolGate, block: pluginDeny},
		{name: "plugin tool gate (hermes)", tool: "hermes", event: "pre_tool_call", cap: integration.HookCapToolGate, block: pluginDeny},
		{
			name: "plugin prompt gate (opencode chat.message)", tool: "opencode", event: "chat.message", cap: integration.HookCapPromptGate,
			block: func(r string) string { return fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", r) },
		},
	}
	postures := []struct {
		name    string
		setup   func(t *testing.T, configPath string)
		enforce bool
	}{
		{"enforced", func(t *testing.T, cp string) {
			writeFileT(t, cp, "")
			writePosture(t, cp, enforcedPosture)
		}, true},
		{"not enforced", func(t *testing.T, cp string) {
			writeFileT(t, cp, "")
			writePosture(t, cp, guardposture.Posture{Enforced: false, Source: guardposture.SourceLocal})
		}, false},
		{"unknown", func(t *testing.T, cp string) {
			// No posture file and a config that does not load.
			writeFileT(t, cp, "this is = = not toml [")
		}, false},
	}
	kinds := []struct {
		name, kind string
		run        func(h *failureHarness, body []byte) bool
	}{
		{"timeout", guardposture.KindTimeout, func(h *failureHarness, _ []byte) bool {
			hookWatchdogFire(time.Millisecond, h.exit, &h.stderr)
			return true
		}},
		{"panic", guardposture.KindCrash, func(h *failureHarness, _ []byte) bool {
			func() {
				defer recoverHookPanic("t:e", hookStdout, &h.stderr, h.exit)
				panic("simulated receiver panic")
			}()
			return true
		}},
		{"config error", guardposture.KindConfig, func(_ *failureHarness, b []byte) bool { return hookFailClosed(guardposture.KindConfig, b) }},
		{"nil guard", guardposture.KindGuardInit, func(_ *failureHarness, b []byte) bool { return hookFailClosed(guardposture.KindGuardInit, b) }},
		{"unparseable payload", guardposture.KindUnparseable, func(_ *failureHarness, b []byte) bool {
			return hookFailClosed(guardposture.KindUnparseable, b)
		}},
	}
	var approve bytes.Buffer
	hook.HandleApprove("t:e", strings.NewReader(""), &approve, io.Discard)

	for _, d := range dialects {
		for _, p := range postures {
			for _, k := range kinds {
				t.Run(d.name+"/"+p.name+"/"+k.name, func(t *testing.T) {
					cp := filepath.Join(t.TempDir(), "config.toml")
					p.setup(t, cp)
					plan := resolveHookFailurePlan(d.tool, d.event, cp)
					if plan.Cap != d.cap {
						t.Fatalf("plan cap = %q, want %q", plan.Cap, d.cap)
					}
					failClosed := p.enforce && d.cap.IsGate()
					if plan.FailClosed != failClosed {
						t.Fatalf("plan.FailClosed = %v, want %v", plan.FailClosed, failClosed)
					}
					h := newFailureHarness(t, plan)
					body := []byte(`{"session_id":"sess-1"}`)
					if k.kind == guardposture.KindUnparseable {
						body = []byte("not json")
					}
					handled := k.run(h, body)
					exits := h.exitCodes()

					spool := guardposture.SpoolPath(cp)
					batch, err := guardposture.Drain(spool, 0)
					if err != nil {
						t.Fatal(err)
					}

					if !failClosed {
						// Today's behaviour, byte for byte.
						switch k.kind {
						case guardposture.KindTimeout:
							if h.stdout.Len() != 0 || len(exits) != 1 || exits[0] != 0 {
								t.Errorf("fail-open timeout: stdout %q exits %v, want empty / [0]", h.stdout.String(), exits)
							}
						case guardposture.KindCrash:
							if h.stdout.String() != approve.String() || len(exits) != 1 || exits[0] != 0 {
								t.Errorf("fail-open panic: stdout %q exits %v, want %q / [0]", h.stdout.String(), exits, approve.String())
							}
						default:
							if handled || h.stdout.Len() != 0 || len(exits) != 0 {
								t.Errorf("fail-open %s: handled=%v stdout %q exits %v, want untouched", k.kind, handled, h.stdout.String(), exits)
							}
						}
						// T-049: a wired gate hook that fails open is recorded
						// too, labelled fail_open; lifecycle hooks never are.
						if !d.cap.IsGate() {
							if batch != nil {
								t.Errorf("fail-open lifecycle cell spooled %+v", batch.Records)
							}
							return
						}
						if batch == nil || len(batch.Records) != 1 {
							t.Fatalf("fail-open gate spool = %+v, want exactly one record", batch)
						}
						if r := batch.Records[0]; r.Outcome != guardposture.OutcomeFailOpen || !r.FailedOpen() ||
							r.Kind != k.kind || r.Tool != d.tool || r.Cap != string(d.cap) {
							t.Errorf("fail-open spool record = %+v", r)
						}
						return
					}

					reason := hook.FailClosedErrorReason
					if k.kind == guardposture.KindTimeout {
						reason = hook.FailClosedTimeoutReason
					}
					want := ""
					if d.block != nil {
						want = d.block(reason)
					}
					if h.stdout.String() != want {
						t.Errorf("stdout = %q, want %q", h.stdout.String(), want)
					}
					wantExits := []int{d.blockCode}
					if k.kind != guardposture.KindTimeout && k.kind != guardposture.KindCrash && d.blockCode == 0 {
						wantExits = nil // a JSON-only block returns; Run exits 0
					}
					if fmt.Sprint(exits) != fmt.Sprint(wantExits) {
						t.Errorf("exits = %v, want %v", exits, wantExits)
					}
					if !handled {
						t.Error("the fail-closed path reported unhandled")
					}
					if d.stderrReason && (k.kind == guardposture.KindTimeout || k.kind == guardposture.KindCrash) &&
						!strings.Contains(h.stderr.String(), reason) {
						t.Errorf("stderr-reason dialect: stderr %q lacks the reason", h.stderr.String())
					}
					// T-048: the host shows a stderr-reason block's stderr as
					// the reason, so a timeout writes the reason and nothing
					// else there, after the DEC-1 header on one line.
					if d.stderrReason && k.kind == guardposture.KindTimeout && h.stderr.String() != "Blocked by Observer guard: "+reason+"\n" {
						t.Errorf("stderr-reason dialect timeout: stderr %q, want exactly the header and the reason on one line", h.stderr.String())
					}
					if !d.stderrReason && d.blockCode != 0 {
						t.Errorf("%s: blocks by exit %d without a stderr reason (T-048)", d.name, d.blockCode)
					}
					if batch == nil || len(batch.Records) != 1 {
						t.Fatalf("spool = %+v, want exactly one record", batch)
					}
					r := batch.Records[0]
					if r.Tool != d.tool || r.Event != d.event || r.Cap != string(d.cap) || r.Kind != k.kind || r.At.IsZero() ||
						r.Outcome != guardposture.OutcomeFailClosed {
						t.Errorf("spool record = %+v", r)
					}
					wantSession := "sess-1"
					if k.kind == guardposture.KindTimeout || k.kind == guardposture.KindCrash || k.kind == guardposture.KindUnparseable {
						wantSession = ""
					}
					if r.SessionID != wantSession {
						t.Errorf("spool session = %q, want %q", r.SessionID, wantSession)
					}
				})
			}
		}
	}
}

// preseedMigratedDB materializes a migrated schema at path from the test DB
// template (dbtemplate), so a receiver or launcher under test that opens
// path finds a current schema instead of replaying the whole migration
// chain (about 9s per open under -race). The code under test still opens
// the file itself through its own path; only the migration replay is
// skipped.
func preseedMigratedDB(t *testing.T, path string) {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("preseed %s: %v", path, err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close preseeded %s: %v", path, err)
	}
}

func writeFileT(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestHookReplyRaceExactlyOneReply: the receiver and the watchdog reply
// concurrently; stdout carries exactly one reply (the receiver's or the
// block, never both, never interleaved) and every exit carries one code.
func TestHookReplyRaceExactlyOneReply(t *testing.T) {
	cp := filepath.Join(t.TempDir(), "config.toml")
	writeFileT(t, cp, "")
	writePosture(t, cp, enforcedPosture)
	for _, tc := range []struct {
		name, tool, event string
		receiverCode      int
	}{
		{"json dialect", "claude-code", "pre-tool", 0},
		{"exit-code dialect", "claude-code", "user-prompt-submit", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := resolveHookFailurePlan(tc.tool, tc.event, cp)
			if !plan.FailClosed {
				t.Fatal("the race needs a fail-closed plan")
			}
			blocked := 0
			for i := 0; i < 200; i++ {
				h := newFailureHarness(t, plan)
				var wg sync.WaitGroup
				wg.Add(2)
				start := make(chan struct{})
				go func() {
					defer wg.Done()
					<-start
					if tc.receiverCode == 0 {
						// A JSON dialect's receiver: the reply, then the mark.
						_ = json.NewEncoder(hookStdout).Encode(hook.Decision{Decision: "approve"})
						markHookReplied()
						return
					}
					// An exit-code dialect's decided block: nothing on
					// stdout, the decision recorded in one step, then the
					// exit.
					markHookDecided(tc.receiverCode)
					hookExit(tc.receiverCode)
				}()
				go func() {
					defer wg.Done()
					<-start
					hookWatchdogFire(time.Millisecond, h.exit, io.Discard)
				}()
				close(start)
				wg.Wait()
				out := h.stdout.String()
				dec := json.NewDecoder(strings.NewReader(out))
				objects := 0
				for {
					var v map[string]any
					if err := dec.Decode(&v); err != nil {
						if !errors.Is(err, io.EOF) {
							t.Fatalf("iteration %d: stdout is not a clean JSON stream: %q (%v)", i, out, err)
						}
						break
					}
					objects++
				}
				// The exit-code dialect's block writes nothing to stdout.
				if objects > 1 || (objects == 0 && tc.receiverCode == 0) {
					t.Fatalf("iteration %d: %d replies on stdout: %q", i, objects, out)
				}
				if objects == 0 || strings.Contains(out, `"deny"`) {
					blocked++
				}
				for _, c := range h.exitCodes() {
					if c != tc.receiverCode && c != 2 && c != 0 {
						t.Fatalf("iteration %d: unexpected exit %d", i, c)
					}
				}
				if tc.receiverCode != 0 {
					for _, c := range h.exitCodes() {
						if c != 2 {
							t.Fatalf("iteration %d: a decided exit-2 verdict was exited %d", i, c)
						}
					}
				}
				resetHookInvocationState()
			}
			t.Logf("%d/200 iterations the watchdog won", blocked)
		})
	}
}

// TestResolveHookFailurePlan pins the plan resolution rules.
func TestResolveHookFailurePlan(t *testing.T) {
	// Hermetic: the [guard] config fallback also reads the user guard
	// policy (per-rule enforce) under HOME, so a developer HOME holding an
	// enforcing policy must not decide (or rescue) these rows.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := t.TempDir()
	cp := filepath.Join(dir, "config.toml")
	writeFileT(t, cp, "")
	writePosture(t, cp, enforcedPosture)
	for _, tc := range []struct {
		tool, event string
		failClosed  bool
		cap         integration.HookCap
	}{
		{"claude-code", "pre-tool", true, integration.HookCapToolGate},              // argv spelling
		{"claude-code", "PreToolUse", true, integration.HookCapToolGate},            // native spelling
		{"claude-code", "post-tool", false, integration.HookCapToolObserve},         // not a gate
		{"codex", "PreToolUse", true, integration.HookCapToolGate},                  // wired tool gate (hook-parity A1)
		{"codex", "PermissionRequest", false, integration.HookCapPermissionObserve}, // not a gate
		{"antigravity-cli", "PreInvocation", true, integration.HookCapPromptGate},   // the abort blocks (guard-enforcement fix 2026-10-15)
		{"kimi-code", "PreToolUse", true, integration.HookCapToolGate},              // wired tool gate (T-378)
		{"kiro-cli", "preToolUse", true, integration.HookCapToolGate},               // wired tool gate (gfiD)
		{"kiro-crew", "PreToolUse", false, integration.HookCapToolGate},             // vendor-only binding
		{"no-such-tool", "PreToolUse", false, ""},
	} {
		plan := resolveHookFailurePlan(tc.tool, tc.event, cp)
		if plan.FailClosed != tc.failClosed || plan.Cap != tc.cap {
			t.Errorf("%s/%s: plan = %+v, want failClosed=%v cap=%q", tc.tool, tc.event, plan, tc.failClosed, tc.cap)
		}
		if plan.SpoolPath != filepath.Join(dir, guardposture.SpoolFilename) {
			t.Errorf("%s/%s: spool %q", tc.tool, tc.event, plan.SpoolPath)
		}
	}

	// No posture, default observe config: the prompt gate is still closed
	// by independent prompt enforcement (Sol A2-01), the tool gate is not.
	dir3 := t.TempDir()
	cp3 := filepath.Join(dir3, "config.toml")
	writeFileT(t, cp3, "[guard]\nenabled = true\nmode = \"observe\"\n")
	if !resolveHookFailurePlan("claude-code", "user-prompt-submit", cp3).FailClosed {
		t.Error("config fallback: independent prompt enforcement must close the prompt gate in observe mode")
	}
	if resolveHookFailurePlan("claude-code", "pre-tool", cp3).FailClosed {
		t.Error("config fallback: independent prompt enforcement must not close the tool gate")
	}

	// No posture: the config fallback ([guard] enforce) decides.
	dir2 := t.TempDir()
	cp2 := filepath.Join(dir2, "config.toml")
	writeFileT(t, cp2, "[guard]\nenabled = true\nmode = \"enforce\"\n")
	if !resolveHookFailurePlan("claude-code", "pre-tool", cp2).FailClosed {
		t.Error("config fallback: [guard] mode=enforce must fail closed")
	}
	writeFileT(t, cp2, "[guard]\nenabled = true\nmode = \"observe\"\n")
	if resolveHookFailurePlan("claude-code", "pre-tool", cp2).FailClosed {
		t.Error("config fallback: mode=observe must not fail closed")
	}
}

// TestEveryWiredGateBindingHasAFailurePlan: every gate binding Observer
// wires resolves from its registered argv and either has a fail-closed
// reply or is a seam that cannot block at all (named here with the reason).
func TestEveryWiredGateBindingHasAFailurePlan(t *testing.T) {
	// agy PreInvocation blocks with the {"injectSteps":[{}]} abort since the
	// guard-enforcement fix (2026-10-15); Kiro CLI userPromptSubmit cannot.
	cannotBlock := map[string]string{
		"kiro-cli": "warn-only seam (Kiro CLI userPromptSubmit cannot block, gfiD 2026-10-15)",
	}
	for _, c := range integration.Capabilities() {
		for _, b := range c.Hook.Bindings {
			if !b.Wired || !b.Cap.IsGate() || b.Dialect == "" {
				continue
			}
			if b.ServedElsewhere() != "" {
				continue
			}
			argv := b.NativeEvent
			if spell, ok := hookArgvSpelling[c.Hook.Mechanism]; ok {
				argv = spell(b.NativeEvent)
			}
			got, ok := resolveHookInvocationBinding(c.Tool, argv)
			// The invocation resolves to the event's PRIMARY binding (a
			// PreToolUse that also rewrites carries two gate bindings).
			if !ok || got.NativeEvent != b.NativeEvent || !got.Cap.IsGate() {
				t.Errorf("%s %s (argv %q) does not resolve to a gate binding of its event", c.Tool, b.NativeEvent, argv)
			}
			if hook.CanFailClosed(b.Dialect) {
				continue
			}
			if _, ok := cannotBlock[b.Dialect]; !ok {
				t.Errorf("%s %s: wired gate dialect %q has no fail-closed reply", c.Tool, b.NativeEvent, b.Dialect)
			}
		}
	}
}

func TestHookGateBudget(t *testing.T) {
	gate := hookFailurePlan{Cap: integration.HookCapToolGate}
	for _, tc := range []struct {
		budget, host, want time.Duration
		plan               hookFailurePlan
	}{
		{30 * time.Second, 60 * time.Second, 30 * time.Second, gate},
		{30 * time.Second, 5 * time.Second, 3 * time.Second, gate},
		{30 * time.Second, 4 * time.Second, 2 * time.Second, gate},
		{30 * time.Second, 10 * time.Second, 8 * time.Second, gate},
		{30 * time.Second, 0, 30 * time.Second, gate},
		{30 * time.Second, 5 * time.Second, 30 * time.Second, hookFailurePlan{Cap: integration.HookCapSessionLifecycle}},
		{0, 5 * time.Second, 0, gate},
	} {
		tc.plan.HostTimeout = tc.host
		if got := hookGateBudget(tc.budget, tc.plan); got != tc.want {
			t.Errorf("budget %v host %v cap %s = %v, want %v", tc.budget, tc.host, tc.plan.Cap, got, tc.want)
		}
	}
}

// TestHookFailureReceiverWiring drives the real receivers into each
// receiver-side failure kind under an enforced posture.
func TestHookFailureReceiverWiring(t *testing.T) {
	enforcedDir := func(t *testing.T, cfgBody string) string {
		t.Helper()
		cp := filepath.Join(t.TempDir(), "config.toml")
		writeFileT(t, cp, cfgBody)
		writePosture(t, cp, enforcedPosture)
		return cp
	}
	guardOn := "[guard]\nenabled = true\nmode = \"enforce\"\n"
	pre := `{"session_id":"s9","cwd":"/r","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`

	t.Run("claude pre-tool config error", func(t *testing.T) {
		cp := enforcedDir(t, "this is = = not toml [")
		h := newFailureHarness(t, resolveHookFailurePlan("claude-code", "pre-tool", cp))
		handleClaudeCodePreTool(strings.NewReader(pre), hookStdout, io.Discard, "claude-code:pre-tool", cp)
		if h.stdout.String() != claudePreToolDeny(hook.FailClosedErrorReason) {
			t.Errorf("stdout = %q", h.stdout.String())
		}
	})
	t.Run("claude pre-tool unparseable", func(t *testing.T) {
		cp := enforcedDir(t, guardOn)
		h := newFailureHarness(t, resolveHookFailurePlan("claude-code", "pre-tool", cp))
		handleClaudeCodePreTool(strings.NewReader("not json"), hookStdout, io.Discard, "claude-code:pre-tool", cp)
		if h.stdout.String() != claudePreToolDeny(hook.FailClosedErrorReason) {
			t.Errorf("stdout = %q", h.stdout.String())
		}
	})
	t.Run("claude pre-tool nil guard", func(t *testing.T) {
		cp := enforcedDir(t, guardOn)
		prev := hookGuardNew
		hookGuardNew = func(guard.Options) (*guard.Guard, error) { return nil, errors.New("injected") }
		t.Cleanup(func() { hookGuardNew = prev })
		h := newFailureHarness(t, resolveHookFailurePlan("claude-code", "pre-tool", cp))
		handleClaudeCodePreTool(strings.NewReader(pre), hookStdout, io.Discard, "claude-code:pre-tool", cp)
		if h.stdout.String() != claudePreToolDeny(hook.FailClosedErrorReason) {
			t.Errorf("stdout = %q", h.stdout.String())
		}
		b, _ := guardposture.Drain(guardposture.SpoolPath(cp), 0)
		if b == nil || len(b.Records) != 1 || b.Records[0].Kind != guardposture.KindGuardInit || b.Records[0].SessionID != "s9" {
			t.Errorf("spool = %+v", b)
		}
	})
	t.Run("claude pre-tool strict implied", func(t *testing.T) {
		cp := enforcedDir(t, guardOn)
		var seen config.GuardConfig
		prev := hookGuardNew
		hookGuardNew = func(o guard.Options) (*guard.Guard, error) { seen = o.Config; return nil, errors.New("stop") }
		t.Cleanup(func() { hookGuardNew = prev })
		newFailureHarness(t, resolveHookFailurePlan("claude-code", "pre-tool", cp))
		handleClaudeCodePreTool(strings.NewReader(pre), hookStdout, io.Discard, "claude-code:pre-tool", cp)
		if !seen.Strict {
			t.Error("[guard].strict was not implied for a fail-closed gate hook")
		}
	})
	t.Run("qoder prompt config error exits 2", func(t *testing.T) {
		cp := enforcedDir(t, "this is = = not toml [")
		h := newFailureHarness(t, resolveHookFailurePlan("qoder", "UserPromptSubmit", cp))
		withStdinT(t, `{"prompt":"hi","session_id":"q1"}`, func() {
			handlePromptSubmitOnlyHook(models.ToolQoder, "qoder", hook.PromptDialectQoder, "UserPromptSubmit", "UserPromptSubmit", cp)
		})
		if h.stdout.Len() != 0 || fmt.Sprint(h.exitCodes()) != "[2]" {
			t.Errorf("stdout %q exits %v, want empty / [2]", h.stdout.String(), h.exitCodes())
		}
	})
	t.Run("not enforced keeps the fail-open config path", func(t *testing.T) {
		cp := filepath.Join(t.TempDir(), "config.toml")
		writeFileT(t, cp, "this is = = not toml [")
		h := newFailureHarness(t, resolveHookFailurePlan("claude-code", "pre-tool", cp))
		handleClaudeCodePreTool(strings.NewReader(pre), hookStdout, io.Discard, "claude-code:pre-tool", cp)
		if !strings.Contains(h.stdout.String(), `"approve"`) || strings.Contains(h.stdout.String(), "deny") {
			t.Errorf("stdout = %q, want the unchanged approve", h.stdout.String())
		}
	})
}

// withStdinT runs fn with os.Stdin fed body.
func withStdinT(t *testing.T, body string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = w.Write([]byte(body))
		_ = w.Close()
	}()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old; _ = r.Close() }()
	fn()
}

// TestDrainHookFailuresPersistsGuardError: a spooled failure lands in
// guard_events as an enforced guard_error deny with the kind in
// degraded_from, and the spool is consumed.
func TestDrainHookFailuresPersistsGuardError(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(dir, "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	spool := filepath.Join(dir, guardposture.SpoolFilename)
	for _, r := range []guardposture.Record{
		{Tool: "claude-code", Event: "pre-tool", Cap: "tool_gate", SessionID: "s1", Kind: guardposture.KindTimeout},
		{Tool: "qoder", Event: "UserPromptSubmit", Cap: "prompt_gate", Kind: guardposture.KindCrash},
	} {
		if err := guardposture.Append(spool, r); err != nil {
			t.Fatal(err)
		}
	}
	if n := drainHookFailures(ctx, spool, st, newLogger("error")); n != 2 {
		t.Fatalf("drained %d, want 2", n)
	}
	rows, err := st.GuardEventsAfter(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("guard_events = %d, want 2", len(rows))
	}
	for _, r := range rows {
		if r.RuleID != guard.GuardErrorRuleID || r.Decision != "deny" || !r.Enforced || r.Category != "guard" {
			t.Errorf("row = %+v", r)
		}
	}
	if rows[0].DegradedFrom != guardposture.KindTimeout || rows[0].Tool != "claude-code" || rows[0].SessionID != "s1" || rows[0].EventKind != "tool_call" {
		t.Errorf("first row = %+v", rows[0])
	}
	if rows[1].DegradedFrom != guardposture.KindCrash || rows[1].EventKind != "user_prompt" {
		t.Errorf("second row = %+v", rows[1])
	}
	if b, err := guardposture.Drain(spool, 0); err != nil || b != nil {
		t.Errorf("spool not consumed: %+v, %v", b, err)
	}
}

// TestComputeGuardPosture: enforced follows mode=enforce (or a per-rule
// enforced rule); the prompt gate joins only when the prompt hook lane
// evaluates; a nil guard is never enforced.
func TestComputeGuardPosture(t *testing.T) {
	now := time.Unix(1000, 0)
	build := func(t *testing.T, g config.GuardConfig) *guard.Guard {
		t.Helper()
		gd, err := guard.New(guard.Options{Config: g, Home: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		return gd
	}
	base := config.Default().Guard
	base.Enabled = true

	off := computeGuardPosture(base, nil, now)
	if off.Enforced || off.Source != guardposture.SourceLocal {
		t.Errorf("nil guard posture = %+v", off)
	}

	// Sol A2-01: the default prompt lane enforces independently of the
	// observe-mode global guard, so the prompt gate is closed while the
	// tool gate stays open.
	observe := base
	observe.Mode = "observe"
	if p := computeGuardPosture(observe, build(t, observe), now); !p.Enforced || fmt.Sprint(p.GateCaps) != "[prompt_gate]" {
		t.Errorf("observe posture = %+v, want only the prompt gate enforced", p)
	}
	observe.Prompt.EnforceIndependent = false
	if p := computeGuardPosture(observe, build(t, observe), now); p.Enforced || len(p.GateCaps) != 0 {
		t.Errorf("observe without independent prompt enforcement = %+v, want not enforced", p)
	}

	enforce := base
	enforce.Mode = "enforce"
	enforce.Prompt.Enabled, enforce.Prompt.HookLane, enforce.Prompt.Mode = true, true, "ask-once"
	p := computeGuardPosture(enforce, build(t, enforce), now)
	if !p.Enforced || fmt.Sprint(p.GateCaps) != "[tool_gate prompt_gate]" {
		t.Errorf("enforce posture = %+v", p)
	}
	enforce.Prompt.HookLane = false
	if p := computeGuardPosture(enforce, build(t, enforce), now); fmt.Sprint(p.GateCaps) != "[tool_gate]" {
		t.Errorf("hook lane off: gate caps %v, want [tool_gate]", p.GateCaps)
	}
}

// TestGuardPostureWriterSkipsUnchanged: the one writer rewrites only on a
// content change.
func TestGuardPostureWriterSkipsUnchanged(t *testing.T) {
	cp := filepath.Join(t.TempDir(), "config.toml")
	w := &guardPostureWriter{}
	p := guardposture.Posture{Enforced: true, Source: "local", GateCaps: []string{"tool_gate"}, WrittenAt: time.Unix(1, 0)}
	if changed, err := w.publish(cp, p); err != nil || !changed {
		t.Fatalf("first publish = %v, %v", changed, err)
	}
	p.WrittenAt = time.Unix(2, 0)
	if changed, _ := w.publish(cp, p); changed {
		t.Error("a WrittenAt-only change rewrote the posture")
	}
	p.Enforced = false
	if changed, _ := w.publish(cp, p); !changed {
		t.Error("an enforcement change was not published")
	}
	got, err := guardposture.Read(guardposture.PosturePath(cp))
	if err != nil || got == nil || got.Enforced {
		t.Errorf("posture on disk = %+v, %v", got, err)
	}
}

// TestPostureForgeryCannotOpenAGate pins Sol A2-02 as corrected by the
// orchestrator (D-040/D-041): only a verifying posture is trusted; any
// other posture is IGNORED and the hook computes the answer from the
// config. So a forged or unsigned "not enforced" posture cannot open a
// gate the config enforces, and an unsigned posture from a daemon still
// running the pre-authentication binary through an upgrade, or a tamper,
// never blocks a node whose config does not enforce.
func TestPostureForgeryCannotOpenAGate(t *testing.T) {
	// The hook reads the org bundle under the home; the process temp home's
	// .observer is a file (FU-20), which reads as an unverifiable org layer.
	pinToolHomes(t)
	const (
		guardOff     = "[guard]\nenabled = false\n"
		guardObserve = "[guard]\nenabled = true\nmode = \"observe\"\n"
		guardEnforce = "[guard]\nenabled = true\nmode = \"enforce\"\n"
	)
	// oldDaemon is what a pre-authentication daemon writes: a posture with
	// no MAC and no key file.
	oldDaemon := func(p guardposture.Posture) func(*testing.T, string) {
		return func(t *testing.T, cp string) {
			t.Helper()
			p.Schema = guardposture.Schema
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			writeFileT(t, guardposture.PosturePath(cp), string(data))
		}
	}
	// forgedOpen writes a signed-LOOKING "not enforced" posture: a MAC
	// field present but not made with the daemon's key, over a real key.
	forgedOpen := func(t *testing.T, cp string) {
		t.Helper()
		writePosture(t, cp, enforcedPosture)
		forged := guardposture.Posture{Schema: guardposture.Schema, Enforced: false, Source: "local", MAC: strings.Repeat("ab", 32)}
		data, err := json.Marshal(forged)
		if err != nil {
			t.Fatal(err)
		}
		writeFileT(t, guardposture.PosturePath(cp), string(data))
	}
	for _, tc := range []struct {
		name, config string
		setup        func(t *testing.T, cp string)
		want         bool
	}{
		{"daemon-signed enforced", guardObserve, func(t *testing.T, cp string) { writePosture(t, cp, enforcedPosture) }, true},
		{"daemon-signed not enforced", guardEnforce, func(t *testing.T, cp string) {
			writePosture(t, cp, guardposture.Posture{Source: "local"})
		}, false},
		{"old-daemon unsigned posture, guard off: allow", guardOff, oldDaemon(enforcedPosture), false},
		{"old-daemon unsigned posture, tool enforcement on: closed", guardEnforce, oldDaemon(guardposture.Posture{Source: "local"}), true},
		{"forged signed-looking open posture, config enforces: closed", guardEnforce, forgedOpen, true},
		{"forged signed-looking open posture, config observes: open", guardObserve, forgedOpen, false},
		{"tamper on a guard-off node: allow", guardOff, forgedOpen, false},
		{"posture deleted, key kept, config enforces: closed", guardEnforce, func(t *testing.T, cp string) {
			writePosture(t, cp, guardposture.Posture{Source: "local"})
			if err := os.Remove(guardposture.PosturePath(cp)); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"key deleted, config observes: open", guardObserve, func(t *testing.T, cp string) {
			writePosture(t, cp, enforcedPosture)
			if err := os.Remove(guardposture.KeyPath(cp)); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"no daemon ever published: config fallback", guardObserve, func(*testing.T, string) {}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := filepath.Join(t.TempDir(), "config.toml")
			writeFileT(t, cp, tc.config)
			tc.setup(t, cp)
			if got := resolveHookFailurePlan("claude-code", "pre-tool", cp).FailClosed; got != tc.want {
				t.Errorf("tool gate FailClosed = %v, want %v", got, tc.want)
			}
		})
	}
	// A guard-off node never blocks on a failed prompt hook either, whatever
	// an unverifiable posture claims.
	cp := filepath.Join(t.TempDir(), "config.toml")
	writeFileT(t, cp, guardOff)
	oldDaemon(enforcedPosture)(t, cp)
	if resolveHookFailurePlan("claude-code", "user-prompt-submit", cp).FailClosed {
		t.Error("prompt gate closed on a guard-off node by an unsigned posture")
	}
}

// TestGuardPostureWriterRepairsTamper pins Sol A2-02 on the daemon side: a
// replaced posture or key is detected on the next publish even though the
// intended content did not change, rewritten, and queued as a tamper
// event that persists as a guard_error flag.
func TestGuardPostureWriterRepairsTamper(t *testing.T) {
	cp := filepath.Join(t.TempDir(), "config.toml")
	w := &guardPostureWriter{}
	p := guardposture.Posture{Enforced: true, Source: "local", GateCaps: []string{"tool_gate"}, WrittenAt: time.Unix(1, 0)}
	if changed, err := w.publish(cp, p); err != nil || !changed {
		t.Fatalf("first publish = %v, %v", changed, err)
	}
	if got := w.takeTampers(); len(got) != 0 {
		t.Fatalf("a fresh node reported tampers: %v", got)
	}
	data, _ := json.Marshal(guardposture.Posture{Schema: guardposture.Schema, Source: "local"})
	writeFileT(t, guardposture.PosturePath(cp), string(data))
	if changed, err := w.publish(cp, p); err != nil || !changed {
		t.Fatalf("publish after a forged posture = %v, %v; want a repair", changed, err)
	}
	if ld := guardposture.Load(guardposture.PosturePath(cp), guardposture.KeyPath(cp)); ld.State != guardposture.StateValid || !ld.Posture.Enforced {
		t.Fatalf("after repair: %s %+v", ld.State, ld.Posture)
	}
	if err := os.Remove(guardposture.KeyPath(cp)); err != nil {
		t.Fatal(err)
	}
	if changed, err := w.publish(cp, p); err != nil || !changed {
		t.Fatalf("publish after a deleted key = %v, %v", changed, err)
	}
	if ld := guardposture.Load(guardposture.PosturePath(cp), guardposture.KeyPath(cp)); ld.State != guardposture.StateValid {
		t.Fatalf("after key repair: %s (%s)", ld.State, ld.Detail)
	}
	if changed, _ := w.publish(cp, p); changed {
		t.Error("a clean, unchanged posture was rewritten")
	}

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	if n := recordPostureTampers(ctx, w, st, newLogger("error")); n != 2 {
		t.Fatalf("recorded %d tamper events, want 2", n)
	}
	rows, err := st.GuardEventsAfter(ctx, 0, 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("guard_events = %d (%v)", len(rows), err)
	}
	for _, r := range rows {
		if r.RuleID != guard.GuardErrorRuleID || r.DegradedFrom != "posture_tamper" || r.Decision != "flag" || r.EventKind != "config_change" {
			t.Errorf("tamper row = %+v", r)
		}
	}

	// A daemon that starts over a posture forged while it was stopped
	// reports it.
	w2 := &guardPostureWriter{}
	writeFileT(t, guardposture.PosturePath(cp), string(data))
	if _, err := w2.publish(cp, p); err != nil {
		t.Fatal(err)
	}
	if got := w2.takeTampers(); len(got) != 1 || !strings.Contains(got[0], "daemon start") {
		t.Errorf("start-time tamper = %v", got)
	}
}

// TestDrainHookFailuresKeepsEveryChunk pins Sol A2-07 end to end: a spool
// larger than one chunk is persisted in full across chunks, nothing past
// the cap is lost.
func TestDrainHookFailuresKeepsEveryChunk(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(dir, "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	spool := filepath.Join(dir, guardposture.SpoolFilename)
	const n = 30
	for i := 0; i < n; i++ {
		if err := guardposture.Append(spool, guardposture.Record{Tool: "claude-code", Event: "pre-tool", Cap: "tool_gate", Kind: guardposture.KindTimeout}); err != nil {
			t.Fatal(err)
		}
	}
	prev := hookFailDrainCap
	hookFailDrainCap = 400 // a few records per chunk
	t.Cleanup(func() { hookFailDrainCap = prev })
	got := 0
	for tick := 0; tick < 10 && got < n; tick++ {
		got += drainHookFailures(ctx, spool, st, newLogger("error"))
	}
	if got != n {
		t.Fatalf("persisted %d of %d spooled failures", got, n)
	}
	rows, err := st.GuardEventsAfter(ctx, 0, 100)
	if err != nil || len(rows) != n {
		t.Fatalf("guard_events = %d (%v), want %d", len(rows), err, n)
	}
}
