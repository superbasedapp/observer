package cloudsession

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// guardOpts is testOpts with the guard on, signed by a fixed test key.
func guardOpts(t *testing.T, agent string, mode GuardMode) PlanOptions {
	t.Helper()
	raw, pin := signedPolicy(t, testSigner(7), 5, nil)
	o := testOpts(agent)
	o.Guard = &GuardSetup{Mode: mode, KeyPin: pin.KeyPin, Policy: raw}
	return o
}

// TestGateRowsPerVendor pins, per supported vendor row, which events carry a
// gate, what each judges, and what it does when it cannot evaluate or when
// observer is missing, under both modes.
func TestGateRowsPerVendor(t *testing.T) {
	type row struct {
		event   string
		kind    GateKind
		failure GateFailure // under enforce
		missing GateFailure // under enforce
	}
	want := map[string][]row{
		"claude-code": {
			{"PreToolUse", GateTool, FailClosed, FailClosed},
			{"UserPromptSubmit", GatePrompt, FailClosed, FailClosed},
		},
		"copilot": {
			{"preToolUse", GateTool, FailClosed, FailClosed},
			// The vendor ignores a prompt hook's exit code: without
			// observer's own reply the prompt passes.
			{"userPromptSubmitted", GatePrompt, FailClosed, FailOpen},
		},
	}
	for _, a := range Agents() {
		rows, ok := want[a.ID]
		if !a.Supported() {
			if ok {
				t.Errorf("%s is unsupported but listed", a.ID)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: no gate rows pinned; add them here", a.ID)
			continue
		}
		cov := GateCoverageFor(a, GuardEnforce)
		if len(cov) != len(rows) {
			t.Fatalf("%s: %d gates, want %d", a.ID, len(cov), len(rows))
		}
		for i, r := range rows {
			c := cov[i]
			if c.Event != r.event || c.Kind != r.kind || c.Failure != r.failure || c.MissingBinary != r.missing || !c.Blocks {
				t.Errorf("%s gate %d = %+v, want %+v", a.ID, i, c, r)
			}
			if c.Grounding == "" || !strings.Contains(c.Line(), r.event) {
				t.Errorf("%s %s: coverage line is not honest: %q", a.ID, r.event, c.Line())
			}
		}
		for _, c := range GateCoverageFor(a, GuardObserve) {
			if c.Blocks || c.Failure != FailOpen || c.MissingBinary != FailOpen {
				t.Errorf("%s %s: observe mode must never block: %+v", a.ID, c.Event, c)
			}
		}
	}
}

// TestGateDialectsMatchRegistry: every gate entry's dialect is the one the
// integration registry names for that vendor event's gate capability, so the
// sandbox gate speaks the same reply dialect as the local hook.
func TestGateDialectsMatchRegistry(t *testing.T) {
	for _, a := range Agents() {
		for _, b := range a.Hooks {
			if b.Action != ActionGate {
				continue
			}
			if _, ok := gateDialectFor(b.Dialect); !ok {
				t.Errorf("%s %s: dialect %q has no gate dialect row", a.ID, b.Event, b.Dialect)
			}
			c, ok := integration.For(a.HookTool)
			if !ok {
				t.Fatalf("%s: no registry row for %s", a.ID, a.HookTool)
			}
			wantCap := integration.HookCapToolGate
			if b.Gate == GatePrompt {
				wantCap = integration.HookCapPromptGate
			}
			found := false
			for _, hb := range c.Hook.Bindings {
				if hb.NativeEvent == b.Event && hb.Cap == wantCap && hb.Dialect == b.Dialect {
					found = true
				}
			}
			if !found {
				t.Errorf("%s %s: the registry has no %s binding with dialect %q", a.ID, b.Event, wantCap, b.Dialect)
			}
		}
	}
}

// TestGateCommands: a gate command is gated on the marker and the binary,
// pins the key and the policy digest, never mentions a token, and blocks
// without the binary only where the failure table says so.
func TestGateCommands(t *testing.T) {
	for _, mode := range GuardModes() {
		for _, id := range []string{"claude-code", "copilot"} {
			a := mustAgent(t, id)
			opts := guardOpts(t, id, mode)
			for _, b := range a.Hooks {
				if b.Action != ActionGate {
					continue
				}
				cmd, err := hookCommand(a, b, opts)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasPrefix(cmd, markerGate(a)+" && ") || !strings.HasSuffix(cmd, "; exit 0 "+OwnerTag) {
					t.Errorf("%s %s: not gated: %s", id, b.Event, cmd)
				}
				for _, want := range []string{"cloud-session gate", "--key-pin " + opts.Guard.KeyPin, "--policy " + PolicyDigest(opts.Guard.Policy), "--mode " + string(mode)} {
					if !strings.Contains(cmd, want) {
						t.Errorf("%s %s: missing %q: %s", id, b.Event, want, cmd)
					}
				}
				if strings.Contains(strings.ToLower(cmd), "token") {
					t.Errorf("%s %s: mentions a token", id, b.Event)
				}
				d, _ := gateDialectFor(b.Dialect)
				closed := mode == GuardEnforce && d.missingBinary != ""
				if strings.Contains(cmd, "exit 2") != closed {
					t.Errorf("%s %s %s: fail-closed-without-binary = %v, want %v: %s", id, b.Event, mode, !closed, closed, cmd)
				}
			}
		}
	}
	if _, err := hookCommand(mustAgent(t, "claude-code"), HookBinding{Event: "PreToolUse", Action: ActionGate, Dialect: "claude-code-pretool"}, testOpts("claude-code")); err == nil {
		t.Error("a gate without --guard rendered")
	}
}

// TestGateBindingLookup: the gate command resolves its entry from the table.
func TestGateBindingLookup(t *testing.T) {
	a := mustAgent(t, "claude-code")
	b, err := GateBinding(a, "PreToolUse")
	if err != nil || b.Gate != GateTool || b.Dialect != "claude-code-pretool" {
		t.Fatalf("binding = %+v, %v", b, err)
	}
	if _, err := GateBinding(a, "PostToolUse"); err == nil {
		t.Error("a capture-only event resolved to a gate")
	}
}

// TestValidateGuard: a bad mode or a policy that does not verify against its
// pin is refused before anything is planned.
func TestValidateGuard(t *testing.T) {
	o := guardOpts(t, "claude-code", "loud")
	if _, err := PlanInit(o, memRepo{}.read); err == nil || !strings.Contains(err.Error(), "--guard-mode") {
		t.Fatalf("err = %v", err)
	}
	o = guardOpts(t, "claude-code", GuardEnforce)
	o.Guard.KeyPin = strings.Repeat("0", 64)
	if _, err := PlanInit(o, memRepo{}.read); err == nil || !strings.Contains(err.Error(), "key_pin") {
		t.Fatalf("err = %v", err)
	}
	o = testOpts("claude-code")
	o.CodeIntel = true
	if _, err := PlanInit(o, memRepo{}.read); err == nil || !strings.Contains(err.Error(), "--mcp") {
		t.Fatalf("err = %v", err)
	}
}
