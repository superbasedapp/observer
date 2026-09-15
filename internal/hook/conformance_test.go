package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// loadFixture reads one testdata/guard payload (the §18 conformance
// harness corpus: real per-client payload shapes, including the F8
// WSL-bridge case).
func loadFixture(t *testing.T, client, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "guard", client, name))
	if err != nil {
		t.Fatalf("fixture %s/%s: %v", client, name, err)
	}
	return body
}

// conformanceGuard builds a real Guard (built-ins only) in the given
// mode for harness runs.
func conformanceGuard(t *testing.T, mode string) *guard.Guard {
	t.Helper()
	g, err := guard.New(guard.Options{
		Config: config.GuardConfig{
			Enabled: true, Mode: mode,
			Taint: config.GuardTaintConfig{Enabled: true, DecayTurns: 10},
		},
		Home:     "/home/dev",
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	return g
}

// TestConformance_ClaudeCode runs the claude-code fixtures through
// HandleGuarded with a real enforce-mode engine and pins the emitted
// decision per fixture — the §6.5 harness for the PreToolUse channel.
func TestConformance_ClaudeCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		fixture  string
		mode     string
		blocked  bool
		emitWant string // substring of the reply when blocked
		ruleWant string
	}{
		{"pretool_bash_rmrf.json", "enforce", true, `"permissionDecision":"deny"`, "R-101"},
		// F8: the SAME command fired by Windows Claude Code through
		// the wsl.exe bridge (Windows-style cwd + transcript path,
		// evaluated by a non-Windows-built binary) must produce the
		// SAME verdict — the path machinery is OS-agnostic by design.
		{"pretool_bash_rmrf_wslbridge.json", "enforce", true, `"permissionDecision":"deny"`, "R-101"},
		// R-152 read in enforce mode is ask-class → native ask.
		{"pretool_read_sensitive.json", "enforce", true, `"permissionDecision":"ask"`, "R-152"},
		// Observe mode: the same destructive command flags but
		// proceeds (D2) — no reply written by HandleGuarded.
		{"pretool_bash_rmrf.json", "observe", false, "", "R-101"},
	}
	for _, tc := range cases {
		t.Run(tc.mode+"/"+tc.fixture, func(t *testing.T) {
			t.Parallel()
			g := conformanceGuard(t, tc.mode)
			body := loadFixture(t, "claude-code", tc.fixture)
			var out bytes.Buffer
			var persisted []guard.ActionVerdict
			blocked, after := HandleGuarded("claude-code:pre-tool", body, g,
				func(v guard.ActionVerdict) { persisted = append(persisted, v) },
				&out, &bytes.Buffer{})
			if blocked != tc.blocked {
				t.Fatalf("blocked = %v, want %v (out=%s)", blocked, tc.blocked, out.String())
			}
			if tc.blocked {
				if !strings.Contains(out.String(), tc.emitWant) {
					t.Errorf("reply = %s, want %s", out.String(), tc.emitWant)
				}
			} else if after != nil {
				after()
			}
			if len(persisted) != 1 || persisted[0].Verdict.RuleID != tc.ruleWant {
				t.Fatalf("persisted = %+v, want one %s verdict", persisted, tc.ruleWant)
			}
			if tc.blocked != persisted[0].Enforced {
				t.Errorf("enforced flag = %v, want %v", persisted[0].Enforced, tc.blocked)
			}
		})
	}
}

// TestConformance_Cursor runs the cursor fixtures through the guarded
// receiver: deny permission JSON on a destructive command in enforce
// mode, allow + capture in observe mode, and capture proceeding on
// EVERY path (a denied attempt still records).
func TestConformance_Cursor(t *testing.T) {
	t.Parallel()
	sc := scrub.New()

	t.Run("enforce denies destructive shell", func(t *testing.T) {
		t.Parallel()
		g := conformanceGuard(t, "enforce")
		sink := &fakeSink{outcomeRows: 1}
		var out bytes.Buffer
		var persisted []guard.ActionVerdict
		HandleCursorEventGuarded("beforeShellExecution", g,
			func(v guard.ActionVerdict) { persisted = append(persisted, v) },
			sink, sc,
			bytes.NewReader(loadFixture(t, "cursor", "before_shell_rmrf.json")),
			false, &out, &bytes.Buffer{}, 0)
		var reply struct {
			Permission string `json:"permission"`
		}
		if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
			t.Fatalf("reply parse: %v (%s)", err, out.String())
		}
		if reply.Permission != "deny" {
			t.Errorf("permission = %q, want deny", reply.Permission)
		}
		if len(persisted) != 1 || persisted[0].Verdict.RuleID != "R-101" || !persisted[0].Enforced {
			t.Errorf("persisted = %+v, want one enforced R-101", persisted)
		}
		if persisted[0].Input.Tool != models.ToolCursor {
			t.Errorf("verdict tool = %q", persisted[0].Input.Tool)
		}
		// Capture proceeded despite the deny — the attempt is recorded.
		if len(sink.called) == 0 {
			t.Error("denied attempt was not captured")
		}
	})

	t.Run("observe flags but allows", func(t *testing.T) {
		t.Parallel()
		g := conformanceGuard(t, "observe")
		sink := &fakeSink{outcomeRows: 1}
		var out bytes.Buffer
		var persisted []guard.ActionVerdict
		HandleCursorEventGuarded("beforeShellExecution", g,
			func(v guard.ActionVerdict) { persisted = append(persisted, v) },
			sink, sc,
			bytes.NewReader(loadFixture(t, "cursor", "before_shell_rmrf.json")),
			false, &out, &bytes.Buffer{}, 0)
		if !strings.Contains(out.String(), `"permission":"allow"`) {
			t.Errorf("observe reply = %s, want allow", out.String())
		}
		if len(persisted) != 1 || persisted[0].Verdict.RuleID != "R-101" || persisted[0].Enforced {
			t.Errorf("persisted = %+v, want one un-enforced R-101 flag", persisted)
		}
	})

	t.Run("benign command stays silent", func(t *testing.T) {
		t.Parallel()
		g := conformanceGuard(t, "enforce")
		sink := &fakeSink{outcomeRows: 1}
		var out bytes.Buffer
		var persisted []guard.ActionVerdict
		HandleCursorEventGuarded("beforeShellExecution", g,
			func(v guard.ActionVerdict) { persisted = append(persisted, v) },
			sink, sc,
			bytes.NewReader(loadFixture(t, "cursor", "before_shell_benign.json")),
			false, &out, &bytes.Buffer{}, 0)
		if !strings.Contains(out.String(), `"permission":"allow"`) {
			t.Errorf("benign reply = %s", out.String())
		}
		if len(persisted) != 0 {
			t.Errorf("benign command persisted a verdict: %+v", persisted)
		}
		if len(sink.called) == 0 {
			t.Error("benign command not captured")
		}
	})

	t.Run("nil guard degrades to unguarded receiver", func(t *testing.T) {
		t.Parallel()
		sink := &fakeSink{outcomeRows: 1}
		var out bytes.Buffer
		HandleCursorEventGuarded("beforeShellExecution", nil, nil, sink, sc,
			bytes.NewReader(loadFixture(t, "cursor", "before_shell_rmrf.json")),
			false, &out, &bytes.Buffer{}, 0)
		if !strings.Contains(out.String(), `"permission":"allow"`) {
			t.Errorf("nil-guard reply = %s, want unconditional allow", out.String())
		}
	})
}

// TestConformance_BoundaryCapsAgreeWithMatrix pins that the
// capabilities each boundary hard-codes (claude-code's
// claudeCodePreToolCaps) or looks up (cursor) AGREE with the §6.5
// conformance matrix — the matrix is the single source of truth and
// a drift here is a silent capability lie.
func TestConformance_BoundaryCapsAgreeWithMatrix(t *testing.T) {
	t.Parallel()
	want, ok := guard.CapabilitiesFor(models.ToolClaudeCode, "hook:PreToolUse")
	if !ok {
		t.Fatal("claude-code hook:PreToolUse missing from the conformance matrix")
	}
	if claudeCodePreToolCaps != want {
		t.Errorf("claudeCodePreToolCaps %+v != matrix %+v", claudeCodePreToolCaps, want)
	}
	for _, ch := range []string{"beforeShellExecution", "beforeMCPExecution", "beforeReadFile"} {
		caps, ok := guard.CapabilitiesFor(models.ToolCursor, "hook:"+ch)
		if !ok || !caps.PreExecution || !caps.CanBlock || !caps.CanAsk {
			t.Errorf("cursor hook:%s caps = %+v ok=%v, want full pre-execution", ch, caps, ok)
		}
	}
}
