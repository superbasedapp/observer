package hook

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// stderrBlockLine is DEC-1's header, spelled out here (not read from the
// constant) so a change to the text is a deliberate test change.
const stderrBlockLine = "Blocked by Observer guard:"

// wantStderrBlock is the exact stderr a stderr-reason host gets for a block
// carrying reason: the header, a space and the reason on one line, then a
// newline.
func wantStderrBlock(reason string) string {
	return stderrBlockLine + " " + reason + "\n"
}

// TestStderrBlockReason pins the helper: the header and the reason share the
// first line (audit finding 5), the reason follows unchanged, and the helper
// is idempotent, including over the earlier header-on-its-own-line form.
func TestStderrBlockReason(t *testing.T) {
	if StderrBlockHeader != stderrBlockLine {
		t.Fatalf("StderrBlockHeader = %q, want %q", StderrBlockHeader, stderrBlockLine)
	}
	for _, r := range []struct {
		name, in, want string
	}{
		{"plain reason", "rm -rf is not allowed here.", stderrBlockLine + " rm -rf is not allowed here."},
		{"multi-line reason", "line one\nline two", stderrBlockLine + " line one\nline two"},
		{"empty reason", "", stderrBlockLine},
		{"already prefixed", stderrBlockLine + " why", stderrBlockLine + " why"},
		{"already prefixed, earlier two-line form", stderrBlockLine + "\nwhy", stderrBlockLine + "\nwhy"},
		{"already prefixed, earlier two-line form, CRLF", stderrBlockLine + "\r\nwhy", stderrBlockLine + "\r\nwhy"},
		{"header alone", stderrBlockLine, stderrBlockLine},
		{"header glued to the reason", stderrBlockLine + "why", stderrBlockLine + " " + stderrBlockLine + "why"},
		{"header later in the reason", "why\n" + stderrBlockLine, stderrBlockLine + " why\n" + stderrBlockLine},
	} {
		t.Run(r.name, func(t *testing.T) {
			got := StderrBlockReason(r.in)
			if got != r.want {
				t.Fatalf("StderrBlockReason(%q) = %q, want %q", r.in, got, r.want)
			}
			if again := StderrBlockReason(got); again != got {
				t.Fatalf("not idempotent: StderrBlockReason(%q) = %q", got, again)
			}
			var b bytes.Buffer
			WriteStderrBlockReason(&b, r.in)
			if b.String() != r.want+"\n" {
				t.Fatalf("WriteStderrBlockReason = %q, want %q", b.String(), r.want+"\n")
			}
		})
	}
}

// TestStderrBlockHeaderOnEveryStderrReasonToolGateDialect: every tool-gate
// row that shows stderr as the block reason writes the header line, then
// the reason, for a deny and for an ask, and never writes it twice; a row
// that does not keeps Observer's diagnostic line there.
func TestStderrBlockHeaderOnEveryStderrReasonToolGateDialect(t *testing.T) {
	const reason = "blocked thing. Do this instead."
	seen := 0
	for _, d := range ToolGateDialects() {
		for _, perm := range []string{"deny", "ask"} {
			b, ok := toolGateBlockFor(d, "PreToolUse", guard.Emission{Permission: perm, Enforced: true, Reason: reason})
			if !ok {
				continue
			}
			for _, in := range []string{reason, StderrBlockReason(reason)} {
				var out, errb bytes.Buffer
				writeToolGateBlock(b, in, "observer-hook: diagnostic", &out, &errb)
				want := "observer-hook: diagnostic\n"
				if ToolGateDialectStderrReason(d) {
					want = wantStderrBlock(reason)
				}
				if errb.String() != want {
					t.Errorf("%s %s (reason %q): stderr = %q, want %q", d, perm, in, errb.String(), want)
				}
				if strings.Contains(out.String(), stderrBlockLine) {
					t.Errorf("%s %s: the header reached stdout %q (stderr channel only)", d, perm, out.String())
				}
			}
		}
		if ToolGateDialectStderrReason(d) {
			seen++
		}
	}
	if seen == 0 {
		t.Fatal("no stderr-reason tool-gate dialect found")
	}
}

// TestStderrBlockHeaderOnEveryStderrReasonPromptDialect: every prompt row
// that shows stderr as the reason writes the header line for a BLOCK, and
// keeps a non-blocking WARNING verbatim (a warning is not a block). The
// header never reaches the JSON reply.
func TestStderrBlockHeaderOnEveryStderrReasonPromptDialect(t *testing.T) {
	ids := make([]string, 0, len(promptDialects))
	for id, d := range promptDialects {
		if d.stderrReason {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		t.Fatal("no stderr-reason prompt dialect found")
	}
	for _, id := range ids {
		d := promptDialects[id]
		caps := d.seamCapsFor()
		t.Run(id, func(t *testing.T) {
			deny := guard.PromptVerdict{
				Verdict: policy.Verdict{Decision: policy.DecisionDeny, RuleID: "R-190", Reason: "secret-shaped content"},
				Outcome: guard.PromptOutcomeBlocked,
			}.WithAction(caps, "hook")
			if !deny.Action.Stops() {
				t.Fatalf("a deny does not stop on this row (action %v)", deny.Action)
			}
			var out, errb bytes.Buffer
			finishPromptVerdict("t", "UserPromptSubmit", d, nil, "s1", deny, "", nil, &out, &errb)
			got := errb.String()
			if !strings.HasPrefix(got, stderrBlockLine+" ") || strings.Count(got, stderrBlockLine) != 1 {
				t.Errorf("block stderr = %q, want one %q then the reason on the first line", got, stderrBlockLine)
			}
			if strings.Contains(got, "observer-hook:") {
				t.Errorf("block stderr carries a diagnostic: %q", got)
			}
			if strings.Contains(out.String(), stderrBlockLine) {
				t.Errorf("the header reached the stdout reply %q (stderr channel only)", out.String())
			}

			out.Reset()
			errb.Reset()
			warn := warnVerdict("heads up").WithAction(caps, "hook")
			finishPromptVerdict("t", "UserPromptSubmit", d, nil, "s1", warn, "", nil, &out, &errb)
			if warn.Action == guard.PromptActionWarn && !strings.Contains(errb.String(), "heads up") {
				t.Errorf("warning stderr = %q, want the notice verbatim", errb.String())
			}
			if strings.Contains(errb.String(), stderrBlockLine) {
				t.Errorf("warning stderr = %q, want no block header on a warning", errb.String())
			}
		})
	}
}
