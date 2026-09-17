package compile_test

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard/compile"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// catalogIDs returns the distinct built-in catalog rule IDs in order.
func catalogIDs() []string {
	var ids []string
	seen := map[string]bool{}
	for _, r := range policy.Catalog() {
		if !seen[r.ID] {
			seen[r.ID] = true
			ids = append(ids, r.ID)
		}
	}
	return ids
}

// implementedTargets returns the v1 compiled dialects.
func implementedTargets(t *testing.T) []compile.Target {
	t.Helper()
	var out []compile.Target
	for _, tgt := range compile.Targets() {
		if tgt.Implemented {
			out = append(out, tgt)
		}
	}
	if len(out) != 2 {
		t.Fatalf("implemented targets = %d, want 2 (claude-code, opencode)", len(out))
	}
	return out
}

// TestTargets pins the §13.2 target table shape: claude-code and
// opencode implemented with config paths; the five deferred targets
// each carry a recorded reason (Q4: deferred-with-reason, never
// silently absent).
func TestTargets(t *testing.T) {
	t.Parallel()
	implemented, deferred := 0, 0
	for _, tgt := range compile.Targets() {
		if tgt.Implemented {
			implemented++
			if tgt.Path("/home/u") == "" || tgt.Rows() == nil {
				t.Errorf("%s: implemented target missing path or rows", tgt.Dialect)
			}
			if tgt.Reason != "" {
				t.Errorf("%s: implemented target carries a deferral reason", tgt.Dialect)
			}
		} else {
			deferred++
			if tgt.Reason == "" {
				t.Errorf("%s: deferred target without a reason", tgt.Dialect)
			}
		}
		if tgt.Client == "" {
			t.Errorf("%s: target without client", tgt.Dialect)
		}
	}
	if implemented != 2 || deferred != 5 {
		t.Errorf("targets = %d implemented / %d deferred, want 2/7-split per spec §13.2", implemented, deferred)
	}
	if tgt, ok := compile.TargetFor("claude-code"); !ok || !strings.HasSuffix(tgt.Path("/home/u"), "settings.json") {
		t.Errorf("TargetFor claude-code = %+v, %v", tgt, ok)
	}
	if _, ok := compile.TargetFor("not-a-dialect"); ok {
		t.Error("TargetFor accepted an unknown dialect")
	}
}

// TestTableCoversCatalog pins the spec §13.2 completeness contract:
// every implemented dialect's translation table records EXACTLY one
// row per built-in catalog rule ID — a new catalog rule fails this
// test until its compilability is recorded as data — and every
// approximation/none row documents itself in its Note.
func TestTableCoversCatalog(t *testing.T) {
	t.Parallel()
	want := catalogIDs()
	for _, tgt := range implementedTargets(t) {
		rows := tgt.Rows()
		got := map[string]int{}
		for _, row := range rows {
			got[row.RuleID]++
			switch row.Fidelity {
			case compile.FidelityNone:
				if len(row.Entries) != 0 {
					t.Errorf("%s %s: none-fidelity row carries entries", tgt.Dialect, row.RuleID)
				}
				if row.Note == "" {
					t.Errorf("%s %s: none-fidelity row without a note", tgt.Dialect, row.RuleID)
				}
			case compile.FidelityApprox:
				if len(row.Entries) == 0 {
					t.Errorf("%s %s: approximation row without entries", tgt.Dialect, row.RuleID)
				}
				if row.Note == "" {
					t.Errorf("%s %s: approximation row without a note — lossy translations are never silent", tgt.Dialect, row.RuleID)
				}
			case compile.FidelityExact:
				if len(row.Entries) == 0 {
					t.Errorf("%s %s: exact row without entries", tgt.Dialect, row.RuleID)
				}
			default:
				t.Errorf("%s %s: unknown fidelity %q", tgt.Dialect, row.RuleID, row.Fidelity)
			}
			for _, e := range row.Entries {
				if e.Action != compile.ActionDeny && e.Action != compile.ActionAsk {
					t.Errorf("%s %s: entry action %q", tgt.Dialect, row.RuleID, e.Action)
				}
			}
		}
		for _, id := range want {
			if got[id] != 1 {
				t.Errorf("%s: catalog rule %s has %d table rows, want exactly 1", tgt.Dialect, id, got[id])
			}
		}
		if len(got) != len(want) {
			t.Errorf("%s: table has %d rule IDs, catalog has %d", tgt.Dialect, len(got), len(want))
		}
	}
}

// rowExpect is one hand-written per-row expectation: how many entries
// the row emits against the unmodified built-in catalog, and how many
// land as deny (the rest are ask). Spec §13.2 / module rule 5: one
// test case per translator row, expectations written out, not
// re-derived from the implementation.
type rowExpect struct {
	entries int
	deny    int
}

// claudeCodeExpect / openCodeExpect are the full per-row expectation
// tables for a full-catalog compile.
var claudeCodeExpect = map[string]rowExpect{
	"R-101": {entries: 2}, "R-102": {entries: 2}, "R-103": {}, "R-104": {entries: 2},
	"R-110": {entries: 2}, "R-111": {entries: 2}, "R-120": {}, "R-130": {entries: 3},
	"R-140": {entries: 4}, "R-141": {entries: 1}, "R-142": {entries: 2, deny: 2},
	"R-150": {}, "R-151": {}, "R-152": {entries: 15, deny: 10}, "R-153": {entries: 5},
	"R-154": {entries: 12, deny: 12}, "R-155": {entries: 5, deny: 4}, "R-156": {entries: 2},
	"R-157": {},
	"R-160": {entries: 4, deny: 4}, "R-161": {}, "R-170": {}, "R-171": {}, "R-172": {},
	"R-173": {}, "R-180": {}, "R-190": {}, "R-204": {}, "R-205": {}, "R-301": {}, "R-302": {}, "R-303": {},
	"R-304": {entries: 8, deny: 8}, "R-305": {},
	"B-603": {}, "B-604": {}, "B-610": {}, "B-611": {}, "B-612": {}, "B-613": {},
	// Token-denominated budget rows (org-budget plan §3.3c): runtime state
	// like their $ siblings, so no native dialect can express them either.
	"B-621": {}, "B-622": {}, "B-623": {}, "B-624": {},
	// The fail-closed row (org-budget ruling R2): daemon state, same reason.
	"B-625": {},
	// The organization's per-tool / per-model caps (bundle BUD-N): policy the
	// org authored, compared against runtime spend. A native config file has
	// neither number.
	"B-626": {}, "B-627": {}, "B-628": {}, "B-629": {},
	"T-501": {}, "T-502": {}, "T-503": {}, "T-504": {}, "T-505": {},
	"B-601": {}, "B-602": {}, "A-610": {},
}

var openCodeExpect = map[string]rowExpect{
	"R-101": {entries: 2}, "R-102": {entries: 2}, "R-103": {}, "R-104": {entries: 2},
	"R-110": {entries: 2}, "R-111": {entries: 2}, "R-120": {}, "R-130": {entries: 3},
	"R-140": {entries: 4}, "R-141": {entries: 1}, "R-142": {entries: 2, deny: 2},
	"R-150": {}, "R-151": {}, "R-152": {}, "R-153": {},
	"R-154": {}, "R-155": {entries: 1}, "R-156": {}, "R-157": {},
	"R-160": {}, "R-161": {}, "R-170": {}, "R-171": {}, "R-172": {},
	"R-173": {}, "R-180": {}, "R-190": {}, "R-204": {}, "R-205": {}, "R-301": {}, "R-302": {}, "R-303": {},
	"R-304": {}, "R-305": {},
	"T-501": {}, "T-502": {}, "T-503": {}, "T-504": {}, "T-505": {},
	"B-601": {}, "B-602": {}, "A-610": {},
	"B-603": {}, "B-604": {}, "B-610": {}, "B-611": {}, "B-612": {}, "B-613": {},
	// Token-denominated budget rows (org-budget plan §3.3c): runtime state
	// like their $ siblings, so no native dialect can express them either.
	"B-621": {}, "B-622": {}, "B-623": {}, "B-624": {},
	// The fail-closed row (org-budget ruling R2): daemon state, same reason.
	"B-625": {},
	// The organization's per-tool / per-model caps (bundle BUD-N): policy the
	// org authored, compared against runtime spend. A native config file has
	// neither number.
	"B-626": {}, "B-627": {}, "B-628": {}, "B-629": {},
}

// TestCompile_PerRow runs the full built-in catalog through each
// implemented dialect and checks every row against its hand-written
// expectation: emission count, deny/ask split, and skip behavior.
func TestCompile_PerRow(t *testing.T) {
	t.Parallel()
	expect := map[compile.Dialect]map[string]rowExpect{
		compile.DialectClaudeCode: claudeCodeExpect,
		compile.DialectOpenCode:   openCodeExpect,
	}
	for _, tgt := range implementedTargets(t) {
		want := expect[tgt.Dialect]
		out := compile.Compile(tgt, policy.Catalog())
		if len(out.Uncompiled) != 0 {
			t.Errorf("%s: catalog compile reports uncompiled rules %v", tgt.Dialect, out.Uncompiled)
		}
		if len(out.Rows) != len(want) {
			t.Fatalf("%s: %d row results, want %d", tgt.Dialect, len(out.Rows), len(want))
		}
		for _, row := range out.Rows {
			exp, ok := want[row.RuleID]
			if !ok {
				t.Errorf("%s %s: no expectation row", tgt.Dialect, row.RuleID)
				continue
			}
			deny := 0
			for _, e := range row.Emitted {
				if e.Action == compile.ActionDeny {
					deny++
				}
			}
			if len(row.Emitted) != exp.entries || deny != exp.deny {
				t.Errorf("%s %s: emitted %d (%d deny), want %d (%d deny)",
					tgt.Dialect, row.RuleID, len(row.Emitted), deny, exp.entries, exp.deny)
			}
			if exp.entries == 0 && row.Skipped == "" {
				t.Errorf("%s %s: silent row — zero entries need a recorded skip reason", tgt.Dialect, row.RuleID)
			}
		}
	}
}

// effectiveWith rewrites the catalog: drop removes IDs, enforce
// overrides an ID's enforce decision on every row.
func effectiveWith(drop string, override string, decision policy.Decision) []policy.RuleInfo {
	var out []policy.RuleInfo
	for _, r := range policy.Catalog() {
		if r.ID == drop {
			continue
		}
		if r.ID == override {
			r.Enforce = decision
		}
		out = append(out, r)
	}
	return out
}

// TestCompile_Gating covers the effective-policy gates: disabled
// rules emit nothing, a deny→ask override caps deny entries to ask, a
// →flag override suppresses emission, and entries are never escalated
// above their table action.
func TestCompile_Gating(t *testing.T) {
	t.Parallel()
	tgt, _ := compile.TargetFor("claude-code")

	find := func(out compile.Compiled, id string) compile.RowResult {
		for _, row := range out.Rows {
			if row.RuleID == id {
				return row
			}
		}
		t.Fatalf("row %s missing", id)
		return compile.RowResult{}
	}

	out := compile.Compile(tgt, effectiveWith("R-142", "", 0))
	if row := find(out, "R-142"); len(row.Emitted) != 0 || !strings.Contains(row.Skipped, "disabled") {
		t.Errorf("disabled R-142 row = %+v", row)
	}
	for _, e := range out.Entries {
		if e.Value == "Bash(mkfs:*)" {
			t.Error("disabled R-142 entry still compiled")
		}
	}

	out = compile.Compile(tgt, effectiveWith("", "R-142", policy.DecisionAsk))
	for _, e := range find(out, "R-142").Emitted {
		if e.Action != compile.ActionAsk {
			t.Errorf("deny→ask override left entry %+v at deny", e)
		}
	}

	out = compile.Compile(tgt, effectiveWith("", "R-142", policy.DecisionFlag))
	if row := find(out, "R-142"); len(row.Emitted) != 0 || !strings.Contains(row.Skipped, "flag") {
		t.Errorf("flag-effective R-142 row = %+v", row)
	}

	// Never escalate: R-140's table entries are ask (broadening
	// discipline); an enforce=deny override must not raise them.
	out = compile.Compile(tgt, effectiveWith("", "R-140", policy.DecisionDeny))
	for _, e := range find(out, "R-140").Emitted {
		if e.Action != compile.ActionAsk {
			t.Errorf("deny override escalated %+v above its table action", e)
		}
	}
}

// TestCompile_UncompiledUserRules pins coverage honesty: an effective
// rule with no translation row (user/project-authored) is listed, not
// silently dropped.
func TestCompile_UncompiledUserRules(t *testing.T) {
	t.Parallel()
	tgt, _ := compile.TargetFor("claude-code")
	eff := append(policy.Catalog(), policy.RuleInfo{
		ID: "U-900", Category: policy.CategoryBoundary,
		Enforce: policy.DecisionDeny, Source: "user",
	})
	out := compile.Compile(tgt, eff)
	if len(out.Uncompiled) != 1 || out.Uncompiled[0] != "U-900" {
		t.Errorf("Uncompiled = %v, want [U-900]", out.Uncompiled)
	}
}

// TestHashEntries pins the pin-hash contract: order-insensitive,
// action- and value-sensitive, versioned.
func TestHashEntries(t *testing.T) {
	t.Parallel()
	a := []compile.Entry{{Action: "deny", Value: "Bash(mkfs:*)"}, {Action: "ask", Value: "Read(~/.ssh/**)"}}
	b := []compile.Entry{{Action: "ask", Value: "Read(~/.ssh/**)"}, {Action: "deny", Value: "Bash(mkfs:*)"}}
	if compile.HashEntries(a) != compile.HashEntries(b) {
		t.Error("hash is order-sensitive; cosmetic reordering would read as drift")
	}
	c := []compile.Entry{{Action: "ask", Value: "Bash(mkfs:*)"}, {Action: "ask", Value: "Read(~/.ssh/**)"}}
	if compile.HashEntries(a) == compile.HashEntries(c) {
		t.Error("hash ignores the action half")
	}
	if !strings.HasPrefix(compile.HashEntries(a), "v1 ") {
		t.Errorf("hash %q not versioned", compile.HashEntries(a))
	}
}
