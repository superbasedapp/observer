package secassess

import (
	"strings"
	"testing"
)

// safetyPlanTable is the plan's W4.6 table as this test reads it: per row, the
// cells the Helper and Observer columns may say. A cell may be "-" or exactly
// the plan's words; it may never say more. The Helper column is what the request
// helper enforces when it is on (depth plan W5b); with it off every cell is "-".
var safetyPlanTable = map[string]struct {
	helper     string         // what the helper script does, "-" where it does nothing
	observer   string         // the plan's words, "-" where the plan has no enforcement point
	promptOnly bool           // with the helper on
	kind       ObserverEffect // what Observer's cell does, "" where it is "-"
}{
	"target_only":     {"refuses any address that is not the target's", "the box's own network when it is limited to the model proxy, and the address checks made before the run starts", false, ObserverPrevents},
	"no_destructive":  {"reads at most 64 KiB of a response and keeps 1 KiB of it", "the git check sees tracked-file edits only, not ignored files, databases or caches", false, ObserverDetects},
	"pace_budget":     {"waits between requests and refuses past the budget, and logs the refusal", "the check counts the requests the log holds", false, ObserverDetects},
	"lockout":         {"counts attempts when a request names an account, per path, and refuses the eleventh; a guard rail, not a barrier", "-", false, ""},
	"time_box":        {"-", "the deadline and the Stop button", false, ObserverStops},
	"stop_conditions": {"-", "-", true, ""},
	"no_credentials":  {"-", "-", true, ""},
}

func TestSafetyRows(t *testing.T) {
	if len(SafetyRows) != len(safetyPlanTable) {
		t.Fatalf("%d rows, the plan's table has %d", len(SafetyRows), len(safetyPlanTable))
	}
	seen := map[string]bool{}
	for _, r := range SafetyRows {
		t.Run(r.ID, func(t *testing.T) {
			plan, ok := safetyPlanTable[r.ID]
			if !ok || seen[r.ID] {
				t.Fatalf("row %q is not in the plan's table or is repeated", r.ID)
			}
			seen[r.ID] = true
			if !r.Prompt {
				t.Errorf("every rule is stated in the prompt")
			}
			if r.Helper != plan.helper {
				t.Errorf("the helper cell is %q, want %q", r.Helper, plan.helper)
			}
			if r.Observer != "-" && r.Observer != plan.observer {
				t.Errorf("the Observer cell says %q, more than the plan's %q", r.Observer, plan.observer)
			}
			if r.Observer != plan.observer {
				t.Errorf("the Observer cell is %q, want %q", r.Observer, plan.observer)
			}
			if r.ObserverKind != plan.kind {
				t.Errorf("the Observer kind is %q, want %q", r.ObserverKind, plan.kind)
			}
			if r.PromptOnly() != plan.promptOnly {
				t.Errorf("PromptOnly = %v, want %v", r.PromptOnly(), plan.promptOnly)
			}
			if strings.TrimSpace(r.Rule) == "" || strings.ContainsAny(r.Rule, "\r\n") || clean(r.Rule, 400) != r.Rule {
				t.Errorf("the rule text is empty, has a break or is changed by clean: %q", r.Rule)
			}
			mCheckWords(t, "safety rule "+r.ID, r.Rule+" "+r.Observer+" "+r.Helper)
		})
	}
	for id := range safetyPlanTable {
		if !seen[id] {
			t.Errorf("the plan's row %s is missing", id)
		}
	}
}

func TestSafetyRowsHonestCells(t *testing.T) {
	byID := map[string]SafetyRow{}
	for _, r := range SafetyRows {
		byID[r.ID] = r
	}
	// "No real credentials, no .env" has no enforcement point (D32): prompt only.
	if !byID["no_credentials"].PromptOnly() {
		t.Error("the no-real-credentials row must read prompt only")
	}
	// The time box and the stop conditions are not enforced by the helper.
	for _, id := range []string{"time_box", "stop_conditions", "no_credentials"} {
		if byID[id].Helper != "-" {
			t.Errorf("%s: the helper cell is %q, but the helper does not hold that rule", id, byID[id].Helper)
		}
	}
	// No cell calls the helper a barrier or an authentic record.
	for _, r := range SafetyRows {
		for _, w := range []string{"authentic", "prevents", "guarantee", "blocks"} {
			if strings.Contains(strings.ToLower(r.Helper), w) {
				t.Errorf("%s: the helper cell says %q", r.ID, w)
			}
		}
	}
	// The boundary audit is git state only; the row says what it does not see.
	for _, w := range []string{"tracked-file edits only", "not ignored files", "databases", "caches"} {
		if !strings.Contains(byID["no_destructive"].Observer, w) {
			t.Errorf("the destructive row lacks %q", w)
		}
	}
	// The box's own network holds the target only while it is limited to the model proxy.
	if !strings.Contains(byID["target_only"].Observer, "limited to the model proxy") {
		t.Error("the target row does not name the tier it depends on")
	}
	// The lockout rule uses the number the prompt uses.
	if !strings.Contains(byID["lockout"].Rule, "10 attempts") {
		t.Errorf("lockout rule: %q", byID["lockout"].Rule)
	}
	// The prompt side states what the table says is prompt only.
	prompt := strings.Join(PentestLimitLines(PTLimitInput{}), "\n") + strings.Join(PentestSetupLines(PTSetupInput{}), "\n") + strings.Join(pentestBoundary, "\n")
	for _, w := range []string{"at most 10 attempts", "Never use a real credential", "not a test account's", "requests per second", "Request budget"} {
		if !strings.Contains(prompt, w) {
			t.Errorf("the prompt lines lack the rule words %q", w)
		}
	}
	// PromptOnly itself: each cell, one row.
	cells := []struct {
		r    SafetyRow
		want bool
	}{
		{SafetyRow{Prompt: true, Helper: "-", Observer: "-"}, true},
		{SafetyRow{Prompt: true, Helper: "refuses another host", Observer: "-"}, false},
		{SafetyRow{Prompt: true, Helper: "-", Observer: "the deadline"}, false},
		{SafetyRow{Prompt: false, Helper: "-", Observer: "-"}, false},
	}
	for _, c := range cells {
		if got := c.r.PromptOnly(); got != c.want {
			t.Errorf("PromptOnly(%+v) = %v", c.r, got)
		}
	}
}

// TestSafetyObserverKinds: the Observer cell and its closed kind agree on every
// row, and only the network rule (which holds while the network is limited to the model proxy) prevents; the
// git check detects afterwards and the deadline gives a way to stop, neither
// stops anything by itself. A surface reads the kind, never the sentence.
func TestSafetyObserverKinds(t *testing.T) {
	prevents := 0
	for _, r := range SafetyRows {
		t.Run(r.ID, func(t *testing.T) {
			if r.Observer == "-" {
				if r.ObserverKind != "" {
					t.Errorf("a row with no Observer check has the kind %q", r.ObserverKind)
				}
				return
			}
			if !r.ObserverKind.Valid() {
				t.Errorf("the Observer cell says %q and the kind %q is not one of the closed words", r.Observer, r.ObserverKind)
			}
			if r.ObserverKind == ObserverPrevents {
				prevents++
				if r.ID != "target_only" || !strings.Contains(r.Observer, "limited to the model proxy") {
					t.Errorf("%s prevents, but only the network rule while the network is limited to the model proxy does", r.ID)
				}
			}
		})
	}
	if prevents != 1 {
		t.Errorf("%d rows prevent, want exactly 1", prevents)
	}
	// The closed list: three words, no repeats, "" is not one of them.
	if len(ObserverEffects) != 3 || ObserverEffect("").Valid() || ObserverEffect("blocks").Valid() {
		t.Errorf("effects = %v", ObserverEffects)
	}
	for _, w := range []ObserverEffect{ObserverPrevents, ObserverDetects, ObserverStops} {
		if !w.Valid() || string(w) != strings.ToLower(string(w)) {
			t.Errorf("%q is not a valid lower-case word", w)
		}
	}
	// PromptOnly stays derived from the cells: it never reads the kind.
	if (SafetyRow{Prompt: true, Helper: "-", Observer: "-", ObserverKind: ObserverStops}).PromptOnly() != true {
		t.Error("PromptOnly reads the kind")
	}
	if (SafetyRow{Prompt: true, Helper: "-", Observer: "a check"}).PromptOnly() {
		t.Error("PromptOnly ignores the Observer cell")
	}
}

// TestSafetyRowsFor: without the helper every Helper cell is "-" and a rule no
// Observer check holds reads prompt only; with it the table is SafetyRows.
func TestSafetyRowsFor(t *testing.T) {
	on := SafetyRowsFor(true)
	off := SafetyRowsFor(false)
	if len(on) != len(SafetyRows) || len(off) != len(SafetyRows) {
		t.Fatalf("rows: %d and %d, want %d", len(on), len(off), len(SafetyRows))
	}
	for i, r := range off {
		if r.Helper != "-" {
			t.Errorf("%s: helper cell %q with the helper off", r.ID, r.Helper)
		}
		if on[i].Helper != SafetyRows[i].Helper || on[i].Observer != SafetyRows[i].Observer || r.Rule != SafetyRows[i].Rule {
			t.Errorf("%s: the table changed apart from the helper cell", r.ID)
		}
		// A row whose Observer check reads the helper's log has nothing to read.
		if r.NeedsHelper != (r.Observer == "-" && SafetyRows[i].Observer != "-") || (r.NeedsHelper && r.ObserverKind != "") {
			t.Errorf("%s: observer cell %q with the helper off", r.ID, r.Observer)
		}
		if r.Observer != SafetyRows[i].Observer && !r.NeedsHelper {
			t.Errorf("%s: the Observer cell changed", r.ID)
		}
	}
	// Without the helper the lockout rule has no check at all.
	for _, r := range off {
		if r.ID == "lockout" && !r.PromptOnly() {
			t.Error("lockout without the helper must read prompt only")
		}
	}
	// SafetyRowsFor never changes the shared table.
	for _, r := range SafetyRows {
		if r.ID == "lockout" && r.Helper == "-" {
			t.Error("SafetyRowsFor wrote into SafetyRows")
		}
	}
}
