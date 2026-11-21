package secassess

import "fmt"

// The pen-test safety table (depth plan W4.6, with the helper column filled by
// W5b): each rule the prompt states and the places where something other than
// the prompt holds it. The honest reading of a row is its cells: a "-" is no
// enforcement point, and a row with "-" in both the helper and the Observer cell
// is prompt only, which the card says in those words.

// ObserverEffect is what Observer's own check does about a rule, in one closed
// word, so a surface never has to read it out of the cell's sentence. A rule
// whose Observer cell is "-" has none.
type ObserverEffect string

// The effects.
const (
	// ObserverPrevents: something Observer built stops the action before it
	// happens (the box's own network when it is limited to the model proxy).
	ObserverPrevents ObserverEffect = "prevents"
	// ObserverDetects: Observer looks afterwards and tells the developer what it
	// saw (the git check after the run); it does not stop anything.
	ObserverDetects ObserverEffect = "detects"
	// ObserverStops: Observer gives the developer a way to end the run (the
	// deadline and the Stop button); the run itself keeps going until they use it,
	// unless the setting that closes it automatically is on.
	ObserverStops ObserverEffect = "stops"
)

// ObserverEffects is the closed list, in the order a surface may sort by
// strength.
var ObserverEffects = []ObserverEffect{ObserverPrevents, ObserverDetects, ObserverStops}

// Valid reports whether e is one of the effects.
func (e ObserverEffect) Valid() bool {
	for _, k := range ObserverEffects {
		if e == k {
			return true
		}
	}
	return false
}

// SafetyRow is one row of the pen-test safety table: a rule and where it is
// enforced. A cell that says "-" means no enforcement point exists there, and
// the card says "prompt only" for a rule with only the prompt column.
type SafetyRow struct {
	ID       string
	Rule     string
	Prompt   bool
	Helper   string
	Observer string
	// ObserverKind is what the Observer cell does, as a closed word; "" exactly
	// when the cell is "-". Only the network rule under proxy_only prevents.
	ObserverKind ObserverEffect
	// NeedsHelper says the Observer cell reads the request helper's log, so a
	// run without the helper has nothing for it to read and the cell is "-".
	NeedsHelper bool
}

// SafetyRows is the safety table as it reads when the request helper is on
// (depth plan W5b); SafetyRowsFor gives the table for a run without one.
//
// The Helper column names what the helper script enforces, in the same plain
// words the prompt and the plan use, and nothing it does not: it refuses an
// address that is not the target's, it reads and keeps a bounded part of a
// response, it waits and counts for the pace and the budget, and it counts
// attempts per account for the lockout rule. It is a script the agent runs: the
// agent can bypass it by sending a request some other way, which the card says
// ("a request sent any other way is not logged"), so no cell calls it a
// barrier. The Observer column holds the enforcement locus in plain words and
// never claims more than the plan's table: the box's network namespace only
// under proxy_only, the git check only for tracked-file edits, the evidence
// check only counts what the log holds, and the workspace secret mask (only when
// it is in force for the run, SafetyRowsWith) only the names it recognises.
// ObserverKind says in one closed word what that check does (prevents, detects afterwards, gives a way to stop), so
// no surface describes the deadline or the git check as holding a rule.
var SafetyRows = []SafetyRow{
	{
		ID: "target_only", Rule: "Send requests to the target address only: no other host, port or address.",
		Prompt: true, Helper: "refuses any address that is not the target's", Observer: "the box's own network when it is limited to the model proxy, and the address checks made before the run starts", ObserverKind: ObserverPrevents,
	},
	{
		ID: "no_destructive", Rule: "Do not delete or overwrite data that is not a test account's; no denial of service; no bulk exfiltration (excerpts only).",
		Prompt: true, Helper: "reads at most 64 KiB of a response and keeps 1 KiB of it", Observer: "the git check sees tracked-file edits only, not ignored files, databases or caches", ObserverKind: ObserverDetects,
	},
	{
		ID: "pace_budget", Rule: "Stay within the request pace and the request budget set for the run.",
		Prompt: true, Helper: "waits between requests and refuses past the budget, and logs the refusal", Observer: "the check counts the requests the log holds", ObserverKind: ObserverDetects, NeedsHelper: true,
	},
	{
		ID: "lockout", Rule: fmt.Sprintf("Test lockout only on accounts you created, at most %d attempts each.", lockoutAttempts),
		Prompt: true, Helper: "counts attempts when a request names an account, per path, and refuses the eleventh; a guard rail, not a barrier", Observer: "-",
	},
	{
		ID: "time_box", Rule: "Finish inside the time box.",
		Prompt: true, Helper: "-", Observer: "the deadline and the Stop button", ObserverKind: ObserverStops,
	},
	{
		ID: "stop_conditions", Rule: "Stop and report when a stop condition holds.",
		Prompt: true, Helper: "-", Observer: "-",
	},
	{
		ID: "no_credentials", Rule: "Use no real credentials and do not open .env files.",
		Prompt: true, Helper: "-", Observer: "-",
	},
}

// SafetyRowsFor returns the safety table for a run: with the helper on it is
// SafetyRows; without one (the setting is off, or python3 was not seen in the
// box) the Helper column is "-" in every row, because nothing of the helper
// holds, and so is the Observer cell of a row that reads the helper's log; a
// rule only the prompt holds says so.
func SafetyRowsFor(helper bool) []SafetyRow {
	out := make([]SafetyRow, len(SafetyRows))
	copy(out, SafetyRows)
	if !helper {
		for i := range out {
			out[i].Helper = "-"
			if out[i].NeedsHelper {
				out[i].Observer, out[i].ObserverKind = "-", ""
			}
		}
	}
	return out
}

// SafetyFacts are the facts about a run the safety table depends on.
type SafetyFacts struct {
	// Helper: the request helper is written for the run (SafetyRowsFor).
	Helper bool
	// Mask: the sandbox hides the workspace's secret files for the run (the
	// effective workspace_secret_mode is mask, decision D32).
	Mask bool
}

// maskedSafety is the table of Observer cells a row has when the workspace
// secret mask is in force; a row not in it is the same with or without the mask.
// The cell says what the mask is (names, a snapshot) and not more, so the row no
// longer reads "prompt only" but never reads as a barrier for what the names do
// not cover.
var maskedSafety = map[string]struct {
	Observer string
	Kind     ObserverEffect
}{
	"no_credentials": {
		Observer: "the sandbox hides environment and key files by name inside the box, a snapshot taken when it starts; what it could not hide is listed once the run has started",
		Kind:     ObserverPrevents,
	},
}

// SafetyRowsWith returns the safety table for a run under its facts: SafetyRowsFor
// for the helper, and with the mask in force the Observer cell of the rules the
// mask holds. The shared SafetyRows is never changed.
func SafetyRowsWith(f SafetyFacts) []SafetyRow {
	out := SafetyRowsFor(f.Helper)
	if !f.Mask {
		return out
	}
	for i := range out {
		if m, ok := maskedSafety[out[i].ID]; ok {
			out[i].Observer, out[i].ObserverKind = m.Observer, m.Kind
		}
	}
	return out
}

// PromptOnly reports whether the rule is held by the prompt alone.
func (r SafetyRow) PromptOnly() bool { return r.Prompt && r.Helper == "-" && r.Observer == "-" }
