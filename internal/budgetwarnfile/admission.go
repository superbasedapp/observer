package budgetwarnfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// THE HOOK-PATH BUDGET ADMISSION FILE (T-519, D-332).
//
// An exhausted organization hard budget used to stop only the work Observer
// could see on its own transport: proxied requests (the guard's proxy check),
// launches (the launch gate) and the processes the node can bind by exact
// executable identity (the process controller). A tool whose model calls go to
// its vendor directly, and whose process the controller could not bind (Cursor
// on the demo estate: a shell-script launcher that execs a bundled node), kept
// answering prompts at 133% of a blocking cap. Its pre-send hooks fired on every
// prompt and every tool call, and answered allow, because a hook process never
// measured spend (the lookup lives in the daemon, and a per-call managed spend
// read would cost a second or more inside the vendor's hook timeout).
//
// This file is how the hook path gets the SAME decision without measuring
// anything: the daemon publishes the managed budget decision the process
// controller and the launch gate already ask (guard.CheckInterventionBudget,
// one owner for the number), and every hook process reads it with one small
// file read before its reply. It is a decision, not a warning, so it lives
// beside budget-status.json rather than inside it: the warning file is
// rewritten on the warn ladder's cadence and keeps its last evaluation when a
// measurement is unavailable, which is the right rule for a warning and the
// wrong one for a stop.
//
// Ownership (CLAUDE.md #4): ONE writer, the daemon's budget service
// (cmd/observer/budgetwarn_wire.go publishAdmission). Hook processes only read.

// AdmissionFilename is the basename, placed beside the DB (the same placement
// rule as budget-status.json, so a cross-OS hook bridge resolves the same
// file).
const AdmissionFilename = "budget-admission.json"

// AdmissionSchema is the admission file's schema version.
const AdmissionSchema = 1

// Stop is one managed budget denial the hook path must enforce.
type Stop struct {
	// Tool scopes the stop to one tool (the organization's per-tool cap,
	// normalized: trimmed, lower-cased). Empty stops every tool.
	Tool string `json:"tool,omitempty"`
	// RuleID is the budget rule that denied (B-602, B-622, B-626, B-625, ...).
	RuleID string `json:"rule_id"`
	// Reason is the developer-facing reason, already rendered by the daemon in
	// the organization's terms and the developer cost display.
	Reason string `json:"reason"`
	// ValidUntil is the exclusive instant the decision stops applying (the next
	// calendar boundary for a daily or monthly cap). Zero means the decision
	// does not clear on a clock boundary (an unavailable-accounting or
	// required-budget denial, a session or subject cap): it holds until the
	// daemon writes a new decision.
	ValidUntil time.Time `json:"valid_until,omitempty"`
}

// Admission is budget-admission.json.
type Admission struct {
	Schema    int       `json:"schema"`
	WrittenAt time.Time `json:"written_at"`
	// Stops is every managed budget denial in force. Empty means nothing is
	// stopped.
	Stops []Stop `json:"stops,omitempty"`
}

// AdmissionPath returns the admission file path beside dbPath ("" when dbPath
// is empty).
func AdmissionPath(dbPath string) string {
	if dbPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(dbPath), AdmissionFilename)
}

// ReadAdmission loads an admission file. A missing file is (nil, nil): the
// daemon has never published a stop on this node. A malformed or foreign-schema
// file is an error.
func ReadAdmission(path string) (*Admission, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("budgetwarnfile.ReadAdmission: %w", err)
	}
	defer func() { _ = f.Close() }()
	var out Admission
	if err := json.NewDecoder(&limitedReader{r: f, n: maxStatusBytes}).Decode(&out); err != nil {
		return nil, fmt.Errorf("budgetwarnfile.ReadAdmission: %w", err)
	}
	if out.Schema != AdmissionSchema {
		return nil, errors.New("budgetwarnfile: unsupported admission schema")
	}
	return &out, nil
}

// WriteAdmission replaces the admission file atomically (temp + rename), mode
// 0600.
func WriteAdmission(path string, a Admission) error {
	if path == "" {
		return errors.New("budgetwarnfile: empty path")
	}
	a.Schema = AdmissionSchema
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("budgetwarnfile.WriteAdmission: %w", err)
	}
	return writeAtomic(path, data)
}

// AdmissionMaxAge is how old a published decision may be and still stop a
// hook (D-359, adversarial review P3-05). The daemon re-writes a file that
// carries a stop at least every AdmissionRefresh, so a live publisher keeps
// it well inside this bound; a file older than it has no live publisher (the
// daemon stopped, the node left its organization, [org_client] was turned
// off) and its stops are not in force. A stop with no ValidUntil (B-625, an
// unavailable-accounting denial) would otherwise hold forever on a node that
// nothing manages any more.
const AdmissionMaxAge = 2 * time.Minute

// AdmissionRefresh is how often the daemon re-writes a file that carries a
// stop even when the decision did not change, so its WrittenAt stays fresh.
// It is a quarter of AdmissionMaxAge: three missed refreshes still stop.
const AdmissionRefresh = AdmissionMaxAge / 4

// Stale reports whether the file is too old (or carries no usable WrittenAt)
// for its stops to be in force at now. A WrittenAt further in the future
// than AdmissionMaxAge is stale too: a clock that ran backwards must not
// extend a stop.
func (a *Admission) Stale(now time.Time) bool {
	if a == nil || a.WrittenAt.IsZero() {
		return true
	}
	age := now.Sub(a.WrittenAt)
	return age > AdmissionMaxAge || age < -AdmissionMaxAge
}

// StopFor returns the first stop in force for tool at now: a node-wide stop
// (Tool empty) or one scoped to this tool. A stop whose ValidUntil has passed is
// not in force (its period ended; the daemon has not rewritten the file yet),
// and no stop of a Stale file is in force. The comparison is on the normalized
// tool id, the spelling the organization's per-tool cap is keyed by.
func (a *Admission) StopFor(tool string, now time.Time) (Stop, bool) {
	if a == nil || a.Stale(now) {
		return Stop{}, false
	}
	norm := NormalizeTool(tool)
	for _, s := range a.Stops {
		if s.RuleID == "" {
			continue
		}
		if !s.ValidUntil.IsZero() && !now.Before(s.ValidUntil) {
			continue
		}
		if s.Tool != "" && s.Tool != norm {
			continue
		}
		return s, true
	}
	return Stop{}, false
}

// NormalizeTool folds a tool id onto the spelling a per-tool stop is keyed by:
// trimmed, ASCII-lowered (guard.NormalizeBudgetSubjectID's rule, restated here
// because this package is read on the hook path and stays stdlib-only).
func NormalizeTool(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// SameStops reports whether two admissions carry the same stops, ignoring
// WrittenAt, so an unchanged decision does not rewrite the file.
func SameStops(a, b []Stop) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Tool != b[i].Tool || a[i].RuleID != b[i].RuleID || a[i].Reason != b[i].Reason ||
			!a[i].ValidUntil.Equal(b[i].ValidUntil) {
			return false
		}
	}
	return true
}
