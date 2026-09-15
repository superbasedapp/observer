package processobs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestClassifySinkError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want SinkErrorClass
	}{
		{"nil carries no class", nil, SinkErrorUnknown},

		// Transient — the failures the 9c fix exists for.
		{"sqlite busy message", errors.New("database is locked (5)"), SinkErrorTransient},
		{
			"sqlite busy wrapped by the store seam",
			fmt.Errorf("store.PersistRuns: exec[3]: %w", errors.New("database is locked")), SinkErrorTransient,
		},
		{"table-level lock", errors.New("database table is locked: process_runs"), SinkErrorTransient},
		{"symbolic code", errors.New("SQLITE_BUSY"), SinkErrorTransient},
		{"busy handler deadline", errors.New("busy_timeout exceeded"), SinkErrorTransient},
		{"structured context deadline", context.DeadlineExceeded, SinkErrorTransient},
		{"structured context cancel", context.Canceled, SinkErrorTransient},
		{
			"wrapped context deadline still structural",
			fmt.Errorf("store.PersistRuns: begin: %w", context.DeadlineExceeded), SinkErrorTransient,
		},
		{"stalled mount", errors.New("read tcp 10.0.0.1:0: i/o timeout"), SinkErrorTransient},

		// Permanent — the small, certain set.
		{"constraint violation", errors.New("constraint failed: UNIQUE process_runs.process_key"), SinkErrorPermanent},
		{"missing table", errors.New("no such table: process_runs"), SinkErrorPermanent},
		{"missing column", errors.New("no such column: exe_basename"), SinkErrorPermanent},
		{"read-only handle", errors.New("attempt to write a readonly database"), SinkErrorPermanent},
		{"type mismatch", errors.New("datatype mismatch"), SinkErrorPermanent},
		{"closed statement", errors.New("sql: statement is closed"), SinkErrorPermanent},

		// Unknown — the ambiguous ones stay ambiguous ON PURPOSE. Each of
		// these LOOKS fatal and routinely clears on its own, so classifying
		// them permanent would convert a recoverable hiccup into real loss.
		{"disk i/o error is ambiguous, not fatal", errors.New("disk I/O error (10)"), SinkErrorUnknown},
		{"full disk may free up", errors.New("database or disk is full"), SinkErrorUnknown},
		{"an unrecognised failure", errors.New("something nobody has seen before"), SinkErrorUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ClassifySinkError(tc.err); got != tc.want {
				t.Errorf("ClassifySinkError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestSinkErrorClassRetain pins the asymmetry the whole design rests on:
// unknown behaves as transient, because wrongly retaining costs bounded
// memory and a counted drop, while wrongly dropping loses history for good.
func TestSinkErrorClassRetain(t *testing.T) {
	t.Parallel()
	cases := []struct {
		class SinkErrorClass
		want  bool
	}{
		{SinkErrorTransient, true},
		{SinkErrorUnknown, true},
		{SinkErrorPermanent, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.class), func(t *testing.T) {
			t.Parallel()
			if got := tc.class.Retain(); got != tc.want {
				t.Errorf("%q.Retain() = %v, want %v", tc.class, got, tc.want)
			}
		})
	}
}

// TestSinkErrorRulesAreWellFormed guards the table itself: every row needs a
// needle, a real class, a recorded justification, and a lowercase needle (the
// matcher lowercases the message, so an uppercase needle silently never
// matches — a rule that looks present and is dead).
func TestSinkErrorRulesAreWellFormed(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool, len(sinkErrorRules))
	for i, r := range sinkErrorRules {
		if r.Needle == "" {
			t.Errorf("rule[%d]: empty needle", i)
		}
		if r.Needle != strings.ToLower(r.Needle) {
			t.Errorf("rule[%d] %q: needle must be lowercase or it can never match", i, r.Needle)
		}
		if r.Class != SinkErrorTransient && r.Class != SinkErrorPermanent {
			t.Errorf("rule[%d] %q: class %q — a rule may only assert transient or permanent", i, r.Needle, r.Class)
		}
		if r.Why == "" {
			t.Errorf("rule[%d] %q: no recorded justification; an unjustified permanent rule destroys data", i, r.Needle)
		}
		if seen[r.Needle] {
			t.Errorf("rule[%d]: duplicate needle %q — the second is unreachable", i, r.Needle)
		}
		seen[r.Needle] = true
	}
}
