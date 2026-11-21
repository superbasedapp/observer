package nontx

import (
	"reflect"
	"testing"
	"time"
)

// TestDecideRows has one case per resumeRules row (the rule name pins which
// row decided), plus the fall-through cases each kind reaches.
func TestDecideRows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind  Kind
		facts Facts
		want  Resume
	}{
		{
			KindCreateIndex,
			Facts{Exists: true, Valid: true, OnTable: false, Name: "s.ix"},
			Resume{Action: ActionRefuse, Rule: "index name held by an index on another table"},
		},
		{
			KindCreateIndex,
			Facts{Exists: true, Valid: true, OnTable: true, Name: "s.ix"},
			Resume{Action: ActionRecord, Rule: "index finished by an earlier run"},
		},
		{
			KindCreateIndex,
			Facts{Exists: true, Valid: false, OnTable: true, Name: "s.ix"},
			Resume{Action: ActionRun, Drop: []string{"s.ix"}, Rule: "invalid index left by an interrupted run"},
		},
		{
			KindDropIndex,
			Facts{},
			Resume{Action: ActionRecord, Rule: "index dropped by an earlier run"},
		},
		{
			KindReindexIndex,
			Facts{Leftovers: []string{"s.ix_ccnew"}},
			Resume{Action: ActionRun, Drop: []string{"s.ix_ccnew"}, Rule: "invalid leftovers of an interrupted reindex"},
		},
		{
			KindReindexTable,
			Facts{Leftovers: []string{"s.a_ccnew", "s.b_ccold"}},
			Resume{Action: ActionRun, Drop: []string{"s.a_ccnew", "s.b_ccold"}, Rule: "invalid leftovers of an interrupted reindex"},
		},
		{
			KindCreateIndex,
			Facts{},
			Resume{Action: ActionRun, Rule: "pending"},
		},
		{
			KindDropIndex,
			Facts{Exists: true, Valid: false, Name: "s.ix"},
			Resume{Action: ActionRun, Rule: "pending"},
		},
		{
			KindReindexIndex,
			Facts{},
			Resume{Action: ActionRun, Rule: "pending"},
		},
		// Leftovers are a REINDEX fact: a CREATE never drops them.
		{
			KindCreateIndex,
			Facts{Leftovers: []string{"s.ix_ccnew"}},
			Resume{Action: ActionRun, Rule: "pending"},
		},
	} {
		if got := Decide(tc.kind, tc.facts); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Decide(%s, %+v) = %+v, want %+v", tc.kind, tc.facts, got, tc.want)
		}
	}
	// Every row is reached by a case above.
	reached := map[string]bool{}
	for _, r := range resumeRules {
		reached[r.name] = false
	}
	for _, tc := range []struct {
		k Kind
		f Facts
	}{
		{KindCreateIndex, Facts{Exists: true}},
		{KindCreateIndex, Facts{Exists: true, Valid: true, OnTable: true}},
		{KindCreateIndex, Facts{Exists: true, OnTable: true}},
		{KindDropIndex, Facts{}},
		{KindReindexTable, Facts{Leftovers: []string{"x"}}},
		{KindReindexIndex, Facts{}},
	} {
		reached[Decide(tc.k, tc.f).Rule] = true
	}
	for name, ok := range reached {
		if !ok {
			t.Errorf("resume row %q has no test case", name)
		}
	}
}

// TestRetryNext has one case per retryRules row and per outcome.
func TestRetryNext(t *testing.T) {
	t.Parallel()
	p := RetryPolicy{MaxAttempts: 4, Base: time.Second, Cap: 3 * time.Second}
	for _, tc := range []struct {
		name     string
		attempt  int
		sqlstate string
		want     Retry
	}{
		{"lock_timeout row, first wait is Base", 1, "55P03", Retry{Again: true, Wait: time.Second, Rule: "lock_not_available (lock_timeout expired)"}},
		{"deadlock row, the wait doubles", 2, "40P01", Retry{Again: true, Wait: 2 * time.Second, Rule: "deadlock_detected"}},
		{"the wait is capped", 3, "55P03", Retry{Again: true, Wait: 3 * time.Second, Rule: "lock_not_available (lock_timeout expired)"}},
		{"attempts exhausted", 4, "55P03", Retry{Rule: "lock_not_available (lock_timeout expired): attempts exhausted"}},
		{"a unique violation is not retryable", 1, "23505", Retry{Rule: "not retryable"}},
		{"statement_timeout is not retryable", 1, "57014", Retry{Rule: "not retryable"}},
		{"no sqlstate is not retryable", 1, "", Retry{Rule: "not retryable"}},
	} {
		if got := p.Next(tc.attempt, tc.sqlstate); got != tc.want {
			t.Errorf("%s: Next(%d, %q) = %+v, want %+v", tc.name, tc.attempt, tc.sqlstate, got, tc.want)
		}
	}
	// A large attempt number never overflows the wait past the cap.
	if got := (RetryPolicy{MaxAttempts: 1000, Base: time.Second, Cap: time.Minute}).Next(999, "55P03"); got.Wait != time.Minute {
		t.Errorf("Next(999) wait = %v, want the cap", got.Wait)
	}
	if d := DefaultRetryPolicy(); d.MaxAttempts < 1 || d.Base <= 0 || d.Cap < d.Base {
		t.Errorf("DefaultRetryPolicy = %+v is not a usable policy", d)
	}
}
