package migplan

import (
	"reflect"
	"strconv"
	"testing"
)

// commitScenario is one database state a per-step runner can meet.
type commitScenario struct {
	name     string
	embedded []int
	ledger   map[string]string
	// late maps each late step to its probe result before the run.
	late map[int]bool
}

// commitScenarios covers every horizon and step rule of Decide that a
// per-step run can interrupt, one row each.
var commitScenarios = []commitScenario{
	{name: "fresh database", embedded: []int{1, 2, 3, 4, 5}},
	{name: "empty lineage on a fresh database", embedded: nil},
	{
		name:     "pre-ledger database adopts up to its version and runs the rest",
		embedded: []int{1, 2, 3, 4, 5},
		ledger:   map[string]string{VersionKey: "3"},
	},
	{
		name:     "pre-ledger database that never ran late step 2",
		embedded: []int{1, 2, 3, 4, 5},
		ledger:   map[string]string{VersionKey: "3"},
		late:     map[int]bool{2: false},
	},
	{
		name:     "pre-ledger database that did run late step 2",
		embedded: []int{1, 2, 3, 4, 5},
		ledger:   map[string]string{VersionKey: "3"},
		late:     map[int]bool{2: true},
	},
	{
		name:     "ledger database with an interleaved step below its maximum",
		embedded: []int{1, 2, 3, 4, 5, 6, 7, 8},
		ledger:   ledgerRows(7, 0, map[int]string{1: RecordApplied, 2: RecordApplied, 3: RecordApplied, 4: RecordApplied, 5: RecordApplied, 7: RecordApplied}),
	},
	{
		name:     "rewound version record forgets the records above it and re-runs them",
		embedded: []int{1, 2, 3, 4, 5},
		ledger:   ledgerRows(3, 5, map[int]string{1: RecordAdopted, 2: RecordAdopted, 3: RecordAdopted, 4: RecordAdopted, 5: RecordAdopted}),
	},
	{
		name:     "adopted late step whose probe disproves it runs",
		embedded: []int{1, 2, 3, 4},
		ledger:   ledgerRows(3, 3, map[int]string{1: RecordAdopted, 2: RecordAdopted, 3: RecordAdopted}),
		late:     map[int]bool{2: false},
	},
	{
		name:     "pre-ledger runner advanced a ledger database",
		embedded: []int{1, 2, 3, 4, 5, 6, 7, 8},
		ledger:   ledgerRows(6, 3, map[int]string{1: RecordApplied, 2: RecordApplied, 3: RecordApplied}),
	},
	{
		name:     "late step present above the version record is adopted and raises it",
		embedded: []int{1, 2, 3, 4, 5},
		ledger:   ledgerRows(2, 2, map[int]string{1: RecordApplied, 2: RecordApplied}),
		late:     map[int]bool{4: true},
	},
	{
		name:     "database already at the head",
		embedded: []int{1, 2, 3},
		ledger:   ledgerRows(3, 0, map[int]string{1: RecordApplied, 2: RecordApplied, 3: RecordApplied}),
	},
}

func ledgerRows(version, horizon int, steps map[int]string) map[string]string {
	rows := map[string]string{VersionKey: strconv.Itoa(version), HorizonKey: strconv.Itoa(horizon)}
	for v, r := range steps {
		rows[StepKey(v)] = r
	}
	return rows
}

// store is a simulated schema_meta plus the schema the late-step probes see.
type store struct {
	rows map[string]string
	late map[int]bool
}

func newStore(sc commitScenario) *store {
	s := &store{rows: map[string]string{}, late: map[int]bool{}}
	for k, v := range sc.ledger {
		s.rows[k] = v
	}
	for k, v := range sc.late {
		s.late[k] = v
	}
	return s
}

func (s *store) decide(t *testing.T, embedded []int) Plan {
	t.Helper()
	l, err := ParseLedger(s.rows)
	if err != nil {
		t.Fatalf("ParseLedger: %v", err)
	}
	p, err := Decide(Input{Embedded: embedded, Ledger: l, Late: s.late})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	return p
}

// record notes a step's record and, for a run step, the schema it creates.
func (s *store) record(st Step) {
	s.rows[StepKey(st.Version)] = st.Action.Record()
	if _, late := s.late[st.Version]; late && st.Action == ActionRun {
		s.late[st.Version] = true
	}
}

// commit applies one Commit the way a per-step runner's transaction does.
func (s *store) commit(c Commit) {
	for _, v := range c.Forget {
		delete(s.rows, StepKey(v))
	}
	if c.WriteHorizon {
		s.rows[HorizonKey] = strconv.Itoa(c.Horizon)
	}
	for _, st := range c.Steps {
		s.record(st)
	}
	if c.WriteVersion {
		s.rows[VersionKey] = strconv.Itoa(c.Version)
	}
}

// batch applies a whole Plan the way the single-transaction runners do.
func (s *store) batch(p Plan) {
	for _, v := range p.Forget {
		delete(s.rows, StepKey(v))
	}
	if p.WriteHorizon {
		s.rows[HorizonKey] = strconv.Itoa(p.Horizon)
	}
	for _, st := range p.Steps {
		s.record(st)
	}
	if p.WriteVersion {
		s.rows[VersionKey] = strconv.Itoa(p.Version)
	}
}

// TestCommitsMatchTheSingleBatch pins that running every commit leaves the
// ledger one transaction over the whole plan leaves, one case per scenario.
func TestCommitsMatchTheSingleBatch(t *testing.T) {
	t.Parallel()
	for _, sc := range commitScenarios {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			perStep, single := newStore(sc), newStore(sc)
			plan := perStep.decide(t, sc.embedded)
			for _, c := range plan.Commits() {
				perStep.commit(c)
			}
			single.batch(plan)
			if !reflect.DeepEqual(perStep.rows, single.rows) {
				t.Fatalf("per-step ledger %v, single-batch ledger %v", perStep.rows, single.rows)
			}
			if again := perStep.decide(t, sc.embedded); !again.Noop() {
				t.Fatalf("a completed per-step run plans more work: %+v", again)
			}
		})
	}
}

// TestCommitsResumeAtTheNextUnappliedStep is plan 07 row M3a.0's proof
// without a database: stopping after any commit leaves a ledger whose plan is
// exactly the run steps that did not commit, and finishing from there lands
// on the uninterrupted ledger.
func TestCommitsResumeAtTheNextUnappliedStep(t *testing.T) {
	t.Parallel()
	for _, sc := range commitScenarios {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			whole := newStore(sc)
			plan := whole.decide(t, sc.embedded)
			commits := plan.Commits()
			for _, c := range commits {
				whole.commit(c)
			}
			for k := 1; k <= len(commits); k++ {
				s := newStore(sc)
				for _, c := range commits[:k] {
					s.commit(c)
				}
				var wantRuns []int
				for _, c := range commits[k:] {
					wantRuns = append(wantRuns, c.Steps[0].Version)
				}
				resumed := s.decide(t, sc.embedded)
				if got := resumed.RunVersions(); !reflect.DeepEqual(got, wantRuns) {
					t.Fatalf("after %d of %d commits the resumed plan runs %v, want %v", k, len(commits), got, wantRuns)
				}
				if len(resumed.Steps) != len(wantRuns) || len(resumed.Forget) != 0 || resumed.WriteHorizon {
					t.Fatalf("after %d of %d commits the resumed plan does bookkeeping again: %+v", k, len(commits), resumed)
				}
				for _, c := range resumed.Commits() {
					s.commit(c)
				}
				if !reflect.DeepEqual(s.rows, whole.rows) {
					t.Fatalf("after %d of %d commits and a resume the ledger is %v, want %v", k, len(commits), s.rows, whole.rows)
				}
			}
		})
	}
}

// TestCommitsShape pins the split itself, one case per shape.
func TestCommitsShape(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		plan Plan
		want []Commit
	}{
		{
			name: "a noop plan is one empty ledger commit",
			plan: Plan{Prior: 3, Version: 3},
			want: []Commit{{Version: 3}},
		},
		{
			name: "fresh lineage: an empty ledger commit with the horizon, then one commit per step",
			plan: Plan{Steps: run(1, 2), WriteHorizon: true, Version: 2, WriteVersion: true},
			want: []Commit{
				{WriteHorizon: true},
				{Steps: run(1), Version: 1, WriteVersion: true},
				{Steps: run(2), Version: 2, WriteVersion: true},
			},
		},
		{
			name: "adopted steps ride the ledger commit ahead of a lower run step",
			plan: Plan{
				Prior: 3, Steps: []Step{{1, ActionAdopt, ""}, {2, ActionRun, ""}, {3, ActionAdopt, ""}, {4, ActionRun, ""}},
				Horizon: 3, WriteHorizon: true, Version: 4, WriteVersion: true,
			},
			want: []Commit{
				{Horizon: 3, WriteHorizon: true, Steps: adopt(1, 3), Version: 3},
				{Steps: run(2), Version: 3},
				{Steps: run(4), Version: 4, WriteVersion: true},
			},
		},
		{
			name: "forgotten records leave in the ledger commit",
			plan: Plan{Prior: 3, Forget: []int{4, 5}, Steps: run(4, 5), Horizon: 3, WriteHorizon: true, Version: 5, WriteVersion: true},
			want: []Commit{
				{Forget: []int{4, 5}, Horizon: 3, WriteHorizon: true, Version: 3},
				{Steps: run(4), Version: 4, WriteVersion: true},
				{Steps: run(5), Version: 5, WriteVersion: true},
			},
		},
		{
			name: "an adopted step above the version record raises it in the ledger commit",
			plan: Plan{Prior: 2, Steps: []Step{{3, ActionRun, ""}, {4, ActionAdopt, ""}}, Version: 4, WriteVersion: true},
			want: []Commit{
				{Steps: adopt(4), Version: 4, WriteVersion: true},
				{Steps: run(3), Version: 4},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.plan.Commits(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Commits()\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}
