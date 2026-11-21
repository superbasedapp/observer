package nontx

// Facts is what the runner read from the catalogue before an attempt
// (Statement.Probe says which read).
type Facts struct {
	// Exists reports that the statement's index exists (ProbeIndex).
	Exists bool
	// Valid reports that the existing index is valid (pg_index.indisvalid).
	Valid bool
	// OnTable reports that the existing index is on the statement's table
	// (ProbeIndex for a CREATE INDEX).
	OnTable bool
	// Name is the existing index, schema-qualified and quoted by the
	// catalogue, when Exists.
	Name string
	// Leftovers lists the invalid _ccnew/_ccold indexes an interrupted
	// REINDEX CONCURRENTLY left on the target, schema-qualified and quoted
	// by the catalogue (ProbeLeftovers).
	Leftovers []string
}

// Action is what the runner does with the step after the probe.
type Action string

const (
	// ActionRun executes the statement, after dropping Resume.Drop.
	ActionRun Action = "run"
	// ActionRecord records the step without executing it: an earlier run
	// finished the statement and died before its ledger record committed.
	ActionRecord Action = "record"
	// ActionRefuse stops the run: the catalogue holds something the step
	// cannot safely adopt or replace.
	ActionRefuse Action = "refuse"
)

// Resume is the decision for one attempt.
type Resume struct {
	Action Action
	// Drop lists the invalid indexes to drop (DROP INDEX CONCURRENTLY IF
	// EXISTS) before the statement runs.
	Drop []string
	// Rule names the resumeRules row that decided.
	Rule string
}

// resumeRule is one row of the resume table.
type resumeRule struct {
	name    string
	applies func(k Kind, f Facts) bool
	action  Action
	drop    func(f Facts) []string
}

// resumeRules is THE ordered resume table, walked top-down, first match wins.
var resumeRules = []resumeRule{
	{
		// The name is taken by an index on another table: recording would
		// claim an index this step never built, and dropping it would destroy
		// someone else's index.
		name:    "index name held by an index on another table",
		applies: func(k Kind, f Facts) bool { return k == KindCreateIndex && f.Exists && !f.OnTable },
		action:  ActionRefuse,
	},
	{
		name:    "index finished by an earlier run",
		applies: func(k Kind, f Facts) bool { return k == KindCreateIndex && f.Exists && f.Valid },
		action:  ActionRecord,
	},
	{
		// An interrupted or failed CREATE INDEX CONCURRENTLY leaves its index
		// behind marked invalid; IF NOT EXISTS would keep it, and without IF
		// NOT EXISTS the build fails on the name. Drop it, then build again.
		name:    "invalid index left by an interrupted run",
		applies: func(k Kind, f Facts) bool { return k == KindCreateIndex && f.Exists && !f.Valid },
		action:  ActionRun,
		drop:    func(f Facts) []string { return []string{f.Name} },
	},
	{
		name:    "index dropped by an earlier run",
		applies: func(k Kind, f Facts) bool { return k == KindDropIndex && !f.Exists },
		action:  ActionRecord,
	},
	{
		// An interrupted REINDEX CONCURRENTLY leaves <name>_ccnew (and after
		// the swap <name>_ccold) invalid; they hold no data a rebuild needs.
		name: "invalid leftovers of an interrupted reindex",
		applies: func(k Kind, f Facts) bool {
			return (k == KindReindexIndex || k == KindReindexTable) && len(f.Leftovers) > 0
		},
		action: ActionRun,
		drop:   func(f Facts) []string { return append([]string(nil), f.Leftovers...) },
	},
	{
		name:    "pending",
		applies: func(Kind, Facts) bool { return true },
		action:  ActionRun,
	},
}

// Decide returns what the runner does with a statement of kind k given the
// catalogue facts. It is a pure function of its input.
func Decide(k Kind, f Facts) Resume {
	for _, r := range resumeRules {
		if !r.applies(k, f) {
			continue
		}
		out := Resume{Action: r.action, Rule: r.name}
		if r.drop != nil {
			out.Drop = r.drop(f)
		}
		return out
	}
	return Resume{Action: ActionRun, Rule: "pending"}
}
