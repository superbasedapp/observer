package migplan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Keys the runners keep in schema_meta. VersionKey predates the ledger and
// still holds the highest applied version, so every Version() caller reads
// what it always read.
const (
	// VersionKey holds the highest applied migration version.
	VersionKey = "version"
	// HorizonKey marks a database whose ledger has been initialised. Its
	// value is the pre-ledger horizon: steps at or below it that carry no
	// per-step record were applied (or skipped) by a runner that kept no
	// per-step history, and are adopted unless a LateStep probe says
	// otherwise.
	HorizonKey = "migration_ledger_horizon"
	// StepKeyPrefix prefixes the per-step record key, e.g. "migration:240".
	StepKeyPrefix = "migration:"
)

// Values stored under a per-step key.
const (
	// RecordApplied means the runner executed the step's SQL.
	RecordApplied = "applied"
	// RecordAdopted means the runner recorded the step without executing it,
	// because the version store or a LateStep probe showed it was present.
	RecordAdopted = "adopted"
)

// StepKey returns the schema_meta key of version's per-step record.
func StepKey(version int) string { return StepKeyPrefix + strconv.Itoa(version) }

// Action is what a runner does with one embedded step.
type Action string

const (
	// ActionRun executes the step's SQL (and any Go pre/post step), then
	// records it as RecordApplied.
	ActionRun Action = "run"
	// ActionAdopt records the step as RecordAdopted without executing it.
	ActionAdopt Action = "adopt"
)

// Record returns the per-step value a runner stores after taking a.
func (a Action) Record() string {
	if a == ActionAdopt {
		return RecordAdopted
	}
	return RecordApplied
}

// LateStep names a migration known to have landed on a parallel branch under
// a number below a step another line shipped first, so a pre-ledger database
// may hold a version record above it without having run it. The probe is a
// column the step adds: present means the step ran.
type LateStep struct {
	// Version is the step's migration number in the runner's own lineage.
	Version int
	// Table and Column identify the schema the step creates.
	Table  string
	Column string
}

// Ledger is what a database's version store holds.
type Ledger struct {
	// Version is the 'version' record (0 when absent).
	Version int
	// HasHorizon reports whether the ledger has been initialised.
	HasHorizon bool
	// Horizon is the stored pre-ledger horizon (valid when HasHorizon).
	Horizon int
	// Steps holds every per-step record, keyed by version.
	Steps map[int]string
}

// ParseLedger builds a Ledger from schema_meta's key/value rows. Keys the
// ledger does not own are ignored; a malformed value under a key it does own
// is an error, never a silent zero.
func ParseLedger(rows map[string]string) (Ledger, error) {
	l := Ledger{Steps: map[int]string{}}
	for key, value := range rows {
		switch {
		case key == VersionKey:
			v, err := strconv.Atoi(value)
			if err != nil || v < 0 {
				return Ledger{}, fmt.Errorf("migplan.ParseLedger: invalid version record %q", value)
			}
			l.Version = v
		case key == HorizonKey:
			v, err := strconv.Atoi(value)
			if err != nil || v < 0 {
				return Ledger{}, fmt.Errorf("migplan.ParseLedger: invalid ledger horizon %q", value)
			}
			l.HasHorizon, l.Horizon = true, v
		case strings.HasPrefix(key, StepKeyPrefix):
			v, err := strconv.Atoi(strings.TrimPrefix(key, StepKeyPrefix))
			if err != nil || v <= 0 {
				return Ledger{}, fmt.Errorf("migplan.ParseLedger: invalid step record key %q", key)
			}
			if value != RecordApplied && value != RecordAdopted {
				return Ledger{}, fmt.Errorf("migplan.ParseLedger: invalid step record %q=%q", key, value)
			}
			l.Steps[v] = value
		}
	}
	return l, nil
}

// Input is everything Decide needs.
type Input struct {
	// Embedded lists the lineage's migration versions, strictly ascending.
	Embedded []int
	// Ledger is the database's version store.
	Ledger Ledger
	// Late maps each LateStep version the runner probed to the probe result
	// (true: the step's schema is present). A version absent from the map is
	// not a late step.
	Late map[int]bool
}

// Step is one planned action.
type Step struct {
	Version int
	Action  Action
	// Rule names the stepRules row that decided it.
	Rule string
}

// Plan is the runner's work list. Every write it implies belongs in the same
// transaction as the steps it runs.
type Plan struct {
	// Steps lists the embedded steps to run or adopt, ascending.
	Steps []Step
	// Horizon is the ledger horizon to store when WriteHorizon is set.
	Horizon      int
	WriteHorizon bool
	// Forget lists per-step records voided by a version record that was
	// rewound below them; the runner deletes them before recording Steps.
	Forget []int
	// Version is the 'version' record to store when WriteVersion is set:
	// the highest of the existing record and every planned step. It never
	// decreases.
	Version      int
	WriteVersion bool
	// NewerThanLineage reports a version record above the highest embedded
	// step (a database migrated by a newer binary).
	NewerThanLineage bool
}

// horizonRule is one row of the ordered horizon table.
type horizonRule struct {
	name    string
	applies func(l Ledger, maxStep int) bool
	horizon func(l Ledger) int
}

// horizonRules decide the pre-ledger horizon, first match wins.
var horizonRules = []horizonRule{
	{
		// A fresh database (version 0) or one written by a runner that kept
		// only the version record: everything at or below it is adopted
		// unless a late-step probe disagrees.
		name:    "uninitialised ledger: the version record is the horizon",
		applies: func(l Ledger, _ int) bool { return !l.HasHorizon },
		horizon: func(l Ledger) int { return l.Version },
	},
	{
		// The version record was lowered by hand (a replay request, which
		// tests and operators use); steps above it must run again, so the
		// horizon cannot keep adopting them.
		name:    "rewound version record lowers the horizon",
		applies: func(l Ledger, _ int) bool { return l.Version < l.Horizon },
		horizon: func(l Ledger) int { return l.Version },
	},
	{
		// A pre-ledger binary advanced the version record after the ledger
		// existed: it ran what it ran without per-step records, which is the
		// pre-ledger contract up to the new version.
		name: "pre-ledger runner advanced the version record",
		applies: func(l Ledger, maxStep int) bool {
			return l.Version > l.Horizon && l.Version > maxStep
		},
		horizon: func(l Ledger) int { return l.Version },
	},
	{
		name:    "ledger horizon unchanged",
		applies: func(Ledger, int) bool { return true },
		horizon: func(l Ledger) int { return l.Horizon },
	},
}

// stepFacts is what the step rules see for one embedded step.
type stepFacts struct {
	version  int
	recorded bool
	late     bool
	present  bool
	horizon  int
}

// stepRule is one row of the ordered per-step table. action "" means skip.
type stepRule struct {
	name    string
	applies func(f stepFacts) bool
	action  Action
}

// stepRules decide each embedded step, first match wins.
var stepRules = []stepRule{
	{name: "recorded", applies: func(f stepFacts) bool { return f.recorded }},
	{name: "late step present", applies: func(f stepFacts) bool { return f.late && f.present }, action: ActionAdopt},
	{name: "late step missing", applies: func(f stepFacts) bool { return f.late && !f.present }, action: ActionRun},
	{name: "within pre-ledger horizon", applies: func(f stepFacts) bool { return f.version <= f.horizon }, action: ActionAdopt},
	{name: "pending", applies: func(stepFacts) bool { return true }, action: ActionRun},
}

// Decide returns the plan for in. It is a pure function of its input.
func Decide(in Input) (Plan, error) {
	for i, v := range in.Embedded {
		if v <= 0 || (i > 0 && v <= in.Embedded[i-1]) {
			return Plan{}, fmt.Errorf("migplan.Decide: embedded versions must be positive and strictly ascending (got %d at index %d)", v, i)
		}
	}
	l := in.Ledger
	var plan Plan
	if n := len(in.Embedded); l.Version > 0 && (n == 0 || l.Version > in.Embedded[n-1]) {
		plan.NewerThanLineage = true
	}

	maxStep := 0
	for v := range l.Steps {
		if v > l.Version {
			plan.Forget = append(plan.Forget, v)
			continue
		}
		maxStep = max(maxStep, v)
	}
	sort.Ints(plan.Forget)

	for _, r := range horizonRules {
		if r.applies(l, maxStep) {
			plan.Horizon = r.horizon(l)
			break
		}
	}
	// An empty lineage on an uninitialised database writes nothing at all.
	plan.WriteHorizon = (!l.HasHorizon && len(in.Embedded) > 0) || (l.HasHorizon && plan.Horizon != l.Horizon)

	plan.Version = l.Version
	for _, v := range in.Embedded {
		_, recorded := l.Steps[v]
		present, late := in.Late[v]
		f := stepFacts{
			version:  v,
			recorded: recorded && v <= l.Version,
			late:     late,
			present:  present,
			horizon:  plan.Horizon,
		}
		for _, r := range stepRules {
			if !r.applies(f) {
				continue
			}
			if r.action != "" {
				plan.Steps = append(plan.Steps, Step{Version: v, Action: r.action, Rule: r.name})
				plan.Version = max(plan.Version, v)
			}
			break
		}
	}
	plan.WriteVersion = plan.Version != l.Version
	return plan, nil
}

// Noop reports whether executing p would write nothing: no step to run or
// adopt, no record to forget, and neither the horizon nor the version record
// to store. A runner may skip taking its write lock for a Noop plan read
// without the lock, because a concurrent writer can only make a later plan
// smaller, never larger.
func (p Plan) Noop() bool {
	return len(p.Steps) == 0 && len(p.Forget) == 0 && !p.WriteHorizon && !p.WriteVersion
}

// RunVersions lists the versions p executes (ActionRun), ascending. Adopted
// steps are bookkeeping only and are not listed: this is the "pending
// migrations" list a doctor or preflight surface reports.
func (p Plan) RunVersions() []int {
	var out []int
	for _, s := range p.Steps {
		if s.Action == ActionRun {
			out = append(out, s.Version)
		}
	}
	return out
}
