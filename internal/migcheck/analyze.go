package migcheck

import (
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/migplan/shipped"
)

// Lineage names, as tests/invariant/testdata/shipped-migrations.json and
// internal/migplan/shipped spell them.
const (
	// LineageOrgPG is the org server's PostgreSQL lineage
	// (internal/orgserver/db/pgmigrations).
	LineageOrgPG = "org-pg"
	// LineageCloud is the hosted cloud service's PostgreSQL lineage
	// (internal/cloudserver/db/migrations).
	LineageCloud = "cloud"
)

// Step is one migration step to check.
type Step struct {
	Lineage string // a lineage name, e.g. LineageOrgPG
	Version int    // the step number
	Name    string // the file name, e.g. 0185_x.sql
	SQL     string // the file's text
}

// StepKey identifies a step within the lineages.
type StepKey struct {
	Lineage string
	Version int
}

// Input is what Analyze checks.
type Input struct {
	// Steps are every step of the lineages, exempt ones included: an exempt
	// step yields no finding but its schema (functions, indexes, CHECK
	// constraints) is what later steps are checked against.
	Steps []Step
	// Exempt holds the shipped steps (shipped-migrations.json). Steps at or
	// below a lineage's PreMigcheckHead are exempt as well.
	Exempt map[StepKey]bool
	// ManifestHasTable reports whether the tenancy manifest has a row for a
	// table a step creates (plan 06 17.1 rule 3). nil skips the rule: the
	// manifest (M3-0.2) does not exist yet.
	ManifestHasTable func(lineage, table string) bool
}

// Finding is one rule a checked step breaks.
type Finding struct {
	Lineage   string
	Version   int
	Name      string
	Rule      string // the rule row's id, e.g. "create-index"
	Statement string // an excerpt of the statement, or "" for a step-level rule
	Required  string // what the rule requires
}

// String renders a finding on one line.
func (f Finding) String() string {
	if f.Statement == "" {
		return fmt.Sprintf("%s/%s: [%s] requires %s", f.Lineage, f.Name, f.Rule, f.Required)
	}
	return fmt.Sprintf("%s/%s: [%s] %q requires %s", f.Lineage, f.Name, f.Rule, f.Statement, f.Required)
}

// Report is Analyze's result.
type Report struct {
	// Checked are the steps that were not exempt, in lineage and version
	// order.
	Checked []StepKey
	// Findings are in step order, then in rule order.
	Findings []Finding
}

// preMigcheckHeads is each lineage's last step written before migcheck
// existed (the managed-SaaS arc's start, 2026-11-12): those steps carry no
// directives and are exempt. Fixed; never raise them to pass the gate.
var preMigcheckHeads = map[string]int{
	LineageOrgPG: 184,
	LineageCloud: 44,
}

// PreMigcheckHead returns the lineage's pre-migcheck head (0 for a lineage
// migcheck has no row for, which checks every step).
func PreMigcheckHead(lineage string) int { return preMigcheckHeads[lineage] }

// lineageCapability is what a lineage's runner provides that a step rule
// depends on (lead decision L-79). Rules read a lineage's row; they never
// branch on the lineage's name.
type lineageCapability struct {
	// progressTable is the table the runner keeps for a data step to record
	// its progress in, so a rerun resumes the batch where it stopped. "" means
	// the runner keeps none: its ledger records only whole steps, so a data
	// step there must be transactional (all of it commits, or none of it and
	// the rerun starts it over), which the data-step rule then requires in
	// place of the progress write.
	progressTable string
}

// lineageCapabilities holds one row per lineage migcheck covers (the
// TestEveryLineageHasACapabilityRow pin), each grounded in that lineage's
// runner:
//
//   - org-pg: internal/orgserver/db keeps schema_meta, which a data step
//     writes its progress to.
//   - cloud: internal/cloudserver/db's ledger is sbci_migrations (one row per
//     applied step, written in the step's own transaction); it has no
//     progress table, applies every step in one transaction and refuses a
//     non-transactional step.
var lineageCapabilities = map[string]lineageCapability{
	LineageOrgPG: {progressTable: "schema_meta"},
	LineageCloud: {progressTable: ""},
}

// defaultLineageCapability applies to a lineage with no row (the rule
// samples' "test" lineage): the strictest resumable shape, a progress row in
// schema_meta.
var defaultLineageCapability = lineageCapability{progressTable: "schema_meta"}

// capabilityOf returns the lineage's capability row, or the default.
func capabilityOf(lineage string) lineageCapability {
	if c, ok := lineageCapabilities[lineage]; ok {
		return c
	}
	return defaultLineageCapability
}

// Lineages returns the lineages migcheck covers, sorted.
func Lineages() []string {
	out := make([]string, 0, len(preMigcheckHeads))
	for l := range preMigcheckHeads {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// ExemptFromRecord returns the exempt set a shipped-migrations record gives:
// every step file it lists in a lineage migcheck covers.
func ExemptFromRecord(rec shipped.Record) map[StepKey]bool {
	out := map[StepKey]bool{}
	for _, l := range rec.Lineages {
		if _, covered := preMigcheckHeads[l.Name]; !covered {
			continue
		}
		for _, st := range l.Steps {
			if n, ok := shipped.StepNumber(st.File); ok {
				out[StepKey{Lineage: l.Name, Version: n}] = true
			}
		}
	}
	return out
}

// Analyze checks every step of in that is not exempt.
func Analyze(in Input) Report { return analyze(in, preMigcheckHeads) }

func analyze(in Input, heads map[string]int) Report {
	steps := append([]Step(nil), in.Steps...)
	sort.SliceStable(steps, func(i, j int) bool {
		if steps[i].Lineage != steps[j].Lineage {
			return steps[i].Lineage < steps[j].Lineage
		}
		return steps[i].Version < steps[j].Version
	})
	var rep Report
	lins := map[string]*lineageState{}
	for _, st := range steps {
		lin := lins[st.Lineage]
		if lin == nil {
			lin = newLineageState()
			lins[st.Lineage] = lin
		}
		key := StepKey{Lineage: st.Lineage, Version: st.Version}
		exempt := in.Exempt[key] || st.Version <= heads[st.Lineage]
		found, _ := checkStep(st, lin, in.ManifestHasTable)
		if exempt {
			continue
		}
		rep.Checked = append(rep.Checked, key)
		rep.Findings = append(rep.Findings, found...)
	}
	return rep
}

// lineageState is what earlier steps of a lineage left behind that later
// steps are checked against.
type lineageState struct {
	routines      map[string]int // function, procedure and view names -> first step
	uniqueIndexes map[string]int // unique index name -> step that built it
	checks        []*notNullCheck
}

// notNullCheck is a CHECK (col IS NOT NULL) constraint.
type notNullCheck struct {
	table, name, column string
	added, validated    int // step numbers; validated 0 = not yet
}

func newLineageState() *lineageState {
	return &lineageState{routines: map[string]int{}, uniqueIndexes: map[string]int{}}
}

// directives are a step's header directives.
type directives struct {
	labels  []string // expand, contract or data, as written
	nonTx   bool
	size    string
	unknown []string // words of "-- step:" lines outside the vocabulary
}

// label returns the step's one label, or "" when it has none or several.
func (d directives) label() string {
	if len(d.labels) == 1 {
		return d.labels[0]
	}
	return ""
}

// Directives is a step's label and class, as its header declares them; the
// runner records the label in schema_meta (plan 06 18.2.5).
type Directives struct {
	Label            string // expand, contract, data, or "" when missing or ambiguous
	NonTransactional bool
	SizeNote         string
}

// ReadDirectives reads a step's header directives. It returns an error when
// the step's SQL cannot be tokenized.
func ReadDirectives(sql string) (Directives, error) {
	lx, err := lex(sql)
	if err != nil {
		return Directives{}, fmt.Errorf("migcheck.ReadDirectives: %w", err)
	}
	d := parseDirectives(lx.header)
	return Directives{Label: d.label(), NonTransactional: d.nonTx, SizeNote: d.size}, nil
}

// directiveWords is the closed vocabulary of "-- step:".
var directiveWords = map[string]string{
	"expand":            "label",
	"contract":          "label",
	"data":              "label",
	"non-transactional": "class",
}

func parseDirectives(header []string) directives {
	var d directives
	for _, line := range header {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "step:"):
			for _, w := range strings.Fields(strings.ReplaceAll(strings.TrimPrefix(line, "step:"), ",", " ")) {
				w = strings.ToLower(w)
				switch directiveWords[w] {
				case "label":
					d.labels = append(d.labels, w)
				case "class":
					d.nonTx = true
				default:
					d.unknown = append(d.unknown, w)
				}
			}
		case strings.HasPrefix(line, "size:"):
			if s := strings.TrimSpace(strings.TrimPrefix(line, "size:")); s != "" {
				if d.size != "" {
					d.size += " "
				}
				d.size += s
			}
		}
	}
	return d
}

// unit is what the statement table classifies: a whole statement, or one
// action of a multi-action ALTER TABLE.
type unit struct {
	stmt    int     // index of the statement in the step
	toks    []token // the statement's tokens
	alter   bool    // an ALTER TABLE action
	table   string  // the ALTER TABLE target, folded
	action  []token // the action's tokens (ALTER TABLE only)
	excerpt string  // for findings
	class   stmtClass
	rule    string // the id of the row that matched
	rewrite bool   // the unit rewrites a populated table (needs a size note)
	target  string // the table a policy, DML or index statement names, folded
}

// stepState is one step under check.
type stepState struct {
	step      Step
	dir       directives
	lin       *lineageState
	newTables map[string]bool
	units     []*unit
	created   []string        // tables the step creates, in order
	notValid  map[string]bool // "table.constraint" added NOT VALID in this step
}

func (s *stepState) label() string { return s.dir.label() }

// isNew reports whether table is created by this step (and so is empty).
func (s *stepState) isNew(table string) bool { return table != "" && s.newTables[table] }

// checkStep classifies one step's statements and applies the step rules. It
// always updates lin, so exempt steps feed later checks. The returned state
// is nil when the step could not be tokenized.
func checkStep(st Step, lin *lineageState, manifest func(lineage, table string) bool) ([]Finding, *stepState) {
	lx, err := lex(st.SQL)
	if err != nil {
		return []Finding{{
			Lineage: st.Lineage, Version: st.Version, Name: st.Name,
			Rule: "parse", Required: "SQL migcheck can tokenize: " + err.Error(),
		}}, nil
	}
	s := &stepState{step: st, dir: parseDirectives(lx.header), lin: lin, newTables: map[string]bool{}}
	for i, stmt := range lx.stmts {
		s.units = append(s.units, splitUnits(st.SQL, i, stmt)...)
	}
	// Tables the step creates are empty for every other statement of the
	// step, wherever they sit in it.
	for _, u := range s.units {
		if t, ok := createdTable(u.toks); ok {
			s.newTables[t] = true
			s.created = append(s.created, t)
		}
	}
	var out []Finding
	add := func(rule, stmt string, required []string) {
		for _, r := range required {
			out = append(out, Finding{Lineage: st.Lineage, Version: st.Version, Name: st.Name, Rule: rule, Statement: stmt, Required: r})
		}
	}
	for _, u := range s.units {
		for _, r := range statementRules {
			if !r.match(u) {
				continue
			}
			u.rule, u.class = r.id, r.class
			if r.check != nil {
				add(r.id, u.excerpt, r.check(u, s))
			}
			break
		}
	}
	for _, r := range stepRules {
		for _, v := range r.check(s, manifest) {
			add(r.id, v.stmt, []string{v.required})
		}
	}
	return out, s
}

// splitUnits turns a statement into units: one per ALTER TABLE action, else
// the statement itself.
func splitUnits(src string, idx int, stmt statement) []*unit {
	toks := stmt.toks
	whole := &unit{stmt: idx, toks: toks, excerpt: excerpt(src, stmt.start, stmt.end)}
	if len(toks) < 3 || !toks[0].isWord("ALTER") || !toks[1].isWord("TABLE") {
		return []*unit{whole}
	}
	i := 2
	i = skipWords(toks, i, "IF", "EXISTS")
	i = skipWords(toks, i, "ONLY")
	table, next := qualifiedName(toks, i)
	if table == "" {
		return []*unit{whole}
	}
	if next < len(toks) && toks[next].isPunct("*") {
		next++
	}
	if next >= len(toks) {
		return []*unit{whole}
	}
	head := excerpt(src, stmt.start, toks[next-1].end)
	var units []*unit
	begin := next
	for j := next; j <= len(toks); j++ {
		if j < len(toks) && !(toks[j].isPunct(",") && toks[j].depth == 0) {
			continue
		}
		if j > begin {
			act := toks[begin:j]
			units = append(units, &unit{
				stmt: idx, toks: toks, alter: true, table: table, action: act,
				excerpt: head + " " + excerpt(src, act[0].pos, act[len(act)-1].end),
			})
		}
		begin = j + 1
	}
	if len(units) == 0 {
		return []*unit{whole}
	}
	return units
}

// skipWords returns i advanced past the keyword sequence words when ts[i:]
// starts with it, else i.
func skipWords(ts []token, i int, words ...string) int {
	if at(ts, i, words...) {
		return i + len(words)
	}
	return i
}

// at reports whether ts[i:] starts with the keyword sequence words.
func at(ts []token, i int, words ...string) bool {
	if i < 0 || i+len(words) > len(ts) {
		return false
	}
	for k, w := range words {
		if !ts[i+k].isWord(w) {
			return false
		}
	}
	return true
}

// findAt returns the index of the first occurrence of the keyword sequence
// words at parenthesis depth depth, or -1.
func findAt(ts []token, depth int, words ...string) int {
	for i := range ts {
		if ts[i].depth == depth && at(ts, i, words...) {
			return i
		}
	}
	return -1
}

// hasWordAnyDepth reports whether any token is one of the keywords.
func hasWordAnyDepth(ts []token, words ...string) bool {
	for _, t := range ts {
		for _, w := range words {
			if t.isWord(w) {
				return true
			}
		}
	}
	return false
}

// qualifiedName reads a possibly schema-qualified name at ts[i] and returns
// its last part, folded, and the index after it.
func qualifiedName(ts []token, i int) (string, int) {
	if i >= len(ts) || (ts[i].kind != tokWord && ts[i].kind != tokQuotedIdent) {
		return "", i
	}
	name := ts[i].ident()
	i++
	for i+1 < len(ts) && ts[i].isPunct(".") && (ts[i+1].kind == tokWord || ts[i+1].kind == tokQuotedIdent) {
		name = ts[i+1].ident()
		i += 2
	}
	return name, i
}

// createdTable returns the table a CREATE TABLE statement creates.
func createdTable(ts []token) (string, bool) {
	if len(ts) < 3 || !ts[0].isWord("CREATE") {
		return "", false
	}
	i := 1
	i = skipWords(ts, i, "GLOBAL")
	i = skipWords(ts, i, "LOCAL")
	for _, w := range []string{"TEMPORARY", "TEMP", "UNLOGGED"} {
		i = skipWords(ts, i, w)
	}
	if !at(ts, i, "TABLE") {
		return "", false
	}
	i = skipWords(ts, i+1, "IF", "NOT", "EXISTS")
	name, _ := qualifiedName(ts, i)
	return name, name != ""
}

// nameAfter returns the qualified name following the first top-level
// occurrence of the keyword sequence words (skipping ONLY), or "".
func nameAfter(ts []token, words ...string) string {
	i := findAt(ts, 0, words...)
	if i < 0 {
		return ""
	}
	j := skipWords(ts, i+len(words), "ONLY")
	name, _ := qualifiedName(ts, j)
	return name
}
