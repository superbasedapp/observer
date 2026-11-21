//go:build !sbo_omit_security

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/seclang"
)

// secfindings_facets.go holds the Code security page's grouped reads of
// the findings store (redesign plan
// docs/plans/code-security-page-redesign-plan-2026-11-06.md section 4.4):
// the filter facets with their counts, the grouped findings and, for the
// Coverage tab (section 4.5), the dependency drivers' newest recorded
// coverage per project. Read-only. Every read shares secFindingWhere with
// ListSecFindings, so a facet, a group and the list never disagree about
// what a filter selects. The evidence column is read for dependency
// findings only (a public package coordinate), never for any other
// category.

// The facet ids of SecFindingFacets, in display order.
const (
	SecFacetSeverity  = "severity"
	SecFacetCategory  = "category"
	SecFacetDriver    = "driver"
	SecFacetEcosystem = "ecosystem"
	SecFacetLanguage  = "language"
	SecFacetProject   = "project"
	SecFacetStatus    = "status"
	SecFacetBaseline  = "baseline"
)

// SecFacetValue is one value of a facet and how many findings it selects
// under the other facets' filters.
type SecFacetValue struct {
	Value string
	Count int
}

// secFacet is one row of the facet table.
type secFacet struct {
	name string
	// column is the grouped expression and its arguments.
	column func() (string, []any)
	// clear removes the facet's own filter, so its counts say what each of
	// its values would select with the other filters applied.
	clear func(*SecFindingFilter)
	// only narrows the facet to the findings it applies to (dependency
	// findings for the ecosystem, every other category for the language).
	only func() []secCond
	// byRank orders the values by severity (critical first) instead of by
	// count.
	byRank bool
}

func secFacetColumn(col string) func() (string, []any) {
	return func() (string, []any) { return col, nil }
}

func secNoCond() []secCond { return nil }

func secDependencyOnly() []secCond {
	return []secCond{{sql: "category = ?", args: []any{string(policy.FindingVulnerableDependency)}}}
}

func secNonDependencyOnly() []secCond {
	return []secCond{{sql: "category <> ?", args: []any{string(policy.FindingVulnerableDependency)}}}
}

// secLanguageCase is the CASE that names a finding path's seclang id (NULL
// for none), built from the same predicates as the Languages filter.
func secLanguageCase() (string, []any) {
	var b strings.Builder
	var args []any
	b.WriteString("CASE")
	for _, r := range seclang.Rows() {
		p, a, ok := secLanguagePredicate(r.ID)
		if !ok {
			continue
		}
		b.WriteString(" WHEN " + p + " THEN ?")
		args = append(args, a...)
		args = append(args, r.ID)
	}
	b.WriteString(" END")
	return b.String(), args
}

// secFacets is the facet table, in display order.
var secFacets = []secFacet{
	{name: SecFacetSeverity, column: secFacetColumn("severity"), clear: func(f *SecFindingFilter) { f.Severities = nil }, only: secNoCond, byRank: true},
	{name: SecFacetCategory, column: secFacetColumn("category"), clear: func(f *SecFindingFilter) { f.Categories = nil }, only: secNoCond},
	{name: SecFacetDriver, column: secFacetColumn("driver"), clear: func(f *SecFindingFilter) { f.Drivers = nil }, only: secNoCond},
	{name: SecFacetEcosystem, column: secFacetColumn(secDepEcosystemSQL), clear: func(f *SecFindingFilter) { f.Ecosystems = nil }, only: secDependencyOnly},
	{name: SecFacetLanguage, column: secLanguageCase, clear: func(f *SecFindingFilter) { f.Languages = nil }, only: secNonDependencyOnly},
	{name: SecFacetProject, column: secFacetColumn("project_root_hash"), clear: func(f *SecFindingFilter) {
		f.ProjectRootHash, f.ProjectRootHashes = "", nil
	}, only: secNoCond},
	{name: SecFacetStatus, column: secFacetColumn("status"), clear: func(f *SecFindingFilter) { f.Status = "" }, only: secNoCond},
	{name: SecFacetBaseline, column: secFacetColumn("baseline"), clear: func(f *SecFindingFilter) { f.Baselines = nil }, only: secNoCond},
}

// SecFacetNames returns the facet ids SecFindingFacets answers, in display
// order.
func SecFacetNames() []string {
	out := make([]string, 0, len(secFacets))
	for _, fc := range secFacets {
		out = append(out, fc.name)
	}
	return out
}

// secSeverityRank maps each known severity to its rank (critical highest).
func secSeverityRank() map[string]int {
	out := map[string]int{}
	for i, sev := range policy.FindingSeverities() {
		out[string(sev)] = i
	}
	return out
}

// sortSecFacetValues orders a facet's values: by severity rank (critical
// first, an unknown severity after every known one) for the severity
// facet, then by count descending, then by value.
func sortSecFacetValues(vals []SecFacetValue, byRank bool) {
	rank := secSeverityRank()
	sort.SliceStable(vals, func(i, j int) bool {
		a, b := vals[i], vals[j]
		if byRank {
			ra, oka := rank[a.Value]
			rb, okb := rank[b.Value]
			if oka != okb {
				return oka
			}
			if oka && ra != rb {
				return ra > rb
			}
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Value < b.Value
	})
}

// SecFindingFacets returns, for every facet of SecFacetNames, each value's
// count under f with that facet's own filter cleared (Limit, Offset and
// Sort ignored): what choosing the value would show with the other filters
// applied. A value that is empty (or no seclang row names a path) is left
// out. Every facet is present, empty when nothing matches.
func (s *Store) SecFindingFacets(ctx context.Context, f SecFindingFilter) (map[string][]SecFacetValue, error) {
	out := make(map[string][]SecFacetValue, len(secFacets))
	for _, fc := range secFacets {
		g := f
		fc.clear(&g)
		col, args := fc.column()
		where, wargs := secFindingWhere(g, fc.only()...)
		args = append(args, wargs...)
		//nolint:gosec // G202: the column, WHERE and CASE are fixed literals (secFacets, secFindingWhere); every value is a bound parameter.
		rows, err := s.db.QueryContext(ctx, `SELECT `+col+`, COUNT(*) FROM sec_findings`+where+` GROUP BY 1`, args...)
		if err != nil {
			return nil, fmt.Errorf("store.SecFindingFacets: %s: %w", fc.name, err)
		}
		vals := []SecFacetValue{}
		for rows.Next() {
			var v sql.NullString
			var n int
			if err := rows.Scan(&v, &n); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("store.SecFindingFacets: %s: %w", fc.name, err)
			}
			if !v.Valid || v.String == "" {
				continue
			}
			vals = append(vals, SecFacetValue{Value: v.String, Count: n})
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return nil, fmt.Errorf("store.SecFindingFacets: %s: %w", fc.name, err)
		}
		sortSecFacetValues(vals, fc.byRank)
		out[fc.name] = vals
	}
	return out, nil
}

// The SecGroupQuery.By values.
const (
	// SecGroupIssue is the same finding across projects: a dependency
	// advisory on one package version (rule id and evidence), or any other
	// rule on one path (rule id and path).
	SecGroupIssue = "issue"
	// SecGroupPackage is one dependency package version (its evidence);
	// dependency findings only.
	SecGroupPackage = "package"
	// SecGroupRule is one rule id.
	SecGroupRule = "rule"
	// SecGroupProject is one project root hash.
	SecGroupProject = "project"
)

// The SecGroupQuery.Sort values.
const (
	SecGroupSortSeverity = "severity"
	SecGroupSortCount    = "count"
	SecGroupSortLastSeen = "last_seen"
)

// The SecFindingGroups paging bounds.
const (
	SecGroupDefaultLimit = 50
	SecGroupMaxLimit     = 200
)

// ErrSecGroupBy reports a SecGroupQuery.By that is not one of the
// groupings.
var ErrSecGroupBy = errors.New("store: unknown findings grouping")

// SecGroupQuery says how SecFindingGroups groups, orders and pages.
type SecGroupQuery struct {
	// By is one of SecGroupIssue, SecGroupPackage, SecGroupRule,
	// SecGroupProject.
	By string
	// Sort is one of the SecGroupSort values ("" or anything else is
	// severity: worst severity, then count, then key); Desc descending.
	Sort string
	Desc bool
	// Limit (default SecGroupDefaultLimit, at most SecGroupMaxLimit) and
	// Offset page the ordered groups.
	Limit  int
	Offset int
}

// SecFindingGroup is one group of findings. Only the key fields its
// grouping uses are set.
type SecFindingGroup struct {
	// RuleID is an issue or rule group's rule id.
	RuleID string
	// Dependency marks an issue or package group of dependency findings;
	// Evidence is then the group's package evidence ("<ecosystem>
	// <name>@<version>"), the only evidence this read ever returns.
	Dependency bool
	Evidence   string
	// RelPath is a non-dependency issue group's path.
	RelPath string
	// ProjectRootHash is a project group's project.
	ProjectRootHash string
	// Category and Message are one deterministic representative of the
	// group's findings (the smallest).
	Category string
	Message  string
	// Count is the group's findings, Projects its distinct projects.
	Count    int
	Projects int
	// MaxSeverity is the group's worst severity.
	MaxSeverity string
	FirstSeen   time.Time
	LastSeen    time.Time
}

// SecFindingGroupsPage is one page of groups, how many groups the filter
// makes in all, and those groups (all of them, not the page) counted by
// their worst severity.
type SecFindingGroupsPage struct {
	Groups     []SecFindingGroup
	Total      int
	BySeverity map[string]int
}

// secDepCategorySQL is the dependency category as a fixed SQL literal (a
// policy constant, no quote in it), for the grouping's key columns, which
// carry no bound parameter so GROUP BY can name them by position.
const secDepCategorySQL = `'` + string(policy.FindingVulnerableDependency) + `'`

// secGroupBy is one row of the grouping table: the four key columns (rule
// id, the dependency flag, the subject and the project; a column the
// grouping does not use is a constant), the positions it groups by (the
// columns it uses), and the findings the grouping applies to. The subject
// of a dependency finding is its evidence (its public package coordinate);
// of any other finding, its path, never its evidence.
type secGroupBy struct {
	rule, dep, subject, project string
	group                       string
	only                        func() []secCond
}

var secGroupBys = map[string]secGroupBy{
	SecGroupIssue: {
		rule: "rule_id", dep: "(category = " + secDepCategorySQL + ")",
		subject: "CASE WHEN category = " + secDepCategorySQL + " THEN evidence_redacted ELSE rel_path END", project: "''",
		group: "1, 2, 3", only: secNoCond,
	},
	SecGroupPackage: {rule: "''", dep: "1", subject: "evidence_redacted", project: "''", group: "3", only: secDependencyOnly},
	SecGroupRule:    {rule: "rule_id", dep: "0", subject: "''", project: "''", group: "1", only: secNoCond},
	SecGroupProject: {rule: "''", dep: "0", subject: "''", project: "project_root_hash", group: "4", only: secNoCond},
}

// secGroupSorts maps a sort onto its column of the grouped rows; the
// order's tie-breaks are fixed (worst severity, count, then the key).
var secGroupSorts = map[string]string{
	SecGroupSortSeverity: "r",
	SecGroupSortCount:    "cnt",
	SecGroupSortLastSeen: "ls",
}

// secSeverityRankSQL is the severity rank as a CASE (policy.FindingSeverities
// order, weakest 0; an unknown severity -1), its labels bound as
// parameters.
func secSeverityRankSQL() (string, []any) {
	var b strings.Builder
	var args []any
	b.WriteString("CASE severity")
	for i, sev := range policy.FindingSeverities() {
		b.WriteString(" WHEN ? THEN " + fmt.Sprint(i))
		args = append(args, string(sev))
	}
	b.WriteString(" ELSE -1 END")
	return b.String(), args
}

// SecFindingGroups groups the findings f selects (Limit, Offset and Sort of
// f ignored) by q.By and returns one page of groups. It answers
// ErrSecGroupBy for an unknown grouping.
func (s *Store) SecFindingGroups(ctx context.Context, f SecFindingFilter, q SecGroupQuery) (SecFindingGroupsPage, error) {
	by, ok := secGroupBys[q.By]
	if !ok {
		return SecFindingGroupsPage{}, ErrSecGroupBy
	}
	limit := q.Limit
	if limit <= 0 {
		limit = SecGroupDefaultLimit
	}
	if limit > SecGroupMaxLimit {
		limit = SecGroupMaxLimit
	}
	rank, rankArgs := secSeverityRankSQL()
	where, whereArgs := secFindingWhere(f, by.only()...)
	inner := `SELECT ` + by.rule + ` AS k_rule, ` + by.dep + ` AS k_dep, ` + by.subject + ` AS k_subject, ` + by.project + ` AS k_project,
		MIN(category) AS cat, MIN(message) AS msg, COUNT(*) AS cnt, COUNT(DISTINCT project_root_hash) AS projects,
		MAX(` + rank + `) AS r, MIN(severity) AS minsev, MIN(first_seen) AS fs, MAX(last_seen) AS ls
		FROM sec_findings` + where + ` GROUP BY ` + by.group
	args := append(append([]any(nil), rankArgs...), whereArgs...)

	out := SecFindingGroupsPage{Groups: []SecFindingGroup{}, BySeverity: map[string]int{}}
	sevs := policy.FindingSeverities()
	//nolint:gosec // G202: the grouping, rank and WHERE are fixed literals (secGroupBys, secSeverityRankSQL, secFindingWhere); every value is a bound parameter.
	rows, err := s.db.QueryContext(ctx, `SELECT r, MIN(minsev), COUNT(*) FROM (`+inner+`) GROUP BY r`, args...)
	if err != nil {
		return SecFindingGroupsPage{}, fmt.Errorf("store.SecFindingGroups: %w", err)
	}
	for rows.Next() {
		var r, n int
		var minSev string
		if err := rows.Scan(&r, &minSev, &n); err != nil {
			_ = rows.Close()
			return SecFindingGroupsPage{}, fmt.Errorf("store.SecFindingGroups: %w", err)
		}
		out.BySeverity[secSeverityLabel(sevs, r, minSev)] += n
		out.Total += n
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return SecFindingGroupsPage{}, fmt.Errorf("store.SecFindingGroups: %w", err)
	}

	col, ok := secGroupSorts[q.Sort]
	if !ok {
		col = secGroupSorts[SecGroupSortSeverity]
	}
	dir := " ASC"
	if q.Desc {
		dir = " DESC"
	}
	//nolint:gosec // G202: as above; the ORDER BY column comes from the secGroupSorts whitelist and the direction is one of two literals.
	page := `SELECT k_rule, k_dep, k_subject, k_project, cat, msg, cnt, projects, r, minsev, fs, ls FROM (` + inner + `)
		ORDER BY ` + col + dir + `, r DESC, cnt DESC, k_rule, k_dep, k_subject, k_project LIMIT ? OFFSET ?`
	pageArgs := append(append([]any(nil), args...), limit, max(q.Offset, 0))
	rows, err = s.db.QueryContext(ctx, page, pageArgs...)
	if err != nil {
		return SecFindingGroupsPage{}, fmt.Errorf("store.SecFindingGroups: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var g SecFindingGroup
		var dep, r int
		var subject, minSev, first, last string
		if err := rows.Scan(&g.RuleID, &dep, &subject, &g.ProjectRootHash, &g.Category, &g.Message, &g.Count, &g.Projects,
			&r, &minSev, &first, &last); err != nil {
			return SecFindingGroupsPage{}, fmt.Errorf("store.SecFindingGroups: %w", err)
		}
		g.Dependency = dep != 0
		if g.Dependency {
			g.Evidence = subject
		} else {
			g.RelPath = subject
		}
		g.MaxSeverity = secSeverityLabel(sevs, r, minSev)
		g.FirstSeen, _ = time.Parse(secTime, first)
		g.LastSeen, _ = time.Parse(secTime, last)
		out.Groups = append(out.Groups, g)
	}
	if err := rows.Err(); err != nil {
		return SecFindingGroupsPage{}, fmt.Errorf("store.SecFindingGroups: %w", err)
	}
	return out, nil
}

// secSeverityLabel turns a rank back into its severity: a known rank is
// its label, an unknown one (-1) the stored value itself.
func secSeverityLabel(sevs []policy.FindingSeverity, r int, stored string) string {
	if r >= 0 && r < len(sevs) {
		return string(sevs[r])
	}
	return stored
}

// SecCoverageSkip is one part of a project a recorded run did not scan,
// and why: a dependency file (Path relative to the project root) or a
// whole ecosystem (Path "ecosystem:<name>", depscan.EcosystemSkipPrefix).
type SecCoverageSkip struct {
	Path   string
	Reason string
}

// SecCoverageRun is one driver's newest recorded run on one project, with
// the coverage it recorded (secscan.Coverage): its outcome and reason, the
// files it read, the parts it scanned in full (a dependency driver: the
// ecosystems) and the parts it skipped (at most the caller's cap;
// SkippedTotal counts every one).
type SecCoverageRun struct {
	ProjectRootHash string
	Driver          string
	Outcome         string
	Reason          string
	StartedAt       time.Time
	FilesScanned    int
	Scanned         []string
	Skipped         []SecCoverageSkip
	SkippedTotal    int
}

// SecLatestCoverageRuns returns, per project and per named driver, the
// newest run that executed (secScanRanSQL: a run that never started is
// not a scan), with its coverage decoded and its skipped parts capped at
// maxSkipped (0 or less keeps none, SkippedTotal still counts them). A row
// whose coverage is not valid JSON keeps its outcome and reads no
// coverage. Sorted by project, then driver.
func (s *Store) SecLatestCoverageRuns(ctx context.Context, drivers []string, maxSkipped int) ([]SecCoverageRun, error) {
	drivers = secFilterList(drivers)
	if len(drivers) == 0 {
		return nil, nil
	}
	ph, args := secPlaceholders(drivers)
	//nolint:gosec // G202: the clauses are fixed literals; every value is a bound parameter.
	rows, err := s.db.QueryContext(ctx, `SELECT project_root_hash, driver, outcome, started_at, coverage_json FROM sec_scan_runs
		WHERE id IN (SELECT MAX(id) FROM sec_scan_runs WHERE driver IN (`+ph+`)`+secScanRanSQL+` GROUP BY project_root_hash, driver)
		ORDER BY project_root_hash, driver`, args...)
	if err != nil {
		return nil, fmt.Errorf("store.SecLatestCoverageRuns: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []SecCoverageRun
	for rows.Next() {
		var r SecCoverageRun
		var started, raw string
		if err := rows.Scan(&r.ProjectRootHash, &r.Driver, &r.Outcome, &started, &raw); err != nil {
			return nil, fmt.Errorf("store.SecLatestCoverageRuns: %w", err)
		}
		r.StartedAt, _ = time.Parse(secTime, started)
		r.Reason = secCoverageReason(raw)
		decodeSecCoverage(raw, maxSkipped, &r)
		out = append(out, r)
	}
	return out, rows.Err()
}

// decodeSecCoverage reads the files scanned, the parts scanned and the
// parts skipped of a recorded coverage (secscan.Coverage's field names);
// a body that is not JSON reads none.
func decodeSecCoverage(raw string, maxSkipped int, r *SecCoverageRun) {
	if raw == "" {
		return
	}
	var cov struct {
		FilesScanned int      `json:"FilesScanned"`
		Scanned      []string `json:"Scanned"`
		Skipped      []struct {
			Path   string `json:"Path"`
			Reason string `json:"Reason"`
		} `json:"Skipped"`
	}
	if json.Unmarshal([]byte(raw), &cov) != nil {
		return
	}
	r.FilesScanned, r.Scanned, r.SkippedTotal = cov.FilesScanned, cov.Scanned, len(cov.Skipped)
	for i, sk := range cov.Skipped {
		if i >= maxSkipped {
			break
		}
		r.Skipped = append(r.Skipped, SecCoverageSkip{Path: sk.Path, Reason: sk.Reason})
	}
}
