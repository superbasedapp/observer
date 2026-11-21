package migcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/migplan/shipped"
	"github.com/marmutapp/superbased-observer/internal/testsupport/publictree"
)

const badStep = "CREATE INDEX i ON t (a);" // no label, no lock_timeout, blocking build

func TestExemptions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		steps       []Step
		exempt      map[StepKey]bool
		wantRules   []string
		wantChecked int
	}{
		{
			name:   "a shipped step is exempt",
			steps:  []Step{{Lineage: LineageOrgPG, Version: 190, Name: "0190_x.sql", SQL: badStep}},
			exempt: map[StepKey]bool{{Lineage: LineageOrgPG, Version: 190}: true},
		},
		{
			name:  "a step at the pre-migcheck head is exempt",
			steps: []Step{{Lineage: LineageOrgPG, Version: 184, Name: "0184_x.sql", SQL: badStep}},
		},
		{
			name:  "a cloud step at its pre-migcheck head is exempt",
			steps: []Step{{Lineage: LineageCloud, Version: 44, Name: "0044_x.sql", SQL: badStep}},
		},
		{
			name:        "the first step above the head is checked",
			steps:       []Step{{Lineage: LineageOrgPG, Version: 185, Name: "0185_x.sql", SQL: badStep}},
			wantRules:   []string{"create-index", "label", "lock-timeout"},
			wantChecked: 1,
		},
		{
			name:        "a cloud step above its head is checked",
			steps:       []Step{{Lineage: LineageCloud, Version: 45, Name: "0045_x.sql", SQL: badStep}},
			wantRules:   []string{"create-index", "label", "lock-timeout"},
			wantChecked: 1,
		},
		{
			name:        "the exempt set is per lineage",
			steps:       []Step{{Lineage: LineageCloud, Version: 190, Name: "0190_x.sql", SQL: badStep}},
			exempt:      map[StepKey]bool{{Lineage: LineageOrgPG, Version: 190}: true},
			wantRules:   []string{"create-index", "label", "lock-timeout"},
			wantChecked: 1,
		},
		{
			name: "an exempt step still feeds later checks (a replaced function)",
			steps: []Step{
				{Lineage: LineageOrgPG, Version: 100, Name: "0100_f.sql", SQL: "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;"},
				{Lineage: LineageOrgPG, Version: 185, Name: "0185_f.sql", SQL: hE + "CREATE OR REPLACE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 2 $$;"},
			},
			wantRules:   []string{"create-or-replace"},
			wantChecked: 1,
		},
		{
			name: "an exempt step still feeds later checks (a unique index)",
			steps: []Step{
				{Lineage: LineageOrgPG, Version: 186, Name: "0186_c.sql", SQL: hE + "ALTER TABLE t ADD CONSTRAINT k UNIQUE USING INDEX t_a_key;"},
				{Lineage: LineageOrgPG, Version: 150, Name: "0150_i.sql", SQL: "CREATE UNIQUE INDEX t_a_key ON t (a);"},
			},
			wantChecked: 1,
		},
		{
			name:  "an unparseable exempt step is not reported",
			steps: []Step{{Lineage: LineageOrgPG, Version: 10, Name: "0010_x.sql", SQL: "SELECT 'x"}},
		},
		{
			name:        "an unparseable checked step is a parse finding",
			steps:       []Step{{Lineage: LineageOrgPG, Version: 200, Name: "0200_x.sql", SQL: hE + "SELECT 'x"}},
			wantRules:   []string{"parse"},
			wantChecked: 1,
		},
		{
			name:        "a lineage without a head is checked from step 1",
			steps:       []Step{{Lineage: "other", Version: 1, Name: "0001_x.sql", SQL: badStep}},
			wantRules:   []string{"create-index", "label", "lock-timeout"},
			wantChecked: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rep := Analyze(Input{Steps: tc.steps, Exempt: tc.exempt})
			var got []string
			for _, f := range rep.Findings {
				got = append(got, f.Rule)
			}
			if strings.Join(got, ",") != strings.Join(tc.wantRules, ",") {
				t.Errorf("rules = %v, want %v (findings %v)", got, tc.wantRules, rep.Findings)
			}
			if len(rep.Checked) != tc.wantChecked {
				t.Errorf("checked %v, want %d steps", rep.Checked, tc.wantChecked)
			}
		})
	}
}

func TestPreMigcheckHeads(t *testing.T) {
	t.Parallel()
	if PreMigcheckHead(LineageOrgPG) != 184 || PreMigcheckHead(LineageCloud) != 44 || PreMigcheckHead("node") != 0 {
		t.Fatalf("heads moved: org-pg %d, cloud %d; they mark the arc's start and never move",
			PreMigcheckHead(LineageOrgPG), PreMigcheckHead(LineageCloud))
	}
	if got := strings.Join(Lineages(), ","); got != "cloud,org-pg" {
		t.Errorf("Lineages() = %s", got)
	}
	for _, l := range Lineages() {
		if _, ok := shipped.LookupLineage(l); !ok {
			t.Errorf("lineage %s is not a shipped-record lineage", l)
		}
	}
}

func TestFindingString(t *testing.T) {
	t.Parallel()
	f := Finding{Lineage: "org-pg", Name: "0185_x.sql", Rule: "create-index", Statement: "CREATE INDEX i ON t (a)", Required: "CONCURRENTLY"}
	if got := f.String(); got != `org-pg/0185_x.sql: [create-index] "CREATE INDEX i ON t (a)" requires CONCURRENTLY` {
		t.Errorf("String() = %s", got)
	}
	f.Statement = ""
	if got := f.String(); got != "org-pg/0185_x.sql: [create-index] requires CONCURRENTLY" {
		t.Errorf("String() = %s", got)
	}
}

// readLineage reads every NNN_name.sql step of dir.
func readLineage(t *testing.T, lineage, dir string) []Step {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var steps []Step
	for _, e := range entries {
		n, ok := shipped.StepNumber(e.Name())
		if !ok || e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		steps = append(steps, Step{Lineage: lineage, Version: n, Name: e.Name(), SQL: string(b)})
	}
	if len(steps) == 0 {
		t.Fatalf("no steps in %s", dir)
	}
	return steps
}

// TestRealLineages runs the analyzer over the real org PostgreSQL and cloud
// directories, as the gate does: zero findings on today's tree. It also
// proves the tokenizer reads every real step (no parse finding with every
// exemption removed).
func TestRealLineages(t *testing.T) {
	t.Parallel()
	publictree.Skip(t, "the org server's PostgreSQL migrations (internal/orgserver/db/pgmigrations)")
	steps := append(
		readLineage(t, LineageOrgPG, filepath.Join("..", "orgserver", "db", "pgmigrations")),
		readLineage(t, LineageCloud, filepath.Join("..", "cloudserver", "db", "migrations"))...)
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "invariant", "testdata", "shipped-migrations.json"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := shipped.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	exempt := ExemptFromRecord(rec)
	rep := Analyze(Input{Steps: steps, Exempt: exempt})
	for _, f := range rep.Findings {
		t.Errorf("finding on the real tree: %s", f)
	}
	all := analyze(Input{Steps: steps}, map[string]int{})
	if len(all.Checked) != len(steps) {
		t.Fatalf("checked %d of %d steps with no exemptions", len(all.Checked), len(steps))
	}
	for _, f := range all.Findings {
		if f.Rule == "parse" {
			t.Errorf("the tokenizer cannot read a real step: %s", f)
		}
	}
}

// TestDocumentedExample: the example in docs/migration-numbering.md ("Step
// labels and migcheck") passes.
func TestDocumentedExample(t *testing.T) {
	t.Parallel()
	sql := "-- 0185_sessions_org_day_idx.sql - what the step does and why.\n" +
		"-- step: expand non-transactional\n" +
		"SET lock_timeout = '5s';\n" +
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_org_day ON sessions (org_id, day);\n"
	rep := Analyze(Input{Steps: []Step{{Lineage: LineageOrgPG, Version: 185, Name: "0185_sessions_org_day_idx.sql", SQL: sql}}})
	if len(rep.Checked) != 1 || len(rep.Findings) != 0 {
		t.Fatalf("checked %v, findings %v", rep.Checked, rep.Findings)
	}
}
