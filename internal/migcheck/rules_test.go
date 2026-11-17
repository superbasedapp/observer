package migcheck

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

// Step headers for the samples.
const (
	hE  = "-- step: expand\nSET lock_timeout = '5s';\n"
	hC  = "-- step: contract\nSET LOCAL lock_timeout = '5s';\n"
	hN  = "-- step: expand non-transactional\nSET lock_timeout = '5s';\n"
	hCN = "-- step: contract non-transactional\nSET lock_timeout = '5s';\n"
	hD  = "-- step: data\nSET LOCAL lock_timeout = '5s';\nSET LOCAL statement_timeout = '60s';\n"
	hCS = "-- step: contract\n-- size: t is about 2 GB; about 4 minutes\nSET LOCAL lock_timeout = '5s';\n"
	// progress is how a data sample records its progress.
	progress = "\nINSERT INTO schema_meta (key, value) VALUES ('bf', '1000') ON CONFLICT (key) DO UPDATE SET value = excluded.value;"
)

// ruleCase is one sample for one rule row: an allowed sample (ok) yields no
// finding and, for a statement row, classifies a unit of its last step under
// that row; a refused sample yields exactly want from its last step.
type ruleCase struct {
	row      string
	ok       bool
	steps    []string // the lineage's steps in order; the last is the one under test
	want     []string // rule ids of the last step's findings (default: [row])
	manifest func(lineage, table string) bool
}

func ok(row string, steps ...string) ruleCase { return ruleCase{row: row, ok: true, steps: steps} }

func refused(row string, want []string, steps ...string) ruleCase {
	return ruleCase{row: row, steps: steps, want: want}
}

var ruleCases = []ruleCase{
	// Statement rows.
	ok("set-lock-timeout", hE+"CREATE TABLE n (a int);"),
	ok("set-statement-timeout", hD+"UPDATE t SET a = 0 WHERE id >= 1 AND id < 1000;"+progress),
	ok("set-session", hE+"SET search_path = public;\nCREATE TABLE n (a int);"),
	refused("transaction-control", []string{"transaction-control", "transaction-control"}, hE+"BEGIN;\nCREATE TABLE n (a int);\nCOMMIT;"),
	ok("policy", hE+"CREATE POLICY p ON t USING (org_id = current_setting('app.org'));"),
	ok("row-level-security", hE+"ALTER TABLE t ENABLE ROW LEVEL SECURITY;\nALTER TABLE t FORCE ROW LEVEL SECURITY;"),
	ok("alter-type-add-value", hE+"ALTER TYPE mood ADD VALUE IF NOT EXISTS 'meh';"),

	ok("create-index", hN+"CREATE INDEX CONCURRENTLY IF NOT EXISTS i ON t (a);"),
	ok("create-index", hE+"CREATE TABLE n (a int);\nCREATE INDEX i ON n (a);"),
	refused("create-index", nil, hE+"CREATE INDEX i ON t (a);"),
	refused("create-index", nil, hE+"CREATE INDEX CONCURRENTLY i ON t (a);"),
	refused("create-index", nil, hN+"CREATE UNIQUE INDEX i ON ONLY t (a);"),
	refused("create-index", nil, hE+"CREATE TABLE n (a int);\nCREATE INDEX CONCURRENTLY i ON n (a);"),

	ok("drop-index", hN+"DROP INDEX CONCURRENTLY IF EXISTS i;"),
	ok("drop-index", hC+"DROP INDEX i;"),
	refused("drop-index", nil, hE+"DROP INDEX i;"),
	refused("drop-index", nil, hC+"DROP INDEX CONCURRENTLY i;"),

	ok("reindex", hN+"REINDEX INDEX CONCURRENTLY i;"),
	ok("reindex", hC+"REINDEX TABLE t;"),
	refused("reindex", nil, hE+"REINDEX (VERBOSE) TABLE t;"),

	ok("create-table", hE+"CREATE TABLE IF NOT EXISTS public.n (id bigint PRIMARY KEY, at timestamptz NOT NULL DEFAULT now());"),

	ok("add-column-volatile-default", hE+"CREATE TABLE n (a int);\nALTER TABLE n ADD COLUMN c timestamptz DEFAULT clock_timestamp();"),
	refused("add-column-volatile-default", nil, hE+"ALTER TABLE t ADD COLUMN c timestamptz DEFAULT clock_timestamp();"),
	refused("add-column-volatile-default", nil, hE+"ALTER TABLE t ADD COLUMN c double precision DEFAULT random();"),
	refused("add-column-volatile-default", nil, hE+"ALTER TABLE t ADD COLUMN c text DEFAULT timeofday();"),
	refused("add-column-volatile-default", nil, hE+"ALTER TABLE t ADD COLUMN c bigint DEFAULT nextval('s');"),
	refused("add-column-volatile-default", nil, hE+"ALTER TABLE t ADD COLUMN c bigint GENERATED ALWAYS AS IDENTITY;"),
	refused("add-column-volatile-default", nil, hE+"ALTER TABLE t ADD COLUMN c int GENERATED ALWAYS AS (a + 1) STORED;"),
	refused("add-column-volatile-default", nil, hE+"ALTER TABLE t ADD COLUMN id bigserial;"),
	refused("add-column-volatile-default", nil, hE+"ALTER TABLE t ADD COLUMN c uuid NOT NULL DEFAULT gen_random_uuid();"),

	ok("add-column-not-null", hE+"CREATE TABLE n (a int);\nALTER TABLE n ADD COLUMN c int NOT NULL;"),
	refused("add-column-not-null", nil, hE+"ALTER TABLE t ADD COLUMN c int NOT NULL;"),

	ok("add-column-inline-constraint", hE+"CREATE TABLE n (a int);\nALTER TABLE n ADD COLUMN u text REFERENCES u (id);"),
	refused("add-column-inline-constraint", nil, hE+"ALTER TABLE t ADD COLUMN c int CHECK (c > 0);"),

	ok("add-column", hE+"ALTER TABLE t ADD COLUMN IF NOT EXISTS c text NOT NULL DEFAULT '', ADD d int;"),
	// STABLE defaults do not rewrite (PostgreSQL 11+): allowed on an existing table.
	ok("add-column", hE+"ALTER TABLE t ADD COLUMN c timestamptz NOT NULL DEFAULT now(), ADD COLUMN d timestamptz DEFAULT CURRENT_TIMESTAMP, "+
		"ADD COLUMN e date DEFAULT CURRENT_DATE, ADD COLUMN f timestamp DEFAULT LOCALTIMESTAMP, "+
		"ADD COLUMN g timestamptz DEFAULT transaction_timestamp(), ADD COLUMN h timestamptz DEFAULT statement_timestamp();"),

	ok("add-constraint-unique-pk",
		hN+"CREATE UNIQUE INDEX CONCURRENTLY t_a_key ON t (a);",
		hE+"ALTER TABLE t ADD CONSTRAINT t_a_key UNIQUE USING INDEX t_a_key;"),
	refused("add-constraint-unique-pk", nil, hE+"ALTER TABLE t ADD CONSTRAINT t_a_key UNIQUE (a);"),
	refused("add-constraint-unique-pk", nil, hE+"ALTER TABLE t ADD CONSTRAINT t_pkey PRIMARY KEY USING INDEX never_built;"),

	ok("add-constraint-exclude", hC+"ALTER TABLE t ADD CONSTRAINT t_x EXCLUDE USING gist (r WITH &&);"),
	refused("add-constraint-exclude", nil, hE+"ALTER TABLE t ADD CONSTRAINT t_x EXCLUDE USING gist (r WITH &&);"),

	ok("add-constraint-fk-check", hE+"ALTER TABLE t ADD CONSTRAINT t_u_fk FOREIGN KEY (u) REFERENCES u (id) NOT VALID;"),
	refused("add-constraint-fk-check", nil, hE+"ALTER TABLE t ADD CONSTRAINT t_a_pos CHECK (a > 0);"),
	refused("add-constraint-fk-check", nil, hC+"ALTER TABLE t ADD FOREIGN KEY (u) REFERENCES u (id);"),

	ok("validate-constraint",
		hE+"ALTER TABLE t ADD CONSTRAINT t_a_pos CHECK (a > 0) NOT VALID;",
		hE+"ALTER TABLE t VALIDATE CONSTRAINT t_a_pos;"),
	refused("validate-constraint", nil, hE+"ALTER TABLE t ADD CONSTRAINT t_a_pos CHECK (a > 0) NOT VALID, VALIDATE CONSTRAINT t_a_pos;"),

	ok("set-not-null",
		hE+"ALTER TABLE t ADD CONSTRAINT t_a_nn CHECK (a IS NOT NULL) NOT VALID;",
		hE+"ALTER TABLE t VALIDATE CONSTRAINT t_a_nn;",
		hE+"ALTER TABLE t ALTER COLUMN a SET NOT NULL;"),
	ok("set-not-null", hC+"ALTER TABLE t ALTER a SET NOT NULL;"),
	refused("set-not-null", nil,
		hE+"ALTER TABLE t ADD CONSTRAINT t_a_nn CHECK (a IS NOT NULL) NOT VALID;",
		hE+"ALTER TABLE t ALTER COLUMN a SET NOT NULL;"),
	refused("set-not-null", nil,
		hE+"ALTER TABLE t ADD CONSTRAINT t_b_nn CHECK (b IS NOT NULL) NOT VALID;",
		hE+"ALTER TABLE t VALIDATE CONSTRAINT t_b_nn;",
		hE+"ALTER TABLE t ALTER COLUMN a SET NOT NULL;"),

	ok("alter-column-type", hCS+"ALTER TABLE t ALTER COLUMN a TYPE bigint;"),
	refused("alter-column-type", []string{"alter-column-type", "size-note"}, hE+"ALTER TABLE t ALTER COLUMN a SET DATA TYPE bigint;"),

	ok("column-default", hE+"ALTER TABLE t ALTER COLUMN a SET DEFAULT now(), ALTER COLUMN b DROP NOT NULL, ALTER c DROP DEFAULT;"),

	ok("drop-column", hC+"ALTER TABLE t DROP COLUMN IF EXISTS a;"),
	refused("drop-column", nil, hE+"ALTER TABLE t DROP COLUMN a;"),

	ok("drop-constraint", hC+"ALTER TABLE t DROP CONSTRAINT t_a_key;"),
	refused("drop-constraint", nil, hE+"ALTER TABLE t DROP CONSTRAINT IF EXISTS t_a_key;"),

	ok("owner", hE+"CREATE FUNCTION f() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;\nALTER FUNCTION public.f() OWNER TO sbci_defs;"),
	ok("owner", hE+"CREATE TABLE n (a int);\nALTER TABLE n OWNER TO r;"),
	refused("owner", nil, hE+"ALTER FUNCTION g() OWNER TO sbci_defs;"),
	refused("owner", nil, hE+"ALTER TABLE t OWNER TO r;"),

	ok("rename", hC+"ALTER TABLE t RENAME COLUMN a TO b;"),
	refused("rename", nil, hE+"ALTER INDEX i RENAME TO j;"),
	refused("rename", nil, hE+"ALTER TABLE t RENAME TO t2;"),

	ok("table-rewrite", hCS+"ALTER TABLE t SET LOGGED;"),
	refused("table-rewrite", []string{"table-rewrite", "size-note"}, hE+"VACUUM FULL t;"),

	ok("drop-table", hC+"DROP TABLE IF EXISTS t;"),
	refused("drop-table", nil, hE+"DROP TABLE t;"),

	ok("drop-object", hC+"DROP FUNCTION f(int);"),
	refused("drop-object", nil, hE+"DROP VIEW v;"),

	ok("truncate", hC+"TRUNCATE t;"),
	refused("truncate", nil, hE+"TRUNCATE TABLE t;"),

	ok("create-or-replace", hE+"CREATE OR REPLACE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1; $$;"),
	refused("create-or-replace", nil,
		hE+"CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;",
		hE+"CREATE OR REPLACE FUNCTION public.f() RETURNS int LANGUAGE sql AS $$ SELECT 2 $$;"),

	ok("create-object", hE+"CREATE SEQUENCE s;\nCREATE TYPE mood AS ENUM ('a', 'b');\nCREATE FUNCTION g() RETURNS int LANGUAGE sql AS $b$ SELECT 1 $b$;"),
	ok("comment", hE+"COMMENT ON TABLE t IS 'x; y';"),
	ok("grant", hE+"GRANT SELECT ON t TO r;"),

	ok("revoke", hC+"REVOKE SELECT ON t FROM r;"),
	refused("revoke", nil, hE+"REVOKE SELECT ON t FROM r;"),

	ok("dml-insert", hE+"INSERT INTO plans (id) VALUES ('free') ON CONFLICT DO NOTHING;"),

	ok("dml-backfill", hD+"UPDATE t SET a = 0 WHERE id >= 1 AND id < 1000 AND a IS NULL;"+progress),
	ok("dml-backfill", hE+"CREATE TABLE n (a int);\nDELETE FROM n WHERE a = 1;"),
	refused("dml-backfill", nil, hE+"UPDATE t SET a = 0 WHERE a IS NULL;"),
	refused("dml-backfill", nil, hE+"WITH x AS (DELETE FROM t WHERE a = 0 RETURNING id) SELECT count(*) FROM x;"),

	ok("do-block", hD+"DO $$ BEGIN UPDATE t SET a = 0 WHERE id < 1000; UPDATE schema_meta SET value = '1000' WHERE key = 'bf'; END $$;"),
	refused("do-block", nil, hE+"DO $$ BEGIN PERFORM 1; END $$;"),

	ok("read", hE+"SELECT 1;\nANALYZE t;"),

	ok("unknown", hC+"CREATE ROLE r;"),
	refused("unknown", nil, hE+"LOCK TABLE t IN SHARE MODE;"),
	refused("unknown", nil, hE+"SET ROLE r;\nCREATE TABLE n (a int);"),

	// Step rows.
	ok("label", hE+"CREATE TABLE n (a int);"),
	refused("label", nil, "SET lock_timeout = '5s';\nCREATE TABLE n (a int);"),
	refused("label", nil, "-- step: expand contract\nSET lock_timeout = '5s';\nCREATE TABLE n (a int);"),

	ok("directive", "-- step: expand, non-transactional\nSET lock_timeout = '5s';\nCREATE INDEX CONCURRENTLY i ON t (a);"),
	refused("directive", nil, "-- step: expand online\nSET lock_timeout = '5s';\nCREATE TABLE n (a int);"),

	ok("lock-timeout", "-- step: expand\nSET search_path = public;\nSET LOCAL lock_timeout = '5s';\nCREATE TABLE n (a int);"),
	refused("lock-timeout", nil, "-- step: expand\nCREATE TABLE n (a int);"),
	refused("lock-timeout", nil, "-- step: expand\nCREATE TABLE n (a int);\nSET lock_timeout = '5s';"),
	refused("lock-timeout", nil, "-- step: expand non-transactional\nSET LOCAL lock_timeout = '5s';\nCREATE INDEX CONCURRENTLY i ON t (a);"),

	ok("policy-own-step", hE+"CREATE POLICY p ON t USING (true);\nALTER TABLE t FORCE ROW LEVEL SECURITY;"),
	ok("policy-own-step", hE+"CREATE TABLE n (org_id text);\nALTER TABLE n ENABLE ROW LEVEL SECURITY;\nCREATE POLICY p ON n USING (true);"),
	refused("policy-own-step", nil, hE+"ALTER TABLE t ADD COLUMN c text;\nCREATE POLICY p ON t USING (true);"),
	refused("policy-own-step", nil, hE+"ALTER TABLE t ADD COLUMN c text, ENABLE ROW LEVEL SECURITY;"),

	ok("add-value-own-step", hE+"ALTER TYPE mood ADD VALUE 'meh';\nALTER TYPE mood ADD VALUE 'ok';"),
	refused("add-value-own-step", nil, hE+"ALTER TYPE mood ADD VALUE 'meh';\nCREATE TABLE n (a int);"),

	ok("non-transactional-one-statement", hN+"CREATE INDEX CONCURRENTLY i ON t (a);"),
	refused("non-transactional-one-statement", nil, hN+"CREATE INDEX CONCURRENTLY i ON t (a);\nCREATE INDEX CONCURRENTLY j ON t (b);"),

	ok("data-step", hD+"UPDATE t SET a = 0 WHERE id >= 1 AND id < 1000;"+progress),
	refused("data-step", []string{"data-step", "data-step", "data-step", "data-step"},
		"-- step: data\nSET lock_timeout = '5s';\nUPDATE t SET a = 0;\nALTER TABLE t ADD COLUMN c int;"),

	ok("size-note", hCS+"ALTER TABLE t ALTER COLUMN a TYPE bigint;"),
	refused("size-note", nil, hC+"ALTER TABLE t ALTER COLUMN a TYPE bigint;"),

	{
		row: "manifest-row", ok: true, steps: []string{hE + "CREATE TABLE n (a int);"},
		manifest: func(string, string) bool { return true },
	},
	{
		row: "manifest-row", steps: []string{hE + "CREATE TABLE n (a int);"},
		manifest: func(_, table string) bool { return table != "n" },
	},
}

// runCase runs a sample's steps as lineage "test" (no pre-migcheck head) and
// returns the last step's findings and state.
func runCase(t *testing.T, tc ruleCase) ([]Finding, []Finding, *stepState) {
	t.Helper()
	lin := newLineageState()
	var earlier, last []Finding
	var st *stepState
	for i, sql := range tc.steps {
		f, s := checkStep(Step{Lineage: "test", Version: 1000 + i, Name: fmt.Sprintf("%04d_case.sql", 1000+i), SQL: sql}, lin, tc.manifest)
		if i == len(tc.steps)-1 {
			last, st = f, s
		} else {
			earlier = append(earlier, f...)
		}
	}
	return earlier, last, st
}

func TestRuleRows(t *testing.T) {
	t.Parallel()
	for i, tc := range ruleCases {
		name := fmt.Sprintf("%s/%d", tc.row, i)
		if tc.ok {
			name += "/allowed"
		} else {
			name += "/refused"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			earlier, last, st := runCase(t, tc)
			if len(earlier) > 0 {
				t.Fatalf("an earlier step of the sample has findings: %v", earlier)
			}
			if tc.ok {
				if len(last) > 0 {
					t.Fatalf("allowed sample has findings: %v", last)
				}
				if isStatementRow(tc.row) && !classified(st, tc.row) {
					t.Fatalf("no unit of the sample was classified by row %s", tc.row)
				}
				return
			}
			want := tc.want
			if want == nil {
				want = []string{tc.row}
			}
			var got []string
			for _, f := range last {
				got = append(got, f.Rule)
			}
			sort.Strings(got)
			want = append([]string(nil), want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("findings %v, want rules %v", last, want)
			}
		})
	}
}

func isStatementRow(id string) bool {
	for _, r := range statementRules {
		if r.id == id {
			return true
		}
	}
	return false
}

func classified(st *stepState, id string) bool {
	if st == nil {
		return false
	}
	for _, u := range st.units {
		if u.rule == id {
			return true
		}
	}
	return false
}

// TestEveryRuleRowHasSamples: every row of both tables has an allowed
// sample, and every row that can refuse has a refused one.
func TestEveryRuleRowHasSamples(t *testing.T) {
	t.Parallel()
	alwaysRefuses := map[string]bool{"transaction-control": true}
	allowed, refusedRows := map[string]bool{}, map[string]bool{}
	for _, tc := range ruleCases {
		if tc.ok {
			allowed[tc.row] = true
		} else {
			refusedRows[tc.row] = true
		}
	}
	seen := map[string]bool{}
	for _, r := range statementRules {
		if seen[r.id] {
			t.Errorf("statement row id %s is used twice", r.id)
		}
		seen[r.id] = true
		if !allowed[r.id] && !alwaysRefuses[r.id] {
			t.Errorf("statement row %s has no allowed sample", r.id)
		}
		if r.check != nil && !refusedRows[r.id] && r.id != "create-object" {
			t.Errorf("statement row %s can refuse but has no refused sample", r.id)
		}
		if r.plan == "" {
			t.Errorf("statement row %s has no plan text", r.id)
		}
	}
	for _, r := range stepRules {
		if seen[r.id] {
			t.Errorf("step row id %s is used twice", r.id)
		}
		seen[r.id] = true
		if !allowed[r.id] || !refusedRows[r.id] {
			t.Errorf("step row %s needs an allowed and a refused sample", r.id)
		}
	}
	for row := range allowed {
		if !seen[row] {
			t.Errorf("sample for unknown row %s", row)
		}
	}
	if last := statementRules[len(statementRules)-1]; last.id != "unknown" || !last.match(&unit{}) {
		t.Error("the statement table's last row must be the catch-all unknown row")
	}
}

func TestManifestRuleNilChecksNothing(t *testing.T) {
	t.Parallel()
	_, last, _ := runCase(t, ruleCase{steps: []string{hE + "CREATE TABLE n (a int);"}})
	if len(last) > 0 {
		t.Fatalf("with no manifest the rule checks nothing, got %v", last)
	}
}

func TestContractDoesNotWaiveBlockingIndexBuild(t *testing.T) {
	t.Parallel()
	_, last, _ := runCase(t, ruleCase{steps: []string{hCN + "CREATE INDEX i ON t (a);"}})
	if len(last) != 1 || last[0].Rule != "create-index" {
		t.Fatalf("findings %v, want create-index: contract does not allow a blocking index build", last)
	}
}

// TestDataStepByLineageCapability: one case per lineageCapabilities row (and
// the default) for the data-step rule's resume requirement (L-79). A lineage
// whose runner keeps a progress table needs the progress write; one whose
// runner keeps none needs the step transactional instead, and both keep the
// statement_timeout and bounded-WHERE requirements.
func TestDataStepByLineageCapability(t *testing.T) {
	t.Parallel()
	const (
		bounded   = "UPDATE t SET a = 0 WHERE id >= 1 AND id < 1000;"
		unbounded = "UPDATE t SET a = 0;"
		// hDN is a non-transactional data header (plain SETs: SET LOCAL has
		// no effect outside a transaction).
		hDN = "-- step: data non-transactional\nSET lock_timeout = '5s';\nSET statement_timeout = '60s';\n"
		// hDNoTimeout is a data header without its statement_timeout.
		hDNoTimeout = "-- step: data\nSET LOCAL lock_timeout = '5s';\n"
	)
	cases := []struct {
		name, lineage, sql string
		want               []string // the data-step findings' required texts, in order
	}{
		{name: "org-pg: progress in schema_meta passes", lineage: LineageOrgPG, sql: hD + bounded + progress},
		{
			name: "org-pg: no progress row is refused", lineage: LineageOrgPG, sql: hD + bounded,
			want: []string{"the step's progress recorded in schema_meta, so it resumes"},
		},
		{name: "cloud: a transactional data step without a progress row passes (0079's shape)", lineage: LineageCloud, sql: hD + bounded},
		{
			name: "cloud: a non-transactional data step is refused", lineage: LineageCloud, sql: hDN + bounded,
			want: []string{"a transactional data step: this lineage's runner keeps no data-step progress table, so a data step commits whole or not at all (drop non-transactional)"},
		},
		{
			name: "cloud: an unbounded data step is still refused", lineage: LineageCloud, sql: hD + unbounded,
			want: []string{"a WHERE bounding the batch by key range"},
		},
		{
			name: "cloud: a data step without statement_timeout is still refused", lineage: LineageCloud, sql: hDNoTimeout + bounded,
			want: []string{"SET statement_timeout: a data step carries its own"},
		},
		{
			name: "a lineage with no row needs the schema_meta progress write", lineage: "test", sql: hD + bounded,
			want: []string{"the step's progress recorded in schema_meta, so it resumes"},
		},
		{name: "a lineage with no row accepts a non-transactional data step that records progress", lineage: "test", sql: hDN + "DO $$ BEGIN UPDATE t SET a = 0 WHERE id < 1000; UPDATE schema_meta SET value = '1000' WHERE key = 'bf'; END $$;"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			found, _ := checkStep(Step{Lineage: tc.lineage, Version: 1000, Name: "1000_case.sql", SQL: tc.sql}, newLineageState(), nil)
			var got []string
			for _, f := range found {
				if f.Rule != "data-step" {
					t.Errorf("unexpected finding outside the data-step row: %s", f)
					continue
				}
				got = append(got, f.Required)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("data-step findings %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEveryLineageHasACapabilityRow: every lineage migcheck covers has a
// lineageCapabilities row, so a new lineage cannot fall to the default by
// omission, and every row names a covered lineage.
func TestEveryLineageHasACapabilityRow(t *testing.T) {
	t.Parallel()
	for _, l := range Lineages() {
		if _, ok := lineageCapabilities[l]; !ok {
			t.Errorf("lineage %s has no lineageCapabilities row", l)
		}
	}
	for l := range lineageCapabilities {
		if _, ok := preMigcheckHeads[l]; !ok {
			t.Errorf("lineageCapabilities row %s is not a lineage migcheck covers", l)
		}
	}
}
