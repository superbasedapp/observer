package nontx

import (
	"reflect"
	"strings"
	"testing"
)

// TestParseKinds has one accepted case per kinds-table row (and its
// variants), checking the kind, the probe and the names the runner probes.
func TestParseKinds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		sql   string
		want  Statement
		param []string
	}{
		{
			name: "create index row",
			sql:  "-- step: expand non-transactional\nSET lock_timeout = '5s';\nCREATE INDEX CONCURRENTLY ix_a ON t (a);\n",
			want: Statement{Kind: KindCreateIndex, Text: "CREATE INDEX CONCURRENTLY ix_a ON t (a)", Probe: ProbeIndex, Index: "ix_a", Table: "t"},
		},
		{
			name: "create unique index if not exists on a qualified table",
			sql:  "SET lock_timeout TO '5s'; create unique index concurrently if not exists ux ON ONLY s.t (a) WHERE b = 'x;y'",
			want: Statement{Kind: KindCreateIndex, Text: "create unique index concurrently if not exists ux ON ONLY s.t (a) WHERE b = 'x;y'", Probe: ProbeIndex, Index: "s.ux", Table: "s.t"},
		},
		{
			name: "create index with quoted names, comments and a dollar quote",
			sql:  "SET lock_timeout = '5s';\nCREATE INDEX CONCURRENTLY \"Ix;\" /* a; /* nested; */ */ ON \"S\".\"T\" (lower(a)) WHERE b <> $$;$$ -- trailing; comment\n;",
			want: Statement{Kind: KindCreateIndex, Text: "CREATE INDEX CONCURRENTLY \"Ix;\" /* a; /* nested; */ */ ON \"S\".\"T\" (lower(a)) WHERE b <> $$;$$", Probe: ProbeIndex, Index: "\"S\".\"Ix;\"", Table: "\"S\".\"T\""},
		},
		{
			name: "drop index row",
			sql:  "SET lock_timeout = '5s'; DROP INDEX CONCURRENTLY IF EXISTS s.ix_a;",
			want: Statement{Kind: KindDropIndex, Text: "DROP INDEX CONCURRENTLY IF EXISTS s.ix_a", Probe: ProbeIndex, Index: "s.ix_a"},
		},
		{
			name: "drop index restrict",
			sql:  "SET lock_timeout = '5s'; DROP INDEX CONCURRENTLY ix_a RESTRICT",
			want: Statement{Kind: KindDropIndex, Text: "DROP INDEX CONCURRENTLY ix_a RESTRICT", Probe: ProbeIndex, Index: "ix_a"},
		},
		{
			name: "reindex index row",
			sql:  "SET lock_timeout = '5s'; REINDEX (VERBOSE) INDEX CONCURRENTLY ix_a;",
			want: Statement{Kind: KindReindexIndex, Text: "REINDEX (VERBOSE) INDEX CONCURRENTLY ix_a", Probe: ProbeLeftovers, Index: "ix_a"},
		},
		{
			name: "reindex table row",
			sql:  "SET lock_timeout = '5s'; REINDEX TABLE CONCURRENTLY s.t;",
			want: Statement{Kind: KindReindexTable, Text: "REINDEX TABLE CONCURRENTLY s.t", Probe: ProbeLeftovers, Table: "s.t"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Parse(tc.sql)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got.Statement, tc.want) {
				t.Fatalf("Statement = %+v\nwant        %+v", got.Statement, tc.want)
			}
		})
	}
}

// TestKindsTableCovered pins one accepted case above per kinds-table row.
func TestKindsTableCovered(t *testing.T) {
	t.Parallel()
	want := []Kind{KindCreateIndex, KindDropIndex, KindReindexIndex, KindReindexTable}
	var got []Kind
	for _, k := range kinds {
		got = append(got, k.kind)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("kinds table = %v, want %v (add a TestParseKinds case for a new row)", got, want)
	}
	if len(Shapes()) != len(kinds) {
		t.Fatalf("Shapes() has %d rows, want %d", len(Shapes()), len(kinds))
	}
}

// TestParseHeaders pins the header split: SETs before and after the statement
// keep their order, LOCAL and SESSION are headers, and Params resets each
// parameter once.
func TestParseHeaders(t *testing.T) {
	t.Parallel()
	got, err := Parse("SET lock_timeout = '5s';\nSET SESSION maintenance_work_mem = '1GB';\nCREATE INDEX CONCURRENTLY ix ON t (a);\nSET LOCAL lock_timeout = '1s';\nSET lock_timeout = DEFAULT;\n")
	if err != nil {
		t.Fatal(err)
	}
	var before, after []string
	for _, h := range got.Before {
		before = append(before, h.Text)
	}
	for _, h := range got.After {
		after = append(after, h.Text)
	}
	if want := []string{"SET lock_timeout = '5s'", "SET SESSION maintenance_work_mem = '1GB'"}; !reflect.DeepEqual(before, want) {
		t.Errorf("Before = %q, want %q", before, want)
	}
	if want := []string{"SET LOCAL lock_timeout = '1s'", "SET lock_timeout = DEFAULT"}; !reflect.DeepEqual(after, want) {
		t.Errorf("After = %q, want %q", after, want)
	}
	if got.Statement.Kind != KindCreateIndex {
		t.Errorf("Kind = %q", got.Statement.Kind)
	}
}

// TestParseParams pins Params: every header parameter once, folded, in order.
func TestParseParams(t *testing.T) {
	t.Parallel()
	got, err := Parse("SET lock_timeout = '5s'; SET LOCAL WORK_MEM = '64MB'; CREATE INDEX CONCURRENTLY ix ON t (a); SET Lock_Timeout = DEFAULT;")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"lock_timeout", "work_mem"}; !reflect.DeepEqual(got.Params(), want) {
		t.Fatalf("Params = %q, want %q", got.Params(), want)
	}
}

// TestParseRefusals has one case per way a non-transactional step is refused.
func TestParseRefusals(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		sql  string
		want string
	}{
		{"no statement", "-- step: expand non-transactional\nSET lock_timeout = '5s';\n", "found none"},
		{"empty", "", "found none"},
		{"two statements", "SET lock_timeout = '5s'; CREATE INDEX CONCURRENTLY a ON t (x); CREATE INDEX CONCURRENTLY b ON t (y);", "found another"},
		{"a mixed-case quoted parameter is not a header", "SET \"Lock_timeout\" = '1s'; CREATE INDEX CONCURRENTLY a ON t (x);", "not an allowed non-transactional statement"},
		{"a SET of another parameter is a statement", "SET role = admin; CREATE INDEX CONCURRENTLY a ON t (x);", "not an allowed non-transactional statement"},
		{"an insert", "INSERT INTO t VALUES (1)", "not an allowed non-transactional statement"},
		{"a transactional index build", "CREATE INDEX ix ON t (a)", "CONCURRENTLY is required"},
		{"an unnamed index", "CREATE INDEX CONCURRENTLY ON t (a)", "needs a name"},
		{"a qualified index name", "CREATE INDEX CONCURRENTLY s.ix ON t (a)", "unqualified index name"},
		{"no table", "CREATE INDEX CONCURRENTLY ix", "ON table is required"},
		{"drop without concurrently", "DROP INDEX ix", "CONCURRENTLY is required"},
		{"drop of two indexes", "DROP INDEX CONCURRENTLY a, b", "exactly one index"},
		{"drop cascade", "DROP INDEX CONCURRENTLY a CASCADE", "exactly one index"},
		{"reindex without concurrently", "REINDEX INDEX ix", "CONCURRENTLY is required"},
		{"reindex concurrently as an option", "REINDEX (CONCURRENTLY) INDEX ix", "not as an option"},
		{"reindex schema", "REINDEX SCHEMA CONCURRENTLY s", "not an allowed non-transactional statement"},
		{"reindex without a name", "REINDEX TABLE CONCURRENTLY", "exactly one name"},
		{"unterminated string", "CREATE INDEX CONCURRENTLY ix ON t (a) WHERE b = 'x", "unterminated string"},
		{"unterminated block comment", "CREATE INDEX CONCURRENTLY ix ON t (a) /* x", "unterminated block comment"},
		{"unterminated quoted identifier", "CREATE INDEX CONCURRENTLY \"ix ON t (a)", "unterminated quoted identifier"},
		{"unterminated dollar quote", "CREATE INDEX CONCURRENTLY ix ON t (a) WHERE b = $q$x", "unterminated dollar-quoted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(tc.sql)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse(%q) err = %v, want one containing %q", tc.sql, err, tc.want)
			}
		})
	}
}

// TestSplit pins the splitter on the token classes that can hide a semicolon.
func TestSplit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		sql  string
		want []string
	}{
		{"plain", "a; b ;c", []string{"a", "b", "c"}},
		{"line comment", "a -- x; y\n; b", []string{"a", "b"}},
		{"block comment", "a /* x; /* y; */ z; */ c; b /* t; */", []string{"a /* x; /* y; */ z; */ c", "b"}},
		{"string", "a 'x;''y'; b", []string{"a 'x;''y'", "b"}},
		{"escape string", `a E'x\';y'; b`, []string{`a E'x\';y'`, "b"}},
		{"quoted identifier", `a "x;""y"; b`, []string{`a "x;""y"`, "b"}},
		{"unicode string and identifier", `a U&'x;' U&"y;"; b`, []string{`a U&'x;' U&"y;"`, "b"}},
		{"dollar quote", "a $$x;y$$; b $t$;$t$; c $1; d", []string{"a $$x;y$$", "b $t$;$t$", "c $1", "d"}},
		{"leading comment and blank statements", "-- head;\n;; a;", []string{"a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stmts, err := split(tc.sql)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, s := range stmts {
				got = append(got, s.text)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("split(%q) = %q, want %q", tc.sql, got, tc.want)
			}
		})
	}
}
