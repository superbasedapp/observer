package migcheck

import (
	"reflect"
	"testing"
)

// TestStatements pins the per-statement view the upgrade preflight reads: one
// case per shape it distinguishes.
func TestStatements(t *testing.T) {
	t.Parallel()
	hdr := "-- step: contract\nSET LOCAL lock_timeout = '5s';\n"
	cases := []struct {
		name string
		sql  string
		want []StatementInfo
	}{
		{
			"add column, stable default",
			hdr + "ALTER TABLE budgets ADD COLUMN org_id TEXT NOT NULL DEFAULT sbo_default_org();",
			[]StatementInfo{{Rule: "set-lock-timeout"}, {Rule: "add-column", Table: "budgets"}},
		},
		{
			"volatile default",
			hdr + "ALTER TABLE t ADD COLUMN u uuid DEFAULT gen_random_uuid();",
			[]StatementInfo{{Rule: "set-lock-timeout"}, {Rule: "add-column-volatile-default", Table: "t"}},
		},
		{
			"index, plain and concurrent",
			hdr + "CREATE INDEX i ON t (a);\nCREATE INDEX CONCURRENTLY j ON t (b);",
			[]StatementInfo{{Rule: "set-lock-timeout"}, {Rule: "create-index", Table: "t"}, {Rule: "create-index", Table: "t", Concurrently: true}},
		},
		{
			"constraint using index, not valid",
			hdr + "ALTER TABLE t ADD CONSTRAINT u UNIQUE USING INDEX i;\nALTER TABLE t ADD CONSTRAINT c CHECK (a > 0) NOT VALID;",
			[]StatementInfo{{Rule: "set-lock-timeout"}, {Rule: "add-constraint-unique-pk", Table: "t", UsingIndex: true}, {Rule: "add-constraint-fk-check", Table: "t", NotValid: true}},
		},
		{
			"do block body is read",
			hdr + "DO $x$ BEGIN ALTER TABLE a DROP CONSTRAINT a_pkey, ADD CONSTRAINT a_pkey PRIMARY KEY (org_id, id); DROP INDEX i; END $x$;",
			[]StatementInfo{
				{Rule: "set-lock-timeout"},
				{Rule: "do-block"},
				{Rule: "drop-constraint", Table: "a", InDoBlock: true},
				{Rule: "add-constraint-unique-pk", Table: "a", InDoBlock: true},
				{Rule: "drop-index", InDoBlock: true},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Statements(tc.sql)
			if err != nil {
				t.Fatal(err)
			}
			for i := range got {
				got[i].Excerpt = "" // excerpts are covered by the findings tests
			}
			// The do-block unit itself carries no table.
			for i := range tc.want {
				tc.want[i].Excerpt = ""
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Statements() =\n%+v\nwant\n%+v", got, tc.want)
			}
		})
	}
}
