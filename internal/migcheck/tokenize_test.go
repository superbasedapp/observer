package migcheck

import (
	"reflect"
	"strings"
	"testing"
)

func TestLex(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		src     string
		want    []string // each statement's excerpt
		header  []string // header comment bodies, trimmed
		wantErr string
	}{
		{
			name: "two statements, last without semicolon",
			src:  "CREATE TABLE a (x int);\nCREATE TABLE b (y int)",
			want: []string{"CREATE TABLE a (x int)", "CREATE TABLE b (y int)"},
		},
		{
			name: "empty statements are dropped",
			src:  ";;SELECT 1;;",
			want: []string{"SELECT 1"},
		},
		{
			name: "line comment hides a semicolon",
			src:  "SELECT 1 -- not; a split\n+ 1;",
			want: []string{"SELECT 1 -- not; a split + 1"},
		},
		{
			name: "nested block comment hides semicolons and quotes",
			src:  "SELECT /* a; /* b; ' */ c; */ 2; SELECT 3",
			want: []string{"SELECT /* a; /* b; ' */ c; */ 2", "SELECT 3"},
		},
		{
			name: "single-quoted string with a doubled quote",
			src:  "INSERT INTO t VALUES ('it''s; fine'); SELECT 1",
			want: []string{"INSERT INTO t VALUES ('it''s; fine')", "SELECT 1"},
		},
		{
			name: "E string with a backslash-escaped quote",
			src:  `SELECT E'a\'; b'; SELECT 2`,
			want: []string{`SELECT E'a\'; b'`, "SELECT 2"},
		},
		{
			name: "standard string: a backslash is literal",
			src:  `SELECT 'a\'; SELECT 2`,
			want: []string{`SELECT 'a\'`, "SELECT 2"},
		},
		{
			name: "quoted identifier with a semicolon and a doubled quote",
			src:  `CREATE TABLE "we;ird""t" (x int); SELECT 1`,
			want: []string{`CREATE TABLE "we;ird""t" (x int)`, "SELECT 1"},
		},
		{
			name: "dollar-quoted body",
			src:  "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1; SELECT 2; $$; SELECT 3",
			want: []string{"CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1; SELECT 2; $$", "SELECT 3"},
		},
		{
			name: "tagged dollar quote containing $$",
			src:  "DO $fn$ BEGIN EXECUTE $$ SELECT 1; $$; END $fn$; SELECT 2",
			want: []string{"DO $fn$ BEGIN EXECUTE $$ SELECT 1; $$; END $fn$", "SELECT 2"},
		},
		{
			name: "positional parameter is not a dollar quote",
			src:  "SELECT $1; SELECT 2",
			want: []string{"SELECT $1", "SELECT 2"},
		},
		{
			name: "dollar inside an identifier",
			src:  "SELECT a$b; SELECT 2",
			want: []string{"SELECT a$b", "SELECT 2"},
		},
		{
			name:   "header comments only before the first statement",
			src:    "-- step: expand\n/* block */\n-- size: big\nSELECT 1;\n-- step: contract\nSELECT 2;",
			want:   []string{"SELECT 1", "SELECT 2"},
			header: []string{"step: expand", "size: big"},
		},
		{
			name:   "CRLF line endings",
			src:    "-- step: data\r\nSELECT 1;\r\n",
			want:   []string{"SELECT 1"},
			header: []string{"step: data"},
		},
		{name: "unterminated string", src: "SELECT 'abc", wantErr: "unterminated string"},
		{name: "unterminated quoted identifier", src: `SELECT "abc`, wantErr: "unterminated quoted identifier"},
		{name: "unterminated block comment", src: "SELECT /* /* */ 1", wantErr: "unterminated block comment"},
		{name: "unterminated dollar quote", src: "SELECT $x$ abc $y$", wantErr: "unterminated dollar-quoted string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lx, err := lex(tc.src)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, s := range lx.stmts {
				got = append(got, excerpt(tc.src, s.start, s.end))
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("statements = %q, want %q", got, tc.want)
			}
			var hdr []string
			for _, h := range lx.header {
				hdr = append(hdr, strings.TrimSpace(h))
			}
			if !reflect.DeepEqual(hdr, tc.header) {
				t.Errorf("header = %q, want %q", hdr, tc.header)
			}
		})
	}
}

func TestLexDepthAndIdent(t *testing.T) {
	t.Parallel()
	lx, err := lex(`ALTER TABLE "Mixed".T ADD CHECK ((a IS NOT NULL)), ADD COLUMN b int`)
	if err != nil {
		t.Fatal(err)
	}
	units := splitUnits(`ALTER TABLE "Mixed".T ADD CHECK ((a IS NOT NULL)), ADD COLUMN b int`, 0, lx.stmts[0])
	if len(units) != 2 {
		t.Fatalf("units = %d, want 2 (the comma inside the parentheses does not split)", len(units))
	}
	if units[0].table != "t" {
		t.Errorf("table = %q, want the folded last part t", units[0].table)
	}
	if got := notNullColumn(units[0].action[2:]); got != "a" {
		t.Errorf("notNullColumn = %q, want a", got)
	}
	if units[1].excerpt != `ALTER TABLE "Mixed".T ADD COLUMN b int` {
		t.Errorf("excerpt = %q", units[1].excerpt)
	}
}

func TestExcerptTruncates(t *testing.T) {
	t.Parallel()
	src := "SELECT " + strings.Repeat("x, ", 100)
	got := excerpt(src, 0, len(src))
	if !strings.HasSuffix(got, "...") || len([]rune(got)) != 123 {
		t.Errorf("excerpt = %q (%d runes)", got, len([]rune(got)))
	}
}

func TestReadDirectives(t *testing.T) {
	t.Parallel()
	cases := []struct {
		src  string
		want Directives
	}{
		{"-- step: expand\nSELECT 1", Directives{Label: "expand"}},
		{"-- step: contract, non-transactional\n-- size: 2 GB; 4 min\nSELECT 1", Directives{Label: "contract", NonTransactional: true, SizeNote: "2 GB; 4 min"}},
		{"-- step: non-transactional\n-- step: Data\nSELECT 1", Directives{Label: "data", NonTransactional: true}},
		{"-- step: expand contract\nSELECT 1", Directives{}},
		{"SELECT 1;\n-- step: expand", Directives{}},
	}
	for _, tc := range cases {
		got, err := ReadDirectives(tc.src)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("ReadDirectives(%q) = %+v, want %+v", tc.src, got, tc.want)
		}
	}
	if _, err := ReadDirectives("SELECT 'x"); err == nil || !strings.Contains(err.Error(), "migcheck.ReadDirectives") {
		t.Errorf("err = %v, want a wrapped tokenizer error", err)
	}
}
