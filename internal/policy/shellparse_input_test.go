package policy

import (
	"slices"
	"testing"
)

// TestParseInputRedirects pins Command.InputRedirects: the standard-input
// redirect source is captured (R-126 reads it), and every other '<' form
// keeps its old meaning (heredocs, here-strings, other descriptors and "<>"
// leave InputRedirects empty and consume their word as before).
func TestParseInputRedirects(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		line    string
		dialect Dialect
		argv    []string
		inputs  []string
		outputs []string
	}{
		{name: "plain input redirect", line: "mysql app < dump.sql", argv: []string{"mysql", "app"}, inputs: []string{"dump.sql"}},
		{name: "fd 0 with a space", line: "psql 0< x.sql", argv: []string{"psql"}, inputs: []string{"x.sql"}},
		{name: "fd 0 attached", line: "psql 0<x.sql", argv: []string{"psql"}, inputs: []string{"x.sql"}},
		{name: "attached to the command word", line: "sqlite3 app.db<x.sql", argv: []string{"sqlite3", "app.db"}, inputs: []string{"x.sql"}},
		{name: "quoted source", line: `mysql app < 'my dump.sql'`, argv: []string{"mysql", "app"}, inputs: []string{"my dump.sql"}},
		{name: "another descriptor is not stdin", line: "cat 3< x.sql", argv: []string{"cat"}},
		{name: "here-string is not a file", line: `cat <<< "hello"`, argv: []string{"cat"}},
		{name: "unrecognised heredoc introducer", line: "cat << EOF", argv: []string{"cat"}},
		{name: "read-write redirect stays an output target", line: "cmd <> f", argv: []string{"cmd"}, outputs: []string{"f"}},
		{name: "input and output", line: "sort < in.txt > out.txt", argv: []string{"sort"}, inputs: []string{"in.txt"}, outputs: []string{"out.txt"}},
		{name: "cmd dialect", line: `sqlcmd -S sql01 < C:\scripts\x.sql`, dialect: DialectCmd, argv: []string{"sqlcmd", "-S", "sql01"}, inputs: []string{`C:\scripts\x.sql`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmds := ParseCommand(tc.line, tc.dialect)
			if len(cmds) != 1 {
				t.Fatalf("got %d units (%s), want 1", len(cmds), bases(cmds))
			}
			c := cmds[0]
			if !slices.Equal(c.Argv, tc.argv) {
				t.Errorf("argv = %q, want %q", c.Argv, tc.argv)
			}
			if !slices.Equal(c.InputRedirects, tc.inputs) {
				t.Errorf("input redirects = %q, want %q", c.InputRedirects, tc.inputs)
			}
			if !slices.Equal(c.RedirectTargets, tc.outputs) {
				t.Errorf("output redirects = %q, want %q", c.RedirectTargets, tc.outputs)
			}
		})
	}

	t.Run("heredoc body is not an input redirect", func(t *testing.T) {
		t.Parallel()
		cmds := ParseCommand("psql <<SQL\nSELECT 1;\nSQL", DialectPosix)
		if len(cmds) != 1 || len(cmds[0].InputRedirects) != 0 || cmds[0].Heredoc == "" {
			t.Fatalf("units = %+v", cmds)
		}
	})

	t.Run("redirect belongs to its own unit", func(t *testing.T) {
		t.Parallel()
		cmds := ParseCommand("mysql < a.sql | tee log; psql", DialectPosix)
		if len(cmds) != 3 {
			t.Fatalf("got %s", bases(cmds))
		}
		if !slices.Equal(cmds[0].InputRedirects, []string{"a.sql"}) || len(cmds[1].InputRedirects) != 0 || len(cmds[2].InputRedirects) != 0 {
			t.Errorf("inputs = %q / %q / %q", cmds[0].InputRedirects, cmds[1].InputRedirects, cmds[2].InputRedirects)
		}
	})
}
