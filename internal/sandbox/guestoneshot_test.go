package sandbox

import (
	"reflect"
	"strings"
	"testing"
)

// TestStagedDiffPlan: the one-shot never lets a repository's config run a
// diff driver, a textconv filter or a pager, and parses only its one flag.
func TestStagedDiffPlan(t *testing.T) {
	t.Parallel()
	want := []string{"git", "--no-pager", "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--binary", "--cached"}
	if got := StagedDiffArgv(false); !reflect.DeepEqual(got, want) {
		t.Fatalf("staged argv %v", got)
	}
	if got := StagedDiffArgv(true); got[len(got)-1] != "HEAD" {
		t.Fatalf("all argv %v", got)
	}
	for _, tc := range []struct {
		args    []string
		all, ok bool
	}{
		{nil, false, true},
		{[]string{"--all"}, true, true},
		{[]string{"--all", "x"}, false, false},
		{[]string{"--output=/etc/x"}, false, false},
	} {
		all, ok := ParseStagedDiffArgs(tc.args)
		if all != tc.all || ok != tc.ok {
			t.Errorf("%v: all %v ok %v", tc.args, all, ok)
		}
	}
}

// TestDBCopyArgsAndNames (lane SBX-P3B, SBX-BE-10): the db-copy one-shot
// takes exactly --root and --out, both absolute and clean, never the same
// or --out above --root; the copy names are digests of the relative path,
// and the host accepts only such a name.
func TestDBCopyArgsAndNames(t *testing.T) {
	good := []string{DBCopyRootFlag, "/home/dev/.claude", DBCopyOutFlag, "/home/dev/.claude/.observer-dbcopy"}
	if r, ok := ParseDBCopyArgs(good); !ok || r.Root != "/home/dev/.claude" || r.Out != "/home/dev/.claude/.observer-dbcopy" {
		t.Fatalf("%+v %v", r, ok)
	}
	for _, bad := range [][]string{
		nil,
		{DBCopyRootFlag, "/a"},
		{DBCopyOutFlag, "/a", DBCopyRootFlag, "/b"},
		{DBCopyRootFlag, "rel", DBCopyOutFlag, "/b"},
		{DBCopyRootFlag, "/a/../b", DBCopyOutFlag, "/c"},
		{DBCopyRootFlag, "/", DBCopyOutFlag, "/c"},
		{DBCopyRootFlag, "/a", DBCopyOutFlag, "/a"},
		{DBCopyRootFlag, "/a/b", DBCopyOutFlag, "/a"},
	} {
		if _, ok := ParseDBCopyArgs(bad); ok {
			t.Errorf("accepted %v", bad)
		}
	}
	n := DBCopyName("projects/x/history.db")
	if !ValidDBCopyName(n) || n == DBCopyName("projects/x/other.db") {
		t.Fatalf("name %q", n)
	}
	for _, bad := range []string{"passwd", "../" + n, strings.ToUpper(n), n[:66], n + "x"} {
		if ValidDBCopyName(bad) {
			t.Errorf("accepted name %q", bad)
		}
	}
	if len(SQLiteHeader) != 16 || SQLiteHeader[15] != 0 {
		t.Fatalf("SQLite header %q", SQLiteHeader)
	}
	argv := DBCopyArgv("/usr/bin/observer", "/r", "/r/o")
	if argv[1] != GuestVerb || argv[2] != GuestDBCopy {
		t.Fatalf("argv %v", argv)
	}
}
