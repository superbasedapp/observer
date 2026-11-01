package gitalias

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseConfigList(t *testing.T) {
	t.Parallel()
	out := []byte("alias.ci\ncommit -n\x00alias.ST\nstatus\x00alias.p\n!git push --no-verify \"$@\"\x00not.alias\nx\x00alias.ci\ncommit --no-verify\x00")
	got := ParseConfigList(out)
	want := map[string]string{"ci": "commit --no-verify", "st": "status", "p": `!git push --no-verify "$@"`}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("alias %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestLookup(t *testing.T) {
	t.Parallel()
	tbl := &Table{Projects: []Project{
		{Root: "/home/u/proj", Aliases: map[string]string{"ci": "commit -n"}},
		{Root: "/home/u/proj/vendor/sub", Aliases: map[string]string{"ci": "commit"}},
		{Root: `C:\Users\u\repo`, Aliases: map[string]string{"x": "push --no-verify"}},
	}}
	cases := []struct {
		dir    string
		ok     bool
		wantCI string
		wantX  string
	}{
		{"/home/u/proj", true, "commit -n", ""},
		{"/home/u/proj/src/", true, "commit -n", ""},
		{"/home/u/proj/vendor/sub/a", true, "commit", ""},
		{"/home/u/project2", false, "", ""},
		{`c:/users/U/repo/src`, true, "", "push --no-verify"},
		{"", false, "", ""},
	}
	for _, tc := range cases {
		got, ok := tbl.Lookup(tc.dir)
		if ok != tc.ok || got["ci"] != tc.wantCI || got["x"] != tc.wantX {
			t.Errorf("Lookup(%q) = %v, %v", tc.dir, got, ok)
		}
	}
	var nilTable *Table
	if _, ok := nilTable.Lookup("/home/u/proj"); ok {
		t.Error("nil table covered a directory")
	}
}

func TestWriteLoadRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := Path(filepath.Join(dir, "observer.db"))
	if got, err := Load(p); got != nil || err != nil {
		t.Fatalf("missing file: %v, %v", got, err)
	}
	in := Table{WrittenAt: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), Projects: []Project{
		{Root: "/b", Aliases: map[string]string{"x": "y"}},
		{Root: "/a"},
	}}
	if err := Write(p, in); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil || got == nil {
		t.Fatalf("Load: %v, %v", got, err)
	}
	if got.Schema != Schema || len(got.Projects) != 2 || got.Projects[0].Root != "/a" || got.Projects[1].Aliases["x"] != "y" {
		t.Fatalf("round trip: %+v", got)
	}
	if err := os.WriteFile(p, []byte(`{"schema":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Error("another schema loaded")
	}
	if err := os.WriteFile(p, []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Error("malformed file loaded")
	}
}
