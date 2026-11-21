package gitmodules

import (
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestPure pins the package free of I/O: no database, network, exec,
// filesystem watching or file reads.
func TestPure(t *testing.T) {
	forbidden := []string{"database/sql", "net", "net/http", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify", "io/fs", "path/filepath"}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), n, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if p == bad {
					t.Errorf("%s imports %s; gitmodules is pure", n, p)
				}
			}
		}
	}
}

func TestParse(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []Entry
	}{
		{"empty", "", []Entry{}},
		{"one submodule", "[submodule \"third_party/zlib\"]\n\tpath = third_party/zlib\n\turl = https://github.com/madler/zlib\n", []Entry{{Name: "third_party/zlib", Path: "third_party/zlib"}}},
		{"two, sorted by path, CRLF", "[submodule \"z\"]\r\n\tpath = vendor/z\r\n[submodule \"a\"]\r\n\tpath = vendor/a\r\n", []Entry{{Name: "a", Path: "vendor/a"}, {Name: "z", Path: "vendor/z"}}},
		{"quoted path with a space and an inline comment", "[submodule \"x\"]\n  path = \"deps/my lib\" # pinned\n", []Entry{{Name: "x", Path: "deps/my lib"}}},
		{"semicolon comment and comment lines", "; top\n# also\n[submodule \"x\"]\n; inside\npath = libs/x ; trailing\n", []Entry{{Name: "x", Path: "libs/x"}}},
		{"keys are case-insensitive", "[Submodule \"x\"]\n\tPATH = libs/x\n", []Entry{{Name: "x", Path: "libs/x"}}},
		{"escaped quote in the section name", "[submodule \"we\\\"ird\"]\n\tpath = libs/w\n", []Entry{{Name: "we\"ird", Path: "libs/w"}}},
		{"older dotted header", "[submodule.Legacy]\n\tpath = libs/legacy\n", []Entry{{Name: "legacy", Path: "libs/legacy"}}},
		{"key on the header line", "[submodule \"x\"] path = libs/x\n", []Entry{{Name: "x", Path: "libs/x"}}},
		{"continuation line", "[submodule \"x\"]\n\tpath = libs/\\\nx\n", []Entry{{Name: "x", Path: "libs/x"}}},
		{"the same name twice: the last path wins", "[submodule \"x\"]\n\tpath = old/x\n[submodule \"x\"]\n\tpath = new/x\n", []Entry{{Name: "x", Path: "new/x"}}},
		{"other sections are ignored", "[core]\n\tpath = nope\n[submodule \"x\"]\n\tpath = libs/x\n[branch \"main\"]\n\tpath = nope2\n", []Entry{{Name: "x", Path: "libs/x"}}},
		{"a section with no path is dropped", "[submodule \"x\"]\n\turl = git@example.com:private/x.git\n", []Entry{}},
		{"path cleaned", "[submodule \"x\"]\n\tpath = ./libs//x/\n", []Entry{{Name: "x", Path: "libs/x"}}},
		{"absolute path refused", "[submodule \"x\"]\n\tpath = /etc/x\n", []Entry{}},
		{"escaping path refused", "[submodule \"x\"]\n\tpath = ../outside\n", []Entry{}},
		{"backslash path refused", "[submodule \"x\"]\n\tpath = \"libs\\\\x\"\n", []Entry{}},
		{"drive letter refused", "[submodule \"x\"]\n\tpath = C:/x\n", []Entry{}},
		{"malformed header ends the section", "[submodule \"x\"]\n\tpath = libs/x\n[submodule \"broken]\n\tpath = libs/y\n", []Entry{{Name: "x", Path: "libs/x"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Parse([]byte(c.body))
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Parse:\n got %#v\nwant %#v", got, c.want)
			}
		})
	}
}

// TestParseNeverKeepsTheURL: the url of a submodule (it can name a private
// host) is in no field of what Parse returns.
func TestParseNeverKeepsTheURL(t *testing.T) {
	body := "[submodule \"x\"]\n\tpath = libs/x\n\turl = https://git.corp.example/secret/x.git\n"
	for _, e := range Parse([]byte(body)) {
		if strings.Contains(e.Name+e.Path, "corp.example") || strings.Contains(e.Name+e.Path, "secret") {
			t.Fatalf("an entry carries the url: %+v", e)
		}
	}
	if typ := reflect.TypeOf(Entry{}); typ.NumField() != 2 {
		t.Fatalf("Entry has %d fields; a url field must never be added", typ.NumField())
	}
}

func TestCleanRel(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"a/b", "a/b", true},
		{"a/./b/", "a/b", true},
		{"a/../b", "b", true},
		{"", "", false},
		{".", "", false},
		{"..", "", false},
		{"../a", "", false},
		{"a/../../b", "", false},
		{"/a", "", false},
		{"a\\b", "", false},
		{"C:x", "", false},
		{"a\x00b", "", false},
		{"a\nb", "", false},
	}
	for _, c := range cases {
		got, ok := CleanRel(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("CleanRel(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

const (
	zlibCommit = "cacf7f1d4e3d44d871b605da3b647f07d718623f"
	curlCommit = "c7aef0a945f9b6fb6d3f91716a21dfe2f4ea635f"
)

func TestParseLsFiles(t *testing.T) {
	out := "100644 " + strings.Repeat("a", 40) + " 0\t.gitmodules\x00" +
		"160000 " + strings.ToUpper(zlibCommit) + " 0\tthird_party/zlib\x00" +
		"160000 " + curlCommit + " 0\tthird_party/curl lib\x00" +
		"160000 " + strings.Repeat("b", 40) + " 1\tconflicted\x00" +
		"160000 " + strings.Repeat("c", 40) + " 2\tconflicted\x00" +
		"garbage without a tab\x00" +
		"160000 short\tbad header\x00"
	want := []Gitlink{
		{Path: "third_party/zlib", Object: zlibCommit},
		{Path: "third_party/curl lib", Object: curlCommit},
	}
	if got := ParseLsFiles([]byte(out)); !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseLsFiles:\n got %#v\nwant %#v", got, want)
	}
}

func TestLsFilesArgs(t *testing.T) {
	got := LsFilesArgs([]string{"a", "*b"})
	want := []string{"--literal-pathspecs", "ls-files", "--stage", "-z", "--", "a", "*b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LsFilesArgs = %v", got)
	}
}

func TestValidCommit(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{zlibCommit, true},
		{strings.ToUpper(zlibCommit), false},
		{zlibCommit[:7], false},
		{strings.Repeat("0", 40), false},
		{strings.Repeat("a", 64), false},
		{strings.Repeat("g", 40), false},
		{"", false},
	}
	for _, c := range cases {
		if got := ValidCommit(c.in); got != c.ok {
			t.Errorf("ValidCommit(%q) = %v", c.in, got)
		}
	}
}

func TestJoin(t *testing.T) {
	entries := []Entry{
		{Name: "zlib", Path: "zlib"},
		{Name: "curl", Path: "curl"},
		{Name: "stale", Path: "stale"},
		{Name: "sha256", Path: "sha256"},
	}
	links := []Gitlink{
		{Path: "zlib", Object: zlibCommit},
		{Path: "curl", Object: curlCommit},
		{Path: "sha256", Object: strings.Repeat("d", 64)},
		{Path: "undeclared", Object: strings.Repeat("e", 40)},
	}
	cases := []struct {
		name    string
		dir     string
		pins    []Pin
		unmatch []string
	}{
		{"the root", ".", []Pin{
			{Path: "curl", Name: "curl", Commit: curlCommit},
			{Path: "zlib", Name: "zlib", Commit: zlibCommit},
		}, []string{"sha256"}},
		// A name that is only the path follows the path into the nested
		// directory, so two nested "zlib" submodules stay apart.
		{"a nested superproject", "third_party/grpc", []Pin{
			{Path: "third_party/grpc/curl", Name: "third_party/grpc/curl", Commit: curlCommit},
			{Path: "third_party/grpc/zlib", Name: "third_party/grpc/zlib", Commit: zlibCommit},
		}, []string{"third_party/grpc/sha256"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pins, un := Join(c.dir, entries, links)
			if !reflect.DeepEqual(pins, c.pins) || !reflect.DeepEqual(un, c.unmatch) {
				t.Fatalf("Join:\n pins %#v\n un %#v", pins, un)
			}
		})
	}
	// A name of its own is kept as it is in a nested directory.
	pins, _ := Join("vendor/a", []Entry{{Name: "the-x-lib", Path: "libs/x"}}, []Gitlink{{Path: "libs/x", Object: zlibCommit}})
	if len(pins) != 1 || pins[0].Name != "the-x-lib" || pins[0].Path != "vendor/a/libs/x" {
		t.Fatalf("nested name %+v", pins)
	}
}
