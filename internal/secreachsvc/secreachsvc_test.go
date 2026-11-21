package secreachsvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// writeTree writes files (slash paths relative to root) under a temp dir.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func goFile(pkg string, imports ...string) string {
	var b strings.Builder
	b.WriteString("package " + pkg + "\n\nimport (\n")
	for _, imp := range imports {
		b.WriteString("\t_ \"" + imp + "\"\n")
	}
	b.WriteString(")\n\nfunc f() {}\n")
	return b.String()
}

// projectTree is a root module with a nested module, the directories the
// go command skips, a file whose imports sit past the read head, and a
// module with no Go files.
func projectTree(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		"go.mod":                       "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/net v0.1.0 // indirect\n\tgolang.org/x/text v0.3.0\n)\n",
		"go.sum":                       "golang.org/x/net v0.1.0 h1:x=\ngolang.org/x/net v0.1.0/go.mod h1:y=\ngithub.com/aws/sdk/service/s3 v1.0.0 h1:z=\n",
		"main.go":                      goFile("main", "fmt", "golang.org/x/net/html"),
		"main_test.go":                 goFile("main", "testing", "golang.org/x/net/http2"),
		"long.go":                      "// " + strings.Repeat("x", 6000) + "\npackage main\n\nimport \"golang.org/x/net/idna\"\n",
		"pkg/a/a.go":                   goFile("a", "os"),
		"vendor/golang.org/x/v/v.go":   goFile("v", "example.com/vendored"),
		"testdata/t.go":                goFile("t", "example.com/testdata"),
		"_skip/s.go":                   goFile("s", "example.com/underscore"),
		".hidden/h.go":                 goFile("h", "example.com/hidden"),
		"node_modules/n/n.go":          goFile("n", "example.com/nodemodules"),
		"pkg/_ignored.go":              goFile("a", "example.com/underscorefile"),
		"sub/go.mod":                   "module example.com/app/sub\n\nrequire golang.org/x/text v0.3.0\n",
		"sub/s.go":                     goFile("sub", "golang.org/x/text/language"),
		"empty/go.mod":                 "module example.com/app/empty\n",
		"empty/README.md":              "no go here\n",
		"docs/notes.txt":               "import \"example.com/notgo\"\n",
		"pkg/a/a_extra_test.go":        goFile("a_test", "example.com/testonly"),
		"pkg/a/internal/deep/deep.go":  goFile("deep", "example.com/deep"),
		"tools/cmd/tool/tool_test.go":  goFile("tool", "example.com/tooltest"),
		"tools/cmd/tool/zz_nothing.go": "package tool\n",
	})
}

func TestScanGoImports(t *testing.T) {
	root := projectTree(t)
	g, err := ScanGoImports(context.Background(), root, Limits{HeadBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if g.Stats.Stopped != "" || !g.complete() {
		t.Fatalf("scan not complete: %+v", g.Stats)
	}
	if g.Stats.FullReads != 1 {
		t.Fatalf("FullReads = %d, want 1 (long.go)", g.Stats.FullReads)
	}
	rootMod := g.Modules[""]
	cases := []struct {
		name   string
		module string
		path   string
		want   secreach.Use
		absent bool
	}{
		{name: "production import", module: "", path: "golang.org/x/net/html", want: secreach.Use{NonTest: true}},
		{name: "test import", module: "", path: "golang.org/x/net/http2", want: secreach.Use{Test: true}},
		{name: "imports past the read head", module: "", path: "golang.org/x/net/idna", want: secreach.Use{NonTest: true}},
		{name: "a subdirectory of the module", module: "", path: "example.com/deep", want: secreach.Use{NonTest: true}},
		{name: "an external test package", module: "", path: "example.com/testonly", want: secreach.Use{Test: true}},
		{name: "a test file in a deep directory", module: "", path: "example.com/tooltest", want: secreach.Use{Test: true}},
		{name: "vendor/ is skipped", module: "", path: "example.com/vendored", absent: true},
		{name: "testdata/ is skipped", module: "", path: "example.com/testdata", absent: true},
		{name: "an _-prefixed directory is skipped", module: "", path: "example.com/underscore", absent: true},
		{name: "a .-prefixed directory is skipped", module: "", path: "example.com/hidden", absent: true},
		{name: "node_modules/ is skipped", module: "", path: "example.com/nodemodules", absent: true},
		{name: "an _-prefixed file is skipped", module: "", path: "example.com/underscorefile", absent: true},
		{name: "a non-Go file is not read", module: "", path: "example.com/notgo", absent: true},
		{name: "a nested module's import is not the root's", module: "", path: "golang.org/x/text/language", absent: true},
		{name: "the nested module holds its own import", module: "sub", path: "golang.org/x/text/language", want: secreach.Use{NonTest: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := g.Modules[tc.module]
			if m == nil {
				t.Fatalf("module %q missing (have %v)", tc.module, keys(g.Modules))
			}
			got, ok := m.Uses[tc.path]
			if tc.absent {
				if ok {
					t.Fatalf("%s present in module %q", tc.path, tc.module)
				}
				return
			}
			if !ok || got != tc.want {
				t.Fatalf("Uses[%s] = %+v (present %v), want %+v", tc.path, got, ok, tc.want)
			}
		})
	}
	wantMods := []string{"example.com/app", "github.com/aws/sdk/service/s3", "golang.org/x/net", "golang.org/x/text"}
	if !reflect.DeepEqual(rootMod.Modules, wantMods) {
		t.Fatalf("root module paths = %v, want %v", rootMod.Modules, wantMods)
	}
	if _, ok := g.Modules["empty"]; !ok {
		t.Fatalf("module dir with no Go files not recorded: %v", keys(g.Modules))
	}
}

func keys(m map[string]*ModuleImports) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestScanGoImportsIncomplete(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name        string
		files       map[string]string
		ctx         context.Context
		lim         Limits
		wantStopped string
		wantErrors  int
	}{
		{name: "max files", files: map[string]string{"a.go": goFile("a", "fmt"), "b.go": goFile("a", "os")}, ctx: context.Background(), lim: Limits{MaxFiles: 1}, wantStopped: StoppedMaxFiles},
		{name: "max dirs", files: map[string]string{"a/a.go": goFile("a", "fmt")}, ctx: context.Background(), lim: Limits{MaxDirs: 1}, wantStopped: StoppedMaxDirs},
		{name: "canceled", files: map[string]string{"a.go": goFile("a", "fmt")}, ctx: canceled, wantStopped: StoppedCanceled},
		{name: "a file that does not parse", files: map[string]string{"a.go": "package a\nimport (\n\t\"fmt\"\n"}, ctx: context.Background(), wantErrors: 1},
		{name: "imports past the size cap", files: map[string]string{"a.go": "// " + strings.Repeat("x", 5000) + "\npackage a\nimport \"fmt\"\n"}, ctx: context.Background(), lim: Limits{HeadBytes: 1024, MaxFileBytes: 2048}, wantErrors: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := ScanGoImports(tc.ctx, writeTree(t, tc.files), tc.lim)
			if err != nil {
				t.Fatal(err)
			}
			if g.Stats.Stopped != tc.wantStopped || g.Stats.ParseErrors != tc.wantErrors {
				t.Fatalf("stats = %+v, want stopped %q errors %d", g.Stats, tc.wantStopped, tc.wantErrors)
			}
			if g.complete() {
				t.Fatalf("an incomplete scan reads complete")
			}
		})
	}
}

func TestScanGoImportsRootErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f.go")
	if err := os.WriteFile(file, []byte("package f\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{filepath.Join(t.TempDir(), "missing"), file} {
		if _, err := ScanGoImports(context.Background(), root, Limits{}); err == nil {
			t.Errorf("ScanGoImports(%q) = nil error", root)
		}
	}
}

func TestScanGoImportsSkipsSymlinks(t *testing.T) {
	outside := writeTree(t, map[string]string{"x/x.go": goFile("x", "example.com/outside")})
	root := writeTree(t, map[string]string{"a.go": goFile("a", "fmt")})
	if err := os.Symlink(filepath.Join(outside, "x"), filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	g, err := ScanGoImports(context.Background(), root, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := g.Modules[""].Uses["example.com/outside"]; ok {
		t.Fatal("a symlinked directory was followed")
	}
}

func TestGoModPaths(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{name: "module and block require", src: "module a.b/c\n\nrequire (\n\tx.y/z v1.0.0 // indirect\n\t\"q.r/s\" v2.0.0\n)\n", want: []string{"a.b/c", "x.y/z", "q.r/s"}},
		{name: "single-line require", src: "module m\nrequire x.y/z v1.0.0\n", want: []string{"m", "x.y/z"}},
		{name: "comments and other directives", src: "// module nope\nmodule m // c\ngo 1.22\nreplace a => b v1\nexclude c v1\n", want: []string{"m"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := goModPaths(tc.src); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("goModPaths = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestImportSetScope(t *testing.T) {
	root := projectTree(t)
	g, err := ScanGoImports(context.Background(), root, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		lockfile string
		has      []string
		lacks    []string
	}{
		{name: "root go.mod: the root module only", lockfile: "go.mod", has: []string{"golang.org/x/net/html"}, lacks: []string{"golang.org/x/text/language"}},
		{name: "./go.sum is the root module", lockfile: "./go.sum", has: []string{"golang.org/x/net/html"}, lacks: []string{"golang.org/x/text/language"}},
		{name: "nested go.mod: that module only", lockfile: "sub/go.mod", has: []string{"golang.org/x/text/language"}, lacks: []string{"golang.org/x/net/html"}},
		{name: "OS-form nested go.sum", lockfile: filepath.Join("sub", "go.sum"), has: []string{"golang.org/x/text/language"}, lacks: []string{"fmt"}},
		{name: "a module with no Go files imports nothing", lockfile: "empty/go.mod", lacks: []string{"fmt", "golang.org/x/net/html"}},
		{name: "another lockfile: every module", lockfile: "bin/app", has: []string{"golang.org/x/net/html", "golang.org/x/text/language"}},
		{name: "a go.mod outside any module the list knows: every module", lockfile: "nowhere/go.mod", has: []string{"golang.org/x/net/html", "golang.org/x/text/language"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := g.ImportSet(tc.lockfile)
			if !set.Complete || set.Source != secreach.SourceGoImports {
				t.Fatalf("set = %+v", set)
			}
			for _, p := range tc.has {
				if _, ok := set.Uses[p]; !ok {
					t.Errorf("missing %s", p)
				}
			}
			for _, p := range tc.lacks {
				if _, ok := set.Uses[p]; ok {
					t.Errorf("unexpected %s", p)
				}
			}
		})
	}
}

// fakeOSV is a local OSV database of Go records.
var fakeOSV = map[string]string{
	"GO-1": `{"id":"GO-1","affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"},"ecosystem_specific":{"imports":[{"path":"golang.org/x/net/html"}]}}]}`,
	"GO-2": `{"id":"GO-2","affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"},"ecosystem_specific":{"imports":[{"path":"golang.org/x/net/http2"}]}}]}`,
	"GO-3": `{"id":"GO-3","affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/text"}}]}`,
	"GO-4": `{"id":"GO-4","affected":[{"package":{"ecosystem":"Go","name":"stdlib"},"ecosystem_specific":{"imports":[{"path":"net/smtp"}]}}]}`,
}

func fakeRecord(eco, id string) ([]byte, error) {
	if eco != "Go" {
		return nil, secdepdetail.ErrDatabaseNotInstalled
	}
	if r, ok := fakeOSV[id]; ok {
		return []byte(r), nil
	}
	return nil, secdepdetail.ErrRecordNotFound
}

func depFinding(id, rule, rel string) secfinding.Finding {
	return secfinding.Finding{
		ID: id, Category: policy.FindingVulnerableDependency, Rule: secfinding.Rule{ID: rule},
		Message: "Known vulnerability in a Go dependency.", Location: secfinding.Location{RelPath: rel},
	}
}

func TestTiers(t *testing.T) {
	root := projectTree(t)
	findings := []secfinding.Finding{
		depFinding("html", "GO-1", "go.mod"),
		depFinding("http2", "GO-2", "go.mod"),
		depFinding("text-root", "GO-3", "go.mod"),
		depFinding("text-sub", "GO-3", "sub/go.mod"),
		depFinding("smtp", "GO-4", "go.mod"),
		depFinding("missing", "GO-404", "go.mod"),
		depFinding("npm", "GHSA-xxxx-yyyy-zzzz", "package-lock.json"),
		{ID: "secret", Category: policy.FindingSecret},
	}
	evidence := map[string]string{
		"html": "Go golang.org/x/net@v0.1.0", "http2": "Go golang.org/x/net@v0.1.0",
		"text-root": "Go golang.org/x/text@v0.3.0", "text-sub": "Go golang.org/x/text@v0.3.0",
		"smtp": "Go stdlib@v1.22.0", "missing": "Go golang.org/x/net@v0.1.0",
		"npm": "npm lodash@4.17.0",
	}
	got := Tiers(context.Background(), root, findings, NewLookup(findings, evidence, fakeRecord))
	want := map[string]secreach.Tier{
		"html":      {Level: secreach.Imported, Source: secreach.SourceGoImports, Match: "golang.org/x/net/html"},
		"http2":     {Level: secreach.Imported, Source: secreach.SourceGoImports, TestsOnly: true, Match: "golang.org/x/net/http2"},
		"text-root": {Level: secreach.NotImportedDirectly, Source: secreach.SourceGoImports},
		"text-sub":  {Level: secreach.Imported, Source: secreach.SourceGoImports, Match: "golang.org/x/text/language"},
		"smtp":      {Level: secreach.NotImportedDirectly, Source: secreach.SourceGoImports},
		"missing":   secreach.UnknownTier(secreach.ReasonNoAdvisory),
		"npm":       secreach.UnknownTier(secreach.ReasonNoCodeIntel),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Tiers =\n%+v\nwant\n%+v", got, want)
	}
}

func TestTiersInputs(t *testing.T) {
	f := depFinding("html", "GO-1", "go.mod")
	ev := map[string]string{"html": "Go golang.org/x/net@v0.1.0"}
	mavenLookup := func(string) (secreach.Advisory, bool) {
		return secreach.Advisory{Ecosystem: "Maven", Package: "org.example:lib", Records: []secreach.Record{{ID: "GHSA-1"}}}, true
	}
	cases := []struct {
		name   string
		root   string
		lookup Lookup
		want   secreach.Tier
	}{
		{name: "no project root", root: "", lookup: NewLookup([]secfinding.Finding{f}, ev, fakeRecord), want: secreach.UnknownTier(secreach.ReasonNoImportData)},
		{name: "an unreadable project root", root: filepath.Join(t.TempDir(), "gone"), lookup: NewLookup([]secfinding.Finding{f}, ev, fakeRecord), want: secreach.UnknownTier(secreach.ReasonNoImportData)},
		{name: "no lookup", root: t.TempDir(), lookup: nil, want: secreach.UnknownTier(secreach.ReasonNoAdvisory)},
		{name: "an ecosystem without a mapping", root: t.TempDir(), lookup: mavenLookup, want: secreach.UnknownTier(secreach.ReasonNoMapping)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Tiers(context.Background(), tc.root, []secfinding.Finding{f}, tc.lookup)
			if got["html"] != tc.want {
				t.Fatalf("tier = %+v, want %+v", got["html"], tc.want)
			}
		})
	}
}

// fakeCodeIntel is a codeintel index read.
type fakeCodeIntel struct {
	res   store.CodeIntelImports
	err   error
	calls int
}

func (f *fakeCodeIntel) CodeIntelProjectImports(context.Context, string, string, int) (store.CodeIntelImports, error) {
	f.calls++
	return f.res, f.err
}

func TestTiersCodeIntelLadder(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": "module example.com/app\n",
		"a.go":   goFile("a", "fmt"),
		"b.go":   goFile("a", "os"),
	})
	site := func(rel, spec string) store.CodeIntelImportSite {
		return store.CodeIntelImportSite{File: filepath.Join(root, filepath.FromSlash(rel)), Spec: spec}
	}
	full := store.CodeIntelImports{Files: 2, Indexed: 2, Sites: []store.CodeIntelImportSite{
		site("a.go", "golang.org/x/net/html"), site("vendor/v/v.go", "golang.org/x/net/http2"),
	}}
	partial := full
	partial.Indexed = 1
	outside := full
	outside.Sites = append([]store.CodeIntelImportSite{{File: filepath.Join(t.TempDir(), "x.go"), Spec: "golang.org/x/net/http2"}}, full.Sites...)
	f := depFinding("html", "GO-1", "go.mod")
	f2 := depFinding("http2", "GO-2", "go.mod")
	ev := map[string]string{"html": "Go golang.org/x/net@v0.1.0", "http2": "Go golang.org/x/net@v0.1.0"}
	findings := []secfinding.Finding{f, f2}
	cases := []struct {
		name      string
		ci        *fakeCodeIntel
		opts      []Option
		wantHTML  secreach.Tier
		wantHTTP2 secreach.Tier
	}{
		{
			name: "complete parse wins; the index is not read",
			ci:   &fakeCodeIntel{res: full},
			// The parse sees only fmt and os.
			wantHTML:  secreach.Tier{Level: secreach.NotImportedDirectly, Source: secreach.SourceGoImports},
			wantHTTP2: secreach.Tier{Level: secreach.NotImportedDirectly, Source: secreach.SourceGoImports},
		},
		{
			name:      "an incomplete parse falls back to a complete index (vendor sites left out)",
			ci:        &fakeCodeIntel{res: full},
			opts:      []Option{WithLimits(Limits{MaxFiles: 1})},
			wantHTML:  secreach.Tier{Level: secreach.Imported, Source: secreach.SourceCodeIntel, Match: "golang.org/x/net/html"},
			wantHTTP2: secreach.Tier{Level: secreach.NotImportedDirectly, Source: secreach.SourceCodeIntel},
		},
		{
			name:      "prefer the index",
			ci:        &fakeCodeIntel{res: full},
			opts:      []Option{PreferCodeIntel()},
			wantHTML:  secreach.Tier{Level: secreach.Imported, Source: secreach.SourceCodeIntel, Match: "golang.org/x/net/html"},
			wantHTTP2: secreach.Tier{Level: secreach.NotImportedDirectly, Source: secreach.SourceCodeIntel},
		},
		{
			name:      "an index that does not hold every file is not used",
			ci:        &fakeCodeIntel{res: partial},
			opts:      []Option{PreferCodeIntel()},
			wantHTML:  secreach.Tier{Level: secreach.NotImportedDirectly, Source: secreach.SourceGoImports},
			wantHTTP2: secreach.Tier{Level: secreach.NotImportedDirectly, Source: secreach.SourceGoImports},
		},
		{
			name:      "an index read error is not used",
			ci:        &fakeCodeIntel{err: errors.New("boom")},
			opts:      []Option{PreferCodeIntel()},
			wantHTML:  secreach.Tier{Level: secreach.NotImportedDirectly, Source: secreach.SourceGoImports},
			wantHTTP2: secreach.Tier{Level: secreach.NotImportedDirectly, Source: secreach.SourceGoImports},
		},
		{
			name:      "an index site outside the root makes the index incomplete",
			ci:        &fakeCodeIntel{res: outside},
			opts:      []Option{WithLimits(Limits{MaxFiles: 1})},
			wantHTML:  secreach.Tier{Level: secreach.Unknown, Reason: secreach.ReasonIncomplete},
			wantHTTP2: secreach.Tier{Level: secreach.Unknown, Reason: secreach.ReasonIncomplete},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]Option{WithCodeIntel(tc.ci)}, tc.opts...)
			got := Tiers(context.Background(), root, findings, NewLookup(findings, ev, fakeRecord), opts...)
			if got["html"] != tc.wantHTML || got["http2"] != tc.wantHTTP2 {
				t.Fatalf("html = %+v, http2 = %+v; want %+v, %+v", got["html"], got["http2"], tc.wantHTML, tc.wantHTTP2)
			}
		})
	}
}

func TestCache(t *testing.T) {
	root := writeTree(t, map[string]string{"go.mod": "module m\n", "a.go": goFile("a", "fmt")})
	c := NewCache(time.Minute)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	o := options{limits: DefaultLimits()}
	first := c.get(context.Background(), o, root)
	if first == nil {
		t.Fatal("no list")
	}
	if again := c.get(context.Background(), o, root); again != first {
		t.Fatal("a fresh entry was rebuilt")
	}
	now = now.Add(2 * time.Minute)
	if later := c.get(context.Background(), o, root); later == first {
		t.Fatal("an expired entry was reused")
	}
	// An incomplete list is kept for an eighth of the TTL only.
	o.limits = Limits{MaxDirs: 1}
	other := writeTree(t, map[string]string{"a/a.go": goFile("a", "fmt")})
	inc := c.get(context.Background(), o, other)
	if inc == nil || inc.complete() {
		t.Fatalf("want an incomplete list, got %+v", inc)
	}
	now = now.Add(10 * time.Second)
	if c.get(context.Background(), o, other) == inc {
		t.Fatal("an incomplete list outlived ttl/8")
	}
	// A nil cache builds every time.
	var none *Cache
	if a, b := none.get(context.Background(), o, root), none.get(context.Background(), o, root); a == nil || a == b {
		t.Fatal("a nil cache cached")
	}
}

func TestRelUnder(t *testing.T) {
	cases := []struct {
		root, file string
		want       string
		ok         bool
	}{
		{root: "/p/proj", file: "/p/proj/a/b.go", want: "a/b.go", ok: true},
		{root: "/p/proj/", file: "/p/proj/b.go", want: "b.go", ok: true},
		{root: `C:\p\proj`, file: `C:\p\proj\a\b.go`, want: "a/b.go", ok: filepath.Separator == '\\'},
		{root: "C:/p/proj", file: "C:/p/proj/a/b.go", want: "a/b.go", ok: true},
		{root: "/p/proj", file: "/p/projx/b.go"},
		{root: "/p/proj", file: "/p/proj"},
		{root: "/p/proj", file: "/p/proj/../x.go"},
		{root: "/p/proj", file: "/p/proj//x.go"},
	}
	for _, tc := range cases {
		got, ok := relUnder(tc.root, tc.file)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("relUnder(%q, %q) = %q, %v; want %q, %v", tc.root, tc.file, got, ok, tc.want, tc.ok)
		}
	}
}

// TestTiersGoBinaryStdlib (item 4 Go stdlib, ruling 2026-11-05): a Go
// standard-library finding read out of a binary is "potentially affected"
// by default, whatever the project imports; symbol evidence (the 3b-bin
// seam) moves it, a stripped binary is unknown; a toolchain finding is
// never a property of a binary; a module a binary embeds and a stdlib row of
// go.mod are decided as before.
func TestTiersGoBinaryStdlib(t *testing.T) {
	root := projectTree(t)
	findings := []secfinding.Finding{
		depFinding("bin-smtp", "GO-4", "bin/app"),
		depFinding("bin-stripped", "GO-4", "bin/stripped"),
		depFinding("bin-toolchain", "GO-5", "bin/app"),
		depFinding("bin-module", "GO-1", "bin/app"),
		depFinding("mod-smtp", "GO-4", "go.mod"),
	}
	evidence := map[string]string{
		"bin-smtp": "Go stdlib@1.22.0", "bin-stripped": "Go stdlib@1.22.0", "bin-toolchain": "Go toolchain@1.22.0",
		"bin-module": "Go golang.org/x/net@v0.1.0", "mod-smtp": "Go stdlib@1.22.0",
	}
	record := func(eco, id string) ([]byte, error) {
		if id == "GO-5" {
			return []byte(`{"id":"GO-5","affected":[{"package":{"ecosystem":"Go","name":"toolchain"},"ecosystem_specific":{"imports":[{"path":"cmd/go"}]}}]}`), nil
		}
		return fakeRecord(eco, id)
	}
	lookup := NewLookup(findings, evidence, record)
	got := Tiers(context.Background(), root, findings, lookup, WithBinaryEvidence(func(rel string) secreach.BinaryEvidence {
		if rel == "bin/stripped" {
			return secreach.BinaryEvidence{Symbols: secreach.SymbolsStripped}
		}
		return secreach.BinaryEvidence{}
	}))
	want := map[string]secreach.Tier{
		"bin-smtp":      {Level: secreach.PotentiallyAffected, Source: secreach.SourceGoBuildinfo},
		"bin-stripped":  secreach.UnknownTier(secreach.ReasonStripped),
		"bin-toolchain": secreach.UnknownTier(secreach.ReasonNotALibrary),
		"bin-module":    {Level: secreach.Imported, Source: secreach.SourceGoImports, Match: "golang.org/x/net/html"},
		"mod-smtp":      {Level: secreach.NotImportedDirectly, Source: secreach.SourceGoImports},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Tiers =\n%+v\nwant\n%+v", got, want)
	}
	// With no evidence func at all the default stands.
	got = Tiers(context.Background(), root, findings[:1], NewLookup(findings[:1], evidence, record))
	if got["bin-smtp"].Level != secreach.PotentiallyAffected {
		t.Fatalf("default tier = %+v", got["bin-smtp"])
	}
}
