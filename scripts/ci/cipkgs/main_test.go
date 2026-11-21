package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/publictree"
)

func TestMatchRule(t *testing.T) {
	cases := []struct {
		pattern, rel string
		want         bool
	}{
		{"go.mod", "go.mod", true},
		{"go.mod", "x/go.mod", false},
		{"scripts/ci/**", "scripts/ci/go-test-run.sh", true},
		{"scripts/ci/**", "scripts/ci/cipkgs/main.go", true},
		{"**/migrations/**", "internal/db/migrations/136_x.sql", true},
		{"**/migrations/**", "internal/orgserver/db/migrations/175_x.sql", true},
		{"**/migrations/**", "internal/db/db.go", false},
		{"testdata/**", "testdata/claudecode/a.jsonl", true},
		{"testdata/**", "internal/adapter/codex/testdata/a.jsonl", false},
		{"docs/plans/*.md", "docs/plans/x.md", true},
		{"docs/plans/*.md", "docs/plans/agent-access-research/fixtures/a.json", false},
		{".github/workflows/*.yml", ".github/workflows/npm-release.yml", true},
		{"tests/e2e/**", "tests/e2e", true},
		{"tests/e2e/**", "tests/e2e/orgserver", true},
		{"tests/e2e/**", "tests/invariant", false},
	}
	for _, c := range cases {
		if got := matchRule(c.pattern, c.rel); got != c.want {
			t.Errorf("matchRule(%q, %q) = %v, want %v", c.pattern, c.rel, got, c.want)
		}
	}
}

func TestClassify(t *testing.T) {
	pkgs := map[string]bool{
		"internal/proxy": true, "internal/adapter/codex": true, "cmd/observer": true, "tests/invariant": true,
		"internal/db/migrations": true, "internal/orgserver/db/migrations": true, "internal/orgserver/db/pgmigrations": true,
	}
	cases := []struct {
		name     string
		changed  []string
		wantAll  bool
		wantDirs []string
	}{
		{"go file maps to its package", []string{"internal/proxy/proxy.go"}, false, []string{"internal/proxy"}},
		{"package testdata maps to the package", []string{"internal/adapter/codex/testdata/s.jsonl"}, false, []string{"internal/adapter/codex"}},
		{"unread doc is ignored", []string{"docs/handovers/x.md", "internal/proxy/a.go"}, false, []string{"internal/proxy"}},
		{"go.sum falls back", []string{"go.sum"}, true, nil},
		{"ci workflow falls back", []string{".github/workflows/ci.yml"}, true, nil},
		{"server migration maps to its migrations package", []string{"internal/orgserver/db/migrations/176_x.sql"}, false, []string{"internal/orgserver/db/migrations"}},
		{"agent migration maps to its migrations package", []string{"internal/db/migrations/197_x.sql"}, false, []string{"internal/db/migrations"}},
		{"pg migration maps to its package", []string{"internal/orgserver/db/pgmigrations/0130_x.sql"}, false, []string{"internal/orgserver/db/pgmigrations"}},
		{"go.mod falls back", []string{"go.mod"}, true, nil},
		{"scripts/ci falls back", []string{"scripts/ci/known-red.txt"}, true, nil},
		{"shared testdata falls back", []string{"testdata/hermes/a.db"}, true, nil},
		{"read doc outside packages falls back", []string{"docs/guard-rules.md"}, true, nil},
		{"other workflow does not", []string{".github/workflows/npm-release.yml"}, false, nil},
		{"invariant test maps to its own package", []string{"tests/invariant/x_test.go"}, false, []string{"tests/invariant"}},
	}
	for _, c := range cases {
		dirs, all, _ := classify(c.changed, pkgs)
		if all != c.wantAll {
			t.Errorf("%s: all = %v, want %v", c.name, all, c.wantAll)
			continue
		}
		if len(dirs) != len(c.wantDirs) {
			t.Errorf("%s: dirs = %v, want %v", c.name, dirs, c.wantDirs)
			continue
		}
		for _, d := range c.wantDirs {
			if !dirs[d] {
				t.Errorf("%s: missing %s in %v", c.name, d, dirs)
			}
		}
	}
}

func TestFileUsesConcurrency(t *testing.T) {
	cases := []struct {
		name, src string
		want      bool
	}{
		{"plain", "package p\nfunc F(a int) int { return a + 1 }\n", false},
		{"go statement", "package p\nfunc F() { go func() {}() }\n", true},
		{"select", "package p\nfunc F(c chan int) { select { case <-c: } }\n", true},
		{"channel type", "package p\ntype T struct{ c chan int }\n", true},
		{"send", "package p\nfunc F(c chan<- int) { c <- 1 }\n", true},
		{"sync import", "package p\nimport \"sync\"\nvar mu sync.Mutex\n", true},
		{"atomic import", "package p\nimport \"sync/atomic\"\nvar n atomic.Int64\n", true},
		{"unrelated import", "package p\nimport \"strings\"\nvar s = strings.ToUpper(\"a\")\n", false},
	}
	for _, c := range cases {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", c.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := fileUsesConcurrency(f); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNeverRace(t *testing.T) {
	cases := []struct {
		rel  string
		want bool
	}{
		{"tests/invariant", true},
		{"internal/store", false},
		{"tests/e2e/orgserver", false},
	}
	for _, c := range cases {
		if got := neverRace[c.rel]; got != c.want {
			t.Errorf("neverRace[%q] = %v, want %v", c.rel, got, c.want)
		}
	}
}

func TestRaceAllRules(t *testing.T) {
	cases := []struct {
		rel  string
		want bool
	}{
		{"go.mod", true},
		{"go.sum", true},
		{"internal/store/store.go", false},
		{"model-pricing/go.mod", false},
		{".github/workflows/ci.yml", false},
	}
	for _, c := range cases {
		if got := anyRule(raceAllRules, c.rel); got != c.want {
			t.Errorf("anyRule(raceAllRules, %q) = %v, want %v", c.rel, got, c.want)
		}
	}
}

// TestRaceAllSince runs the --since decision against a throwaway repository.
func TestRaceAllSince(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "GIT_CONFIG_GLOBAL=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	commit := func(file, body string) string {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, file)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		git("add", file)
		git("commit", "-q", "-m", file)
		out := git("rev-parse", "HEAD")
		return out[:len(out)-1]
	}
	git("init", "-q")
	base := commit("go.mod", "module x\n")
	code := commit("internal/a/a.go", "package a\n")
	mod := commit("go.mod", "module x\n\ngo 1.27\n")
	cases := []struct {
		name, base, head string
		want             bool
	}{
		{"unknown base races all", "", code, true},
		{"zero base races all", "0000000000000000000000000000000000000000", code, true},
		{"code change keeps the list", base, code, false},
		{"go.mod change races all", code, mod, true},
		{"bad base races all", "deadbeef", mod, true},
	}
	for _, c := range cases {
		if got := raceAllSince(dir, c.base, c.head); got != c.want {
			t.Errorf("%s: raceAllSince = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFreshRules(t *testing.T) {
	cases := []struct {
		rel  string
		want bool
	}{
		{"tests/e2e", true},
		{"tests/e2e/statusline", true},
		{"tests/distro", true},
		{"tests/invariant", false},
		{"internal/store", false},
	}
	for _, c := range cases {
		if got := anyRule(freshRules, c.rel); got != c.want {
			t.Errorf("anyRule(freshRules, %q) = %v, want %v", c.rel, got, c.want)
		}
	}
}

func TestIsLiveEnvName(t *testing.T) {
	cases := []struct {
		v    string
		want bool
	}{
		{"OBSERVER_CONTROL_STORE_DSN", true},
		{"OBSERVER_POSTGRES_URL", true},
		{"SBO_HA_PG_DB", true},
		{"OBSERVER_KAFKA_TEST_BROKERS", true},
		{"OBSERVER_SANDBOX_LIVE_INTERNET", true},
		{"PRICING_DSN", true},
		{"OBSERVER_NATS_URL", true},
		{"DSN", false},              // one word: a label, not a variable
		{"STATUS_DELIVERED", false}, // LIVE inside a word does not count
		{"OBSERVER_HOME", false},
		{"observer_dsn", false},
		{"SBO_SKIP_TOOLCHAIN_TESTS", false},
	}
	for _, c := range cases {
		if got := isLiveEnvName(c.v); got != c.want {
			t.Errorf("isLiveEnvName(%q) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestFileNamesLiveEnv(t *testing.T) {
	cases := []struct {
		name, src string
		want      bool
	}{
		{"getenv dsn", "package p\nimport \"os\"\nvar d = os.Getenv(\"OBSERVER_CONTROL_STORE_DSN\")\n", true},
		{"const live switch", "package p\nconst k = `OBSERVER_PROCESS_LIVE`\n", true},
		{"ordinary env", "package p\nimport \"os\"\nvar h = os.Getenv(\"OBSERVER_HOME\")\n", false},
		{"no literals", "package p\nfunc F() {}\n", false},
	}
	for _, c := range cases {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", c.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := fileNamesLiveEnv(f); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFileRunsChildTool(t *testing.T) {
	cases := []struct {
		name, src string
		want      bool
	}{
		{"git command", "package p\nimport \"os/exec\"\nvar c = exec.Command(\"git\", \"init\")\n", true},
		{"go command context", "package p\nimport (\"context\"; \"os/exec\")\nvar c = exec.CommandContext(context.TODO(), \"go\", \"list\")\n", true},
		{"raw string git", "package p\nimport \"os/exec\"\nvar c = exec.Command(`git`)\n", true},
		{"other tool", "package p\nimport \"os/exec\"\nvar c = exec.Command(\"bwrap\", \"git\")\n", false},
		{"variable name", "package p\nimport \"os/exec\"\nvar bin = \"git\"\nvar c = exec.Command(bin)\n", false},
		{"go as context arg slot", "package p\nimport \"os/exec\"\nvar c = exec.Command(\"sh\", \"go\")\n", false},
		{"not exec", "package p\nfunc Command(string) {}\nfunc F() { Command(\"git\") }\n", false},
	}
	for _, c := range cases {
		f, err := parser.ParseFile(token.NewFileSet(), "x_test.go", c.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := fileRunsChildTool(f); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestTestsRunChildToolReadsOnlyTestFiles: a product file that runs git
// (a scanner, a resolver) does not by itself make the package fresh; its
// tests replay as before unless a test file starts the tool.
func TestTestsRunChildToolReadsOnlyTestFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("scan.go", "package p\nimport \"os/exec\"\nvar c = exec.Command(\"git\")\n")
	write("scan_test.go", "package p\n")
	if got, err := testsRunChildTool(dir, []string{"scan.go", "scan_test.go"}); err != nil || got {
		t.Fatalf("product-only git call: got %v %v, want false", got, err)
	}
	write("repo_test.go", "package p\nimport \"os/exec\"\nvar d = exec.Command(\"git\", \"init\")\n")
	if got, err := testsRunChildTool(dir, []string{"scan.go", "scan_test.go", "repo_test.go"}); err != nil || !got {
		t.Fatalf("test-file git call: got %v %v, want true", got, err)
	}
}

func TestPathReadTargetRules(t *testing.T) {
	cases := []struct {
		dir  string
		want bool
	}{
		{"internal/db/migrations", true},
		{"internal/orgserver/db/migrations", true},
		{"internal/orgserver/db/pgmigrations", true},
		{"internal/cloudserver/db/migrations", true},
		{"internal/db", false},
		{"internal/orgserver/db/pgmigrations/gen/schema", false},
	}
	for _, c := range cases {
		if got := anyRule(pathReadTargetRules, c.dir); got != c.want {
			t.Errorf("%s: target = %v, want %v", c.dir, got, c.want)
		}
	}
}

func TestFilePathLiterals(t *testing.T) {
	cases := []struct {
		name, src, target, pkg string
		want                   bool
	}{
		{"const relative dir", `const committedDir = "../migrations"`, "internal/db/migrations", "internal/db/taxbackfillgen", true},
		{"glob under the dir", `var g = []string{"../db/migrations/*.sql"}`, "internal/orgserver/db/migrations", "internal/orgserver/rolloutcore", true},
		{"join with a trailing variable", `func f(x string) { _ = filepath.Join("..", "..", "db", "migrations", x) }`, "internal/orgserver/db/migrations", "internal/orgserver/vendorconn/decide", true},
		{"join from a root variable", `func f(root string) { _ = filepath.Join(root, "internal", "db", "migrations") }`, "internal/db/migrations", "tests/invariant", true},
		{"module-relative literal", `var d = "internal/db/migrations"`, "internal/db/migrations", "tools/shippedmiggen", true},
		{"a sibling name is not the dir", `const d = "../migrationsx"`, "internal/db/migrations", "internal/db/taxbackfillgen", false},
		{"a bare word is not a path", `func f() { readJoined(t, "migrations", nil) }`, "internal/orgserver/db/migrations", "internal/orgserver/controlstore", false},
		{"another lineage is not the target", `const d = "../db/pgmigrations"`, "internal/orgserver/db/migrations", "internal/orgserver/controlstore", false},
	}
	for _, c := range cases {
		f, err := parser.ParseFile(token.NewFileSet(), "x_test.go", "package p\n"+c.src, 0)
		if err != nil {
			t.Fatalf("%s: parse: %v", c.name, err)
		}
		if got := readsAny(c.pkg, filePathLiterals(f), []string{c.target}); got != c.want {
			t.Errorf("%s: reads %s = %v, want %v (literals %q)", c.name, c.target, got, c.want, filePathLiterals(f))
		}
	}
}

// TestPathReadersFindTheKnownReaders scans the real test files of every
// package the TESTCI audit (H2) found reading a migrations directory by path,
// one row each, so a reader the scan stops seeing fails here rather than
// silently dropping out of a migration-only push.
func TestPathReadersFindTheKnownReaders(t *testing.T) {
	rows := []struct{ reader, target string }{
		{"internal/db/taxbackfillgen", "internal/db/migrations"},
		{"internal/db/asstbackfillgen", "internal/db/migrations"},
		{"internal/db/reasoninggen", "internal/db/migrations"},
		{"internal/orgserver/rolloutcore", "internal/orgserver/db/migrations"},
		{"internal/orgserver/rolloutcore", "internal/orgserver/db/pgmigrations"},
		{"internal/orgserver/vendorconn/decide", "internal/orgserver/db/migrations"},
		{"internal/orgserver/controlstore", "internal/orgserver/db/migrations"},
		{"internal/orgserver/controlstore", "internal/orgserver/db/pgmigrations"},
		{"scripts/vendorsign", "internal/db/migrations"},
	}
	root := filepath.Join("..", "..", "..")
	public := publictree.In(root)
	for _, r := range rows {
		if public && strings.HasPrefix(r.reader, "internal/orgserver/") {
			// The org server's packages are private-only; the private
			// tree still holds every row.
			continue
		}
		dir := filepath.Join(root, filepath.FromSlash(r.reader))
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("%s: %v", r.reader, err)
		}
		var files []string
		for _, e := range ents {
			files = append(files, e.Name())
		}
		lits, err := testPathLiterals(dir, files)
		if err != nil {
			t.Fatalf("%s: %v", r.reader, err)
		}
		if !readsAny(r.reader, lits, []string{r.target}) {
			t.Errorf("%s: the scan no longer sees it read %s by path", r.reader, r.target)
		}
	}
}

// selects reports whether go test, given flag (as splitFlag prints it, ""
// for none), runs the top-level test, example or fuzz target called name.
func selects(t *testing.T, flag, name string) bool {
	t.Helper()
	switch {
	case flag == "":
		return true
	case strings.HasPrefix(flag, "-run="):
		return regexp.MustCompile(strings.TrimPrefix(flag, "-run=")).MatchString(name)
	case strings.HasPrefix(flag, "-skip="):
		return !regexp.MustCompile(strings.TrimPrefix(flag, "-skip=")).MatchString(name)
	}
	t.Fatalf("unexpected flag %q", flag)
	return false
}

func TestIsSplitTestName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"Test", true},
		{"TestA", true},
		{"Test_x", true},
		{"Test1", true},
		{"TestAbc_Def9", true},
		{"Testing", false},    // go test does not run it
		{"Testabc", false},    // lower case after Test
		{"ExampleFoo", false}, // examples always fall to the last part
		{"FuzzFoo", false},
		{"BenchmarkFoo", false},
		{"TestÜber", false}, // not ASCII: grouped nowhere, runs in the last part
	}
	for _, c := range cases {
		if got := isSplitTestName(c.name); got != c.want {
			t.Errorf("isSplitTestName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSplitPartsCoverEveryTestOnce is the honesty property of the split
// mode: for every k, each test, example and fuzz target runs in exactly one
// of the k parts, including names the grouping never saw.
func TestSplitPartsCoverEveryTestOnce(t *testing.T) {
	grouped := []string{
		"Test", "TestA", "TestAb", "TestAbc", "TestAbcd", "TestAbd", "TestB",
		"TestBa", "TestBaz", "TestBazQux", "Test_x", "Test1", "TestZz", "TestZzz9",
		"TestRun", "TestRunner", "TestRunAll", "TestServeHTTP", "TestServe",
	}
	unseen := []string{"ExampleFoo", "Example", "FuzzParse", "TestFromAFileThatDidNotParse"}
	cases := []struct {
		name  string
		names []string
	}{
		{"several groups", grouped},
		{"one group", []string{"TestAbc1", "TestAbc2", "TestAbc3"}},
		{"no tests", nil},
	}
	for _, c := range cases {
		for k := 1; k <= 6; k++ {
			flags := make([]string, k)
			for i := range flags {
				flags[i] = splitFlag(c.names, i, k)
			}
			all := append(append([]string{}, c.names...), unseen...)
			for _, n := range all {
				// TestFromAFileThatDidNotParse shares its group with no
				// grouped name, so only the last part may run it.
				runs := 0
				for _, f := range flags {
					if selects(t, f, n) {
						runs++
					}
				}
				if runs != 1 {
					t.Errorf("%s, k=%d: %s runs in %d parts, want 1 (flags %q)", c.name, k, n, runs, flags)
				}
			}
		}
	}
}

func TestSplitFlagShapes(t *testing.T) {
	names := []string{"TestAaa", "TestBbb", "TestCcc", "TestDdd"}
	cases := []struct {
		i, k int
		want string
	}{
		{0, 1, ""},
		{0, 2, "-run=^Test(?:Aaa|Bbb)"},
		{1, 2, "-skip=^Test(?:Aaa|Bbb)"},
		{0, 4, "-run=^Test(?:Aaa)"},
		{2, 4, "-run=^Test(?:Ccc)"},
		{3, 4, "-skip=^Test(?:Aaa|Bbb|Ccc)"},
	}
	for _, c := range cases {
		if got := splitFlag(names, c.i, c.k); got != c.want {
			t.Errorf("splitFlag(%d, %d) = %q, want %q", c.i, c.k, got, c.want)
		}
	}
	// More parts than groups: an earlier part with nothing to run must run
	// nothing, never everything.
	if got := splitFlag([]string{"TestAaa"}, 1, 3); got != "-run=^$" {
		t.Errorf("empty earlier part = %q, want -run=^$", got)
	}
}

// TestSplitTableRows pins scripts/ci/go-test-splits.tsv: every row names a
// package directory with tests and a part count of at least 2, and every
// part's pattern of the real package stays far below the 128 KiB limit on
// one argument while the parts stay roughly even.
func TestSplitTableRows(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	data, err := os.ReadFile(filepath.Join("..", "go-test-splits.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 2 {
			t.Errorf("malformed row %q (want <pkg-dir> TAB <parts>)", line)
			continue
		}
		k, err := strconv.Atoi(f[1])
		if err != nil || k < 2 {
			t.Errorf("row %q: parts must be an integer >= 2", line)
			continue
		}
		rows++
		dir := filepath.Join(root, filepath.FromSlash(f[0]))
		if _, err := os.Stat(dir); err != nil {
			if publictree.In(root) {
				continue // a private-only package; the private tree checks it
			}
			t.Errorf("row %q: %v", line, err)
			continue
		}
		names, err := testFuncNames(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(names) < k {
			t.Errorf("%s: %d tests cannot fill %d parts", f[0], len(names), k)
		}
		counts := make([]int, k)
		for _, n := range names {
			for i := 0; i < k; i++ {
				if selects(t, splitFlag(names, i, k), n) {
					counts[i]++
				}
			}
		}
		for i := 0; i < k; i++ {
			if l := len(splitFlag(names, i, k)); l > 16*1024 {
				t.Errorf("%s part %d: pattern is %d bytes", f[0], i, l)
			}
			if counts[i] < len(names)/(3*k) {
				t.Errorf("%s part %d runs %d of %d tests: the split is lopsided (%v)", f[0], i, counts[i], len(names), counts)
			}
		}
		t.Logf("%s: %d tests in %d parts %v", f[0], len(names), k, counts)
	}
	if rows == 0 {
		t.Error("go-test-splits.tsv has no rows")
	}
}

// TestNarrowVerdict: one row per bound of a narrowed release-gate run
// (P-222). Every change the narrowing cannot see through, including a file
// that belongs to no package, forces the full run; none is a silent skip.
func TestNarrowVerdict(t *testing.T) {
	pkgDirs := map[string]bool{"internal/a": true, "internal/a/sub": true, "cmd/b": true, "internal/db/migrations": true}
	many := func(n int) []string {
		var r []string
		for i := 0; i < n; i++ {
			r = append(r, fmt.Sprintf("internal/a/f%d.go", i))
		}
		return r
	}
	cases := []struct {
		name    string
		changed []string
		full    bool
	}{
		{"a package file", []string{"internal/a/x.go"}, false},
		{"a package file in a subdirectory of a package", []string{"internal/a/testdata/in.json"}, false},
		{"a migration of a migrations package", []string{"internal/db/migrations/200_x.sql"}, false},
		{"docs no test reads", []string{"docs/plans/x.md", "PROGRESS.md"}, false},
		{"nothing changed", nil, false},
		{"go.mod", []string{"internal/a/x.go", "go.mod"}, true},
		{"go.sum", []string{"go.sum"}, true},
		{"the ci workflow itself", []string{".github/workflows/ci.yml"}, true},
		{"another workflow (tests/invariant always runs and reads it)", []string{".github/workflows/npm-release.yml"}, false},
		{"a website page ci.yml path-ignores", []string{"website/arcade.html", "website/assets/x.css"}, false},
		{"a website path ci.yml does not ignore", []string{"website/new-dir/x.go"}, true},
		{"the go-cache action", []string{".github/actions/go-cache/action.yml"}, true},
		{"the CI scripts", []string{"scripts/ci/go-test-splits.tsv"}, true},
		{"the omit-tag script", []string{"scripts/omit-tag-check.sh"}, true},
		{"the distro build script", []string{"scripts/build-distro.sh"}, true},
		{"the Makefiles", []string{"Makefile.private"}, true},
		{"top-level testdata", []string{"testdata/x/y.json"}, true},
		{"a file in no package (hidden change)", []string{"internal/a/x.go", "deploy/values.yaml"}, true},
		{"a root file not on the unread list", []string{"README.md"}, true},
		{"exactly the file bound", many(narrowMaxFiles), false},
		{"one file over the bound", many(narrowMaxFiles + 1), true},
	}
	for _, c := range cases {
		full, why := narrowVerdict(c.changed, pkgDirs)
		if full != c.full {
			t.Errorf("%s: full=%v (%s), want %v", c.name, full, why, c.full)
		}
		if full && why == "" {
			t.Errorf("%s: a full verdict must say why", c.name)
		}
	}
}

func TestBuildLineTags(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{"//go:build !sbo_omit_adapter_aider", "sbo_omit_adapter_aider"},
		{"//go:build sbo_omit_a || (linux && !sbo_omit_b)", "sbo_omit_a,sbo_omit_b"},
		{"//go:build no_obs", ""},
		{"// sbo_omit_a in a comment", ""},
		{"package x // sbo_omit_a", ""},
	}
	for _, c := range cases {
		if got := strings.Join(buildLineTags(c.line), ","); got != c.want {
			t.Errorf("buildLineTags(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

// TestRunNarrowOnARealRepository drives `cipkgs narrow` end to end on a
// throwaway module: a package change narrows and names the omit tags of its
// dependency closure; a hidden change (a file in no package), a failed diff
// and a base that is not a sha run full.
func TestRunNarrowOnARealRepository(t *testing.T) {
	for _, tool := range []string{"git", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not on PATH")
		}
	}
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write("go.mod", "module example.com/m\n\ngo 1.21\n")
	write("lib/lib.go", "package lib\n\nfunc F() int { return 1 }\n")
	write("lib/lib_off.go", "//go:build sbo_omit_lib\n\npackage lib\n")
	write("app/app.go", "package app\n\nimport \"example.com/m/lib\"\n\nfunc G() int { return lib.F() }\n")
	write("app/app_test.go", "package app\n\nimport \"testing\"\n\nfunc TestG(t *testing.T) { _ = G() }\n")
	write("other/other.go", "//go:build !sbo_omit_other\n\npackage other\n")
	git("init", "-q")
	git("add", "-A")
	git("commit", "-q", "-m", "base")
	base := git("rev-parse", "HEAD")

	narrow := func(b, head string) string {
		t.Helper()
		var out strings.Builder
		if err := runNarrow(root, "example.com/m", b, head, &out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	write("app/app.go", "package app\n\nimport \"example.com/m/lib\"\n\nfunc G() int { return lib.F() + 1 }\n")
	git("commit", "-q", "-am", "app change")
	got := narrow(base, git("rev-parse", "HEAD"))
	if !strings.Contains(got, "mode=narrowed") || !strings.Contains(got, "tags=sbo_omit_lib\n") {
		t.Errorf("a package change must narrow and name its dependency's tag (not sbo_omit_other):\n%s", got)
	}

	write("deploy/values.yaml", "x: 1\n")
	git("add", "-A")
	git("commit", "-q", "-m", "hidden change")
	if got := narrow(base, git("rev-parse", "HEAD")); !strings.Contains(got, "mode=full") {
		t.Errorf("a file in no package must force the full run:\n%s", got)
	}
	if got := narrow(base, "no-such-ref"); !strings.Contains(got, "mode=full") {
		t.Errorf("a failed diff must force the full run:\n%s", got)
	}
	if got := narrow("HEAD~1", "HEAD"); !strings.Contains(got, "mode=full") {
		t.Errorf("a base that is not a 40-hex sha must force the full run:\n%s", got)
	}
}

func TestGateHead(t *testing.T) {
	base := strings.Repeat("ab", 20)
	other := strings.Repeat("cd", 20)
	full := func(status, concl string) ghRun {
		return ghRun{Status: status, Conclusion: concl, Event: "workflow_dispatch", HeadBranch: "main", DisplayTitle: "ci"}
	}
	narrowed := func(b, status, concl string) ghRun {
		return ghRun{Status: status, Conclusion: concl, Event: "workflow_dispatch", HeadBranch: "main", DisplayTitle: "ci narrowed since " + b}
	}
	cases := []struct {
		name string
		runs []ghRun
		want string
	}{
		{"no runs", nil, "none"},
		{"only a push run", []ghRun{{Status: "completed", Conclusion: "success", Event: "push", HeadBranch: "main", DisplayTitle: "fix: x"}}, "none"},
		{"a dispatch on another branch", []ghRun{{Status: "completed", Conclusion: "success", Event: "workflow_dispatch", HeadBranch: "lane", DisplayTitle: "ci"}}, "none"},
		{"a green full run", []ghRun{full("completed", "failure"), full("completed", "success")}, "full"},
		{"full wins over narrowed", []ghRun{narrowed(base, "completed", "success"), full("completed", "success")}, "full"},
		{"a green narrowed run", []ghRun{narrowed(base, "completed", "success")}, "narrowed " + base},
		{"two bases", []ghRun{narrowed(other, "completed", "success"), narrowed(base, "completed", "success")}, "narrowed " + base + "|narrowed " + other},
		{"a malformed narrowed title counts as full, never as a base", []ghRun{{Status: "completed", Conclusion: "success", Event: "workflow_dispatch", HeadBranch: "main", DisplayTitle: "ci narrowed since xyz"}}, "full"},
		{"running", []ghRun{narrowed(base, "in_progress", ""), full("completed", "failure")}, "running"},
		{"red", []ghRun{narrowed(base, "completed", "failure"), full("completed", "cancelled")}, "failed:cancelled,failure"},
	}
	for _, c := range cases {
		if got := strings.Join(gateHead(c.runs), "|"); got != c.want {
			t.Errorf("%s: gateHead = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestGateBase(t *testing.T) {
	b := strings.Repeat("ab", 20)
	cases := []struct {
		name string
		runs []ghRun
		want string
	}{
		{"a green full dispatch on main", []ghRun{{Status: "completed", Conclusion: "success", Event: "workflow_dispatch", HeadBranch: "main", DisplayTitle: "ci"}}, "full"},
		{"only a green narrowed run", []ghRun{{Status: "completed", Conclusion: "success", Event: "workflow_dispatch", HeadBranch: "main", DisplayTitle: "ci narrowed since " + b}}, "not-full"},
		{"a red full run", []ghRun{{Status: "completed", Conclusion: "failure", Event: "workflow_dispatch", HeadBranch: "main", DisplayTitle: "ci"}}, "not-full"},
		{"a green push run", []ghRun{{Status: "completed", Conclusion: "success", Event: "push", HeadBranch: "main", DisplayTitle: "ci"}}, "not-full"},
		{"nothing", nil, "not-full"},
	}
	for _, c := range cases {
		if got := gateBase(c.runs); got != c.want {
			t.Errorf("%s: gateBase = %q, want %q", c.name, got, c.want)
		}
	}
	// The JSON gh prints decodes into the same records.
	var out strings.Builder
	in := `[{"conclusion":"success","displayTitle":"ci","event":"workflow_dispatch","headBranch":"main","status":"completed"}]`
	if err := runGate([]string{"base"}, strings.NewReader(in), &out); err != nil || out.String() != "full\n" {
		t.Errorf("gate base on gh JSON = %q, %v", out.String(), err)
	}
}

// TestSplitRefinesAnOversizedGroup: when most tests share one three-letter
// prefix, the group is refined by longer prefixes so k parts are all
// non-empty, and the parts still cover every test exactly once (a name that
// is itself a refined prefix, TestSecurityCI beside TestSecurityCIE2E,
// included).
func TestSplitRefinesAnOversizedGroup(t *testing.T) {
	names := []string{"TestAlpha", "TestBeta", "TestSecurityCI", "TestSecurityCIE2E", "TestSecurityCIOff",
		"TestSecurityH2A", "TestSecurityH2B", "TestSecurityP4", "TestSecurityLeft", "TestSec", "TestSecurity"}
	for _, k := range []int{2, 4, 6, 8} {
		seen := map[string]int{}
		for i := 0; i < k; i++ {
			flag := splitFlag(names, i, k)
			n := 0
			for _, name := range names {
				if selects(t, flag, name) {
					seen[name]++
					n++
				}
			}
			// Eleven names fill at most four parts by count; past that only
			// the exactly-once rule below holds (TestSplitTableRows guards
			// the real packages' balance).
			if n == 0 && k <= 4 {
				t.Errorf("k=%d part %d selects no test (%s)", k, i, flag)
			}
		}
		for _, name := range names {
			if seen[name] != 1 {
				t.Errorf("k=%d: %s runs in %d parts, want 1", k, name, seen[name])
			}
		}
	}
}
