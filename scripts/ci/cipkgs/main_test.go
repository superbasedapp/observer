package main

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
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
