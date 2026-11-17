// Command cipkgs decides which Go test packages a CI run tests, which of
// them run under the race detector, and which of them may replay a cached
// test result (D-609). It is the one owner of those rules; ci.yml and
// scripts/ci/go-test-run.sh only call it.
//
//	go run ./scripts/ci/cipkgs race [--all | --since <base> <head>]
//	    Module-relative paths of the packages that run with -race: every
//	    package whose Go files (tests included) use concurrency (a go
//	    statement, select, a channel type or operation, or an import of sync
//	    or sync/atomic). A push and a full run (dispatch, release gate) use
//	    this same list. --all lists every package instead. --since lists
//	    every package when a raceAllRules path (go.mod, go.sum: the
//	    toolchain and the dependencies) changed between base and head, or
//	    the base is unknown, and the concurrency list otherwise; a full run
//	    passes the previous release tag as base. The packages on neverRace
//	    are left out in every form.
//
//	go run ./scripts/ci/cipkgs affected <base-sha> <head-sha>
//	    Module-relative paths of the test packages a push from base to head
//	    can affect: the packages holding a changed file plus every package
//	    whose test dependency closure (go list -test -deps) contains one.
//	    A migration file is an input of its migrations package (embedded),
//	    so it is classified like any other package file. A changed package
//	    on pathReadTargetRules (a migrations directory) also affects every
//	    package whose test files read that directory from disk by path
//	    (pathReaders): those tests see the files without importing them.
//	    Prints the single word ALL when the run must test everything: an
//	    unknown base, a change to a shared input (go.mod, go.sum, ci.yml,
//	    scripts/ci, top-level testdata, ...), or a changed file that belongs
//	    to no package and is not on the known-unread list (a test may read
//	    it from disk).
//
//	go run ./scripts/ci/cipkgs affected --precise <base-sha> <head-sha>
//	    The same for a local gate rerun (tools/testrunner), never called by
//	    ci.yml: a changed _test.go file or embedded dashboard bundle
//	    (webapp/dist) selects its own package instead of everything that
//	    imports it, and a changed file of a tree tests read only by path
//	    (the web sources, docs) selects the packages whose test files name
//	    it or a directory above it instead of ALL (precise.go).
//
//	go run ./scripts/ci/cipkgs fresh
//	    Module-relative paths of the packages that always run with -count=1,
//	    even on a push where the others may replay a cached result: the
//	    packages on freshRules (end-to-end suites that start binaries and
//	    listen on sockets) and every package whose Go files name a live
//	    environment variable (liveEnvMarkers: a database DSN, a broker, a
//	    LIVE switch), and every package whose test files start git or go by
//	    name (childTools). Go's test cache tracks the files a test opens and
//	    the variables it reads, but not a database, a network peer, the
//	    clock, or what a child git or go process reads.
//
//	go run ./scripts/ci/cipkgs split <pkg-dir> <i> <k>
//	    The go test flag that selects part i (0-based) of k of one package's
//	    tests, for a package too slow for one CI shard
//	    (scripts/ci/go-test-splits.tsv). The top-level Test functions are
//	    grouped by the first splitKeyLen characters after "Test" and the
//	    sorted groups are cut into k contiguous runs of about equal test
//	    count; a group bigger than one part's share is refined by longer
//	    prefixes, down to single tests (groupCounts). Parts 0..k-2 print
//	    -run=^Test(?:<their groups>); the last
//	    part prints -skip=^Test(?:<every earlier group>), so it runs
//	    everything the earlier parts do not: Examples, Fuzz seeds and any
//	    test the parser missed. The union of the k parts is therefore the
//	    whole package by construction, and no test runs twice. An earlier
//	    part with no group prints -run=^$; a last part with nothing to skip
//	    prints nothing.
//
//	go run ./scripts/ci/cipkgs narrow <base> <head>
//	    Whether a repeat release commit may run a NARROWED release-gate
//	    dispatch against <base>, the sha of the cycle's green full run
//	    (P-222, 2026-11-01). Prints key=value lines: mode=full|narrowed,
//	    reason=..., files=<changed file count> and, when narrowed,
//	    tags=<comma list>: the sbo_omit_* tags named in a build line of a
//	    changed package or of any package in its test dependency closure,
//	    i.e. the single omit-tag sets the diff can break. mode=full whenever
//	    the diff is not safely narrowable: an unknown base or a failed diff,
//	    more than narrowMaxFiles changed files, a path on narrowForceRules
//	    (toolchain, dependencies, CI and build definitions), or anything
//	    `affected` itself turns into ALL (a shared input, or a file in no
//	    package that is not on the unread list). Fail toward the full run.
//
//	go run ./scripts/ci/cipkgs gate head|base   (run records on stdin)
//	    The release gate's reading of the ci.yml runs of one commit, from
//	    the JSON array `gh run list --json
//	    status,conclusion,event,headBranch,displayTitle` prints. Only
//	    workflow_dispatch runs on main count. A run titled
//	    "ci narrowed since <40-hex sha>" (ci.yml's run-name) is narrowed;
//	    any other title is a full run. `gate head` prints full, or one line
//	    "narrowed <base>" per distinct base of a green narrowed run when no
//	    full run is green, or running, none or failed:<conclusions>.
//	    `gate base` prints full when a full run on main is green, else
//	    not-full: a narrowed run is never the base of another one.
//
// The rules are tables (fallbackRules, unreadRules, raceAllRules, neverRace,
// freshRules, liveEnvMarkers, childTools, pathReadTargetRules, concurrency kinds), one
// test row each in main_test.go.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "cipkgs:", err)
		os.Exit(2)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: cipkgs race [--all | --since <base> <head>] | cipkgs affected <base> <head> | cipkgs fresh | cipkgs split <pkg-dir> <i> <k>")
	}
	if args[0] == "split" {
		// No module lookup: the package directory is read as given, so the
		// mode works from any checkout of the tree.
		return runSplit(args[1:], out)
	}
	if args[0] == "gate" {
		// Reads run records on stdin; needs no checkout at all.
		return runGate(args[1:], os.Stdin, out)
	}
	root, module, err := moduleRoot()
	if err != nil {
		return err
	}
	switch args[0] {
	case "race":
		all := false
		switch {
		case len(args) == 1:
		case len(args) == 2 && args[1] == "--all":
			all = true
		case len(args) == 4 && args[1] == "--since":
			all = raceAllSince(root, args[2], args[3])
		default:
			return errors.New("usage: cipkgs race [--all | --since <base> <head>]")
		}
		pkgs, err := listPackages(root)
		if err != nil {
			return err
		}
		var race []string
		for _, p := range pkgs {
			if neverRace[p.rel] {
				continue
			}
			ok := all
			if !ok {
				ok, err = usesConcurrency(filepath.Join(root, filepath.FromSlash(p.rel)), p.files)
				if err != nil {
					return err
				}
			}
			if ok {
				race = append(race, p.rel)
			}
		}
		sort.Strings(race)
		for _, r := range race {
			fmt.Fprintln(out, r)
		}
		return nil
	case "fresh":
		if len(args) != 1 {
			return errors.New("usage: cipkgs fresh")
		}
		pkgs, err := listPackages(root)
		if err != nil {
			return err
		}
		var fresh []string
		for _, p := range pkgs {
			dir := filepath.Join(root, filepath.FromSlash(p.rel))
			ok := anyRule(freshRules, p.rel)
			if !ok {
				ok, err = namesLiveEnv(dir, p.files)
				if err != nil {
					return err
				}
			}
			if !ok {
				ok, err = testsRunChildTool(dir, p.files)
				if err != nil {
					return err
				}
			}
			if ok {
				fresh = append(fresh, p.rel)
			}
		}
		sort.Strings(fresh)
		for _, f := range fresh {
			fmt.Fprintln(out, f)
		}
		return nil
	case "narrow":
		if len(args) != 3 {
			return errors.New("usage: cipkgs narrow <base> <head>")
		}
		return runNarrow(root, module, args[1], args[2], out)
	case "affected":
		precise := len(args) == 4 && args[1] == "--precise"
		if precise {
			args = append([]string{args[0]}, args[2:]...)
		}
		if len(args) != 3 {
			return errors.New("usage: cipkgs affected [--precise] <base> <head>")
		}
		res, err := affected(root, module, args[1], args[2], precise)
		if err != nil {
			return err
		}
		for _, r := range res {
			fmt.Fprintln(out, r)
		}
		return nil
	default:
		return fmt.Errorf("unknown mode %q", args[0])
	}
}

// ---------------------------------------------------------------- packages

type pkgInfo struct {
	rel   string   // module-relative import path ("." for the root)
	files []string // every Go file name in the directory (tests included)
}

func moduleRoot() (root, module string, err error) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}|{{.Path}}").Output()
	if err != nil {
		return "", "", fmt.Errorf("go list -m: %w", err)
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("go list -m: unexpected %q", out)
	}
	return parts[0], parts[1], nil
}

type listed struct {
	ImportPath     string
	Dir            string
	GoFiles        []string
	TestGoFiles    []string
	XTestGoFiles   []string
	IgnoredGoFiles []string
	Deps           []string
	ForTest        string
}

func goListJSON(root string, args ...string) ([]listed, error) {
	cmd := exec.Command("go", append([]string{"list", "-e", "-json"}, args...)...)
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	var res []listed
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var l listed
		if err := dec.Decode(&l); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode go list: %w", err)
		}
		res = append(res, l)
	}
	return res, nil
}

func listPackages(root string) ([]pkgInfo, error) {
	ls, err := goListJSON(root, "./...")
	if err != nil {
		return nil, err
	}
	var res []pkgInfo
	for _, l := range ls {
		rel, err := filepath.Rel(root, l.Dir)
		if err != nil {
			return nil, err
		}
		files := append(append(append([]string{}, l.GoFiles...), l.TestGoFiles...), l.XTestGoFiles...)
		files = append(files, l.IgnoredGoFiles...) // build-tag variants count too
		res = append(res, pkgInfo{rel: filepath.ToSlash(rel), files: files})
	}
	return res, nil
}

// ---------------------------------------------------------------- race rule

// neverRace are packages that never run under -race, whatever the mode.
// tests/invariant is source scans, toolchain lists and store-backed wire
// checks; it starts no goroutines of its own, and the store's own race run
// covers the store. Measured 607 s with -race against 102 s without on a
// lane laptop run (item 6 of the test-time plan); every assertion still
// runs, in the plain half.
var neverRace = map[string]bool{"tests/invariant": true}

// raceAllRules: a changed path matching any of these makes a full run race
// every package, because a new toolchain or a new dependency version can
// bring a data race into a package that starts no goroutine of its own.
var raceAllRules = []string{"go.mod", "go.sum"}

// raceAllSince reports whether the run must race every package: true when
// the base is unknown, the diff fails, or a raceAllRules path changed.
func raceAllSince(root, base, head string) bool {
	if base == "" || strings.Trim(base, "0") == "" {
		fmt.Fprintln(os.Stderr, "cipkgs: no base for the race scope; racing everything")
		return true
	}
	diff := exec.Command("git", "diff", "--name-only", base, head)
	diff.Dir = root
	out, err := diff.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cipkgs: git diff %s %s failed (%v); racing everything\n", base, head, err)
		return true
	}
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" && anyRule(raceAllRules, l) {
			fmt.Fprintln(os.Stderr, "cipkgs: toolchain or dependency input changed: "+l+"; racing everything")
			return true
		}
	}
	return false
}

// concurrencyImports are the imports that mark a package as concurrent.
var concurrencyImports = map[string]bool{"sync": true, "sync/atomic": true}

// usesConcurrency reports whether any of the files uses a concurrency
// construct: a go statement, a select, a channel type, a send, a receive, or
// an import of sync / sync/atomic.
func usesConcurrency(dir string, files []string) (bool, error) {
	fset := token.NewFileSet()
	for _, name := range files {
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			// A file that does not parse cannot be judged; run it with -race.
			return true, nil //nolint:nilerr // fail toward more checking
		}
		if fileUsesConcurrency(f) {
			return true, nil
		}
	}
	return false, nil
}

func fileUsesConcurrency(f *ast.File) bool {
	for _, imp := range f.Imports {
		if concurrencyImports[strings.Trim(imp.Path.Value, `"`)] {
			return true
		}
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if found {
			return false
		}
		switch x := n.(type) {
		case *ast.GoStmt, *ast.SelectStmt, *ast.SendStmt, *ast.ChanType:
			found = true
		case *ast.UnaryExpr:
			if x.Op == token.ARROW {
				found = true
			}
		}
		return !found
	})
	return found
}

// ---------------------------------------------------------------- fresh rule

// freshRules: packages that always run with -count=1. The end-to-end suites
// build and start binaries and talk to them over sockets with timeouts;
// none of that is an input Go's test cache can see.
var freshRules = []string{"tests/e2e/**", "tests/distro"}

// liveEnvMarkers: a string literal that looks like an environment variable
// name (upper case, digits and underscores, at least two words) with one of
// these as a whole word marks a package whose tests can reach a live
// database, broker, host tool or the network when that variable is set.
var liveEnvMarkers = map[string]bool{"DSN": true, "POSTGRES": true, "PG": true, "LIVE": true, "KAFKA": true, "BROKERS": true, "NATS": true}

// namesLiveEnv reports whether any of the files holds a string literal that
// names a live environment variable.
func namesLiveEnv(dir string, files []string) (bool, error) {
	fset := token.NewFileSet()
	for _, name := range files {
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			// A file that does not parse cannot be judged; keep it fresh.
			return true, nil //nolint:nilerr // fail toward more checking
		}
		if fileNamesLiveEnv(f) {
			return true, nil
		}
	}
	return false, nil
}

func fileNamesLiveEnv(f *ast.File) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if found {
			return false
		}
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			found = isLiveEnvName(strings.Trim(lit.Value, "`\""))
		}
		return !found
	})
	return found
}

// isLiveEnvName reports whether v looks like an environment variable name
// (A-Z first, then A-Z, 0-9 and _, with at least one _) and one of its
// words is a liveEnvMarkers entry.
func isLiveEnvName(v string) bool {
	if len(v) < 3 || v[0] < 'A' || v[0] > 'Z' || !strings.Contains(v, "_") {
		return false
	}
	for _, r := range v {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	for _, w := range strings.Split(v, "_") {
		if liveEnvMarkers[w] {
			return true
		}
	}
	return false
}

// childTools: a test file that starts one of these by its literal name
// (exec.Command("git", ...) or exec.CommandContext(ctx, "go", ...)) marks a
// package fresh. Go's test cache sees the files and variables the test
// process itself reads, not what a child git or go reads (the repository,
// the module graph, the build cache), so a cached pass could be stale.
var childTools = map[string]bool{"git": true, "go": true}

// testsRunChildTool reports whether any of the package's test files starts a
// childTools binary by its literal name.
func testsRunChildTool(dir string, files []string) (bool, error) {
	fset := token.NewFileSet()
	for _, name := range files {
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			// A file that does not parse cannot be judged; keep it fresh.
			return true, nil //nolint:nilerr // fail toward more checking
		}
		if fileRunsChildTool(f) {
			return true, nil
		}
	}
	return false, nil
}

// fileRunsChildTool reports whether f calls exec.Command or
// exec.CommandContext with a childTools literal as the program name.
func fileRunsChildTool(f *ast.File) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "exec" {
			return true
		}
		arg := -1
		switch sel.Sel.Name {
		case "Command":
			arg = 0
		case "CommandContext":
			arg = 1
		}
		if arg < 0 || len(call.Args) <= arg {
			return true
		}
		if lit, ok := call.Args[arg].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			found = childTools[strings.Trim(lit.Value, "`\"")]
		}
		return !found
	})
	return found
}

// ---------------------------------------------------------------- affected

// fallbackRules: a changed path matching any of these makes the run test
// everything. Patterns use path.Match per segment ("**" = any depth).
var fallbackRules = []string{
	"go.mod",
	"go.sum",
	".github/workflows/ci.yml",
	".github/actions/**",
	"scripts/ci/**",
	"scripts/omit-tag-check.sh",
	"testdata/**",
	// No migrations rule (item 22 of the test-time plan): every migrations
	// and pgmigrations directory is a Go package that embeds its .sql
	// files, so classify maps a changed migration to that package and the
	// test import graph finds every package that applies it.
	"Makefile",
	"Makefile.private",
}

// unreadRules: paths no Go test reads, so a change to them alone affects no
// package (the same list ci.yml's paths-ignore uses, website entries
// included since 2026-11-01: that list states no ci job reads them, and
// website/track-gen, the one Go package under website/, is not on it).
var unreadRules = []string{
	"docs/handovers/**",
	"docs/audits/**",
	"docs/decisions/**",
	"docs/strategy/**",
	"docs/demos/**",
	"docs/plans/*.md",
	"marketing/**",
	"design/**",
	"website/*.html",
	"website/*.txt",
	"website/*.xml",
	"website/_redirects",
	"website/_worker.js",
	"website/.well-known/**",
	"website/arcade/**",
	"website/arcade-src/**",
	"website/assets/**",
	"website/deck/**",
	"website/docs/**",
	"website/docs-tools/**",
	"website/legal/**",
	"website/pages-src/**",
	"website/tools/**",
	"PROGRESS.md",
	"CLAUDE.md",
	"AGENTS.md",
	"CHANGELOG.md",
	"kickstart-prompt.md",
	"superbased-final-spec-v2.md",
	".github/workflows/*.yml",
	".github/dependabot.yml",
}

// alwaysRun are test packages every affected run includes: tests/invariant
// reads product source across the tree, so the import graph cannot say
// which change touches it.
var alwaysRun = []string{"tests/invariant"}

// matchRule reports whether rel (slash-separated) matches pattern, where a
// "**" segment matches zero or more path segments.
func matchRule(pattern, rel string) bool {
	return matchSegs(strings.Split(pattern, "/"), strings.Split(rel, "/"))
}

func matchSegs(p, s []string) bool {
	for len(p) > 0 {
		if p[0] == "**" {
			for i := 0; i <= len(s); i++ {
				if matchSegs(p[1:], s[i:]) {
					return true
				}
			}
			return false
		}
		if len(s) == 0 {
			return false
		}
		if ok, _ := path.Match(p[0], s[0]); !ok {
			return false
		}
		p, s = p[1:], s[1:]
	}
	return len(s) == 0
}

func anyRule(rules []string, rel string) bool {
	for _, r := range rules {
		if matchRule(r, rel) {
			return true
		}
	}
	return false
}

// classify maps the changed files to the set of changed package dirs. all is
// true when the run must test everything.
func classify(changed []string, pkgDirs map[string]bool) (dirs map[string]bool, all bool, why string) {
	dirs = map[string]bool{}
	for _, c := range changed {
		if anyRule(fallbackRules, c) {
			return nil, true, "shared input changed: " + c
		}
		if anyRule(unreadRules, c) {
			continue
		}
		d := path.Dir(c)
		for {
			if pkgDirs[d] {
				dirs[d] = true
				break
			}
			if d == "." || d == "/" {
				return nil, true, "file outside every package and not on the unread list: " + c
			}
			d = path.Dir(d)
		}
	}
	return dirs, false, ""
}

// affected is the affected mode. precise selects classifyPrecise
// (precise.go: `affected --precise`, the local gate rerun's rule); without
// it the result is the push rule ci.yml runs, unchanged.
func affected(root, module, base, head string, precise bool) ([]string, error) {
	if base == "" || strings.Trim(base, "0") == "" {
		fmt.Fprintln(os.Stderr, "cipkgs: no base commit; testing everything")
		return []string{"ALL"}, nil
	}
	diff := exec.Command("git", "diff", "--name-only", base, head)
	diff.Dir = root
	out, err := diff.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cipkgs: git diff %s %s failed (%v); testing everything\n", base, head, err)
		return []string{"ALL"}, nil //nolint:nilerr // fail toward more testing
	}
	var changed []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			changed = append(changed, l)
		}
	}
	pkgs, err := listPackages(root)
	if err != nil {
		return nil, err
	}
	pkgDirs := map[string]bool{}
	for _, p := range pkgs {
		pkgDirs[p.rel] = true
	}
	var dirs map[string]bool
	var cs changeSet
	var all bool
	var why string
	if precise {
		cs, all, why = classifyPrecise(changed, pkgDirs)
		dirs = cs.dirs
	} else {
		dirs, all, why = classify(changed, pkgDirs)
	}
	if all {
		fmt.Fprintln(os.Stderr, "cipkgs: "+why+"; testing everything")
		return []string{"ALL"}, nil
	}
	// Packages whose tests read a changed migrations directory by path.
	readers, err := pathReaders(root, pkgs, dirs)
	if err != nil {
		return nil, err
	}
	// Reverse dependencies through the test graph.
	changedImports := map[string]bool{}
	for d := range dirs {
		changedImports[importPath(module, d)] = true
	}
	ls, err := goListJSON(root, "-test", "-deps=false", "./...")
	if err != nil {
		return nil, err
	}
	hit := map[string]bool{}
	for _, l := range ls {
		owner := l.ImportPath
		if l.ForTest != "" {
			owner = l.ForTest
		}
		if strings.HasSuffix(owner, ".test") {
			continue
		}
		if changedImports[owner] {
			hit[owner] = true
			continue
		}
		for _, d := range l.Deps {
			if changedImports[d] {
				hit[owner] = true
				break
			}
		}
	}
	for _, a := range alwaysRun {
		hit[importPath(module, a)] = true
	}
	for _, r := range readers {
		hit[importPath(module, r)] = true
	}
	// --precise: the packages whose change stays in the package, and the
	// packages whose tests read a changed file by path.
	for d := range cs.leaf {
		hit[importPath(module, d)] = true
	}
	fileRd, err := fileReaders(root, pkgs, cs.read)
	if err != nil {
		return nil, err
	}
	for _, r := range fileRd {
		hit[importPath(module, r)] = true
	}
	res := make([]string, 0, len(hit))
	for h := range hit {
		res = append(res, relPath(module, h))
	}
	sort.Strings(res)
	fmt.Fprintf(os.Stderr, "cipkgs: %d changed file(s) in %d package(s) affect %d package(s)\n", len(changed), len(dirs)+len(cs.leaf), len(res))
	return res, nil
}

// pathReadTargetRules: package directories whose files tests read from
// disk by path, outside the import graph (the generators' committed-output
// checks, the stage vocabulary pin, the PostgreSQL twin checks). A change in
// one also affects every package that reads it that way (H2 of the TESTCI
// audit: taxbackfillgen was missing from a migration-only push).
var pathReadTargetRules = []string{"**/migrations", "**/pgmigrations"}

// pathReaders returns the module-relative directories of the packages whose
// _test.go files read one of the changed directories that match
// pathReadTargetRules, found by scanning the test files' path literals
// (testPathLiterals). It parses nothing when no such directory changed.
func pathReaders(root string, pkgs []pkgInfo, changed map[string]bool) ([]string, error) {
	var targets []string
	for d := range changed {
		if anyRule(pathReadTargetRules, d) {
			targets = append(targets, d)
		}
	}
	if len(targets) == 0 {
		return nil, nil
	}
	var res []string
	for _, p := range pkgs {
		lits, err := testPathLiterals(filepath.Join(root, filepath.FromSlash(p.rel)), p.files)
		if err != nil {
			return nil, err
		}
		if readsAny(p.rel, lits, targets) {
			res = append(res, p.rel)
		}
	}
	sort.Strings(res)
	if len(res) > 0 {
		fmt.Fprintf(os.Stderr, "cipkgs: %d package(s) read a changed migrations directory by path: %s\n", len(res), strings.Join(res, " "))
	}
	return res, nil
}

// testPathLiterals returns the path candidates named in the package's
// _test.go files: every string literal, and every run of consecutive string
// literal arguments of a Join call (filepath.Join("..", "db", "migrations",
// f) gives "../db/migrations"), joined with "/".
func testPathLiterals(dir string, files []string) ([]string, error) {
	fset := token.NewFileSet()
	var res []string
	for _, name := range files {
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			// A test file that does not parse cannot be judged here; the
			// package's own compile failure is what CI reports.
			continue
		}
		res = append(res, filePathLiterals(f)...)
	}
	return res, nil
}

func filePathLiterals(f *ast.File) []string {
	var res []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				res = append(res, strings.Trim(x.Value, "`\""))
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Join" {
				return true
			}
			var run []string
			flush := func() {
				if len(run) > 1 {
					res = append(res, strings.Join(run, "/"))
				}
				run = nil
			}
			for _, a := range x.Args {
				if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					run = append(run, strings.Trim(lit.Value, "`\""))
					continue
				}
				flush()
			}
			flush()
		}
		return true
	})
	return res
}

// readsAny reports whether one of the literals, read from package pkgRel,
// names one of the target directories or a path below it. A literal is
// tried relative to the package directory (a test's working directory) and,
// when it does not climb, relative to the module root; a glob segment ends
// the path ("../db/migrations/*.sql" names ../db/migrations).
func readsAny(pkgRel string, lits, targets []string) bool {
	for _, l := range lits {
		l = filepath.ToSlash(l)
		if l == "" || strings.ContainsAny(l, " \t\n") || path.IsAbs(l) {
			continue
		}
		segs := strings.Split(l, "/")
		for i, sg := range segs {
			if strings.ContainsAny(sg, "*?[") {
				segs = segs[:i]
				break
			}
		}
		l = strings.Join(segs, "/")
		if l == "" {
			continue
		}
		cands := []string{path.Join(pkgRel, l)}
		if !strings.HasPrefix(l, "..") {
			cands = append(cands, path.Clean(l))
		}
		for _, c := range cands {
			for _, t := range targets {
				if c == t || strings.HasPrefix(c, t+"/") {
					return true
				}
			}
		}
	}
	return false
}

func importPath(module, rel string) string {
	if rel == "." {
		return module
	}
	return module + "/" + rel
}

func relPath(module, imp string) string {
	if imp == module {
		return "."
	}
	return strings.TrimPrefix(imp, module+"/")
}

// ---------------------------------------------------------------- split

// splitKeyLen is how many characters after "Test" name a test group. Three
// keeps the groups small enough to balance (cmd/observer has about 3,600
// tests) and the patterns short: one alternative per group, never one per
// test, so a pattern stays far below Linux's 128 KiB limit on a single
// argument.
const splitKeyLen = 3

// runSplit implements `cipkgs split <pkg-dir> <i> <k>`.
func runSplit(args []string, out io.Writer) error {
	if len(args) != 3 {
		return errors.New("usage: cipkgs split <pkg-dir> <i> <k>")
	}
	i, errI := strconv.Atoi(args[1])
	k, errK := strconv.Atoi(args[2])
	if errI != nil || errK != nil || k < 1 || i < 0 || i >= k {
		return fmt.Errorf("split: want 0 <= i < k, got %q %q", args[1], args[2])
	}
	names, err := testFuncNames(args[0])
	if err != nil {
		return err
	}
	if flag := splitFlag(names, i, k); flag != "" {
		fmt.Fprintln(out, flag)
	}
	return nil
}

// testFuncNames returns the names of the top-level Test functions declared
// in dir's _test.go files, whatever their build constraint. A file that does
// not parse is left out: its tests are then named by no earlier part's
// pattern, so they run in the last part.
func testFuncNames(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("split: %w", err)
	}
	fset := token.NewFileSet()
	var names []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && isSplitTestName(fn.Name.Name) {
				names = append(names, fn.Name.Name)
			}
		}
	}
	return names, nil
}

// isSplitTestName reports whether n is a test go test runs ("Test" followed
// by nothing or by a rune that is not lower case) spelled only in ASCII
// letters, digits and underscores. Any other test is grouped nowhere and so
// runs in the last part.
func isSplitTestName(n string) bool {
	if !strings.HasPrefix(n, "Test") {
		return false
	}
	for j := 4; j < len(n); j++ {
		c := n[j]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return len(n) == 4 || n[4] < 'a' || n[4] > 'z'
}

// splitKey is a test's group: the first splitKeyLen characters after "Test",
// or, for a shorter name, the whole rest anchored with $ so the group names
// that test only. Keys are therefore prefix-free and each test matches
// exactly one.
func splitKey(n string) string {
	rest := n[len("Test"):]
	if len(rest) >= splitKeyLen {
		return rest[:splitKeyLen]
	}
	return rest + "$"
}

// groupCounts maps each group key to its test count. A group of more than
// maxGroup tests is refined: its key grows by one character at a time (a
// test whose whole name is the key stays as the key anchored with $), until
// every group fits or names a single test. Refined keys extend their parent
// key, so the key set stays prefix-free and each test still matches exactly
// one. Without this, a package whose tests mostly share one three-letter
// prefix (tests/e2e/orgserver: 23 of 57 are TestSecurity...) cannot be cut
// into more than two non-empty parts.
func groupCounts(names []string, maxGroup int) map[string]int {
	count := map[string]int{}
	base := map[string][]string{}
	for _, n := range names {
		key := splitKey(n)
		if strings.HasSuffix(key, "$") {
			count[key]++
			continue
		}
		base[key] = append(base[key], n[len("Test"):])
	}
	for key, rests := range base {
		refineGroup(key, rests, maxGroup, count)
	}
	return count
}

// refineGroup records the tests whose rest-of-name starts with key: as one
// group when they fit in maxGroup (or are one test), else split one
// character further.
func refineGroup(key string, rests []string, maxGroup int, count map[string]int) {
	if len(rests) <= maxGroup || len(rests) == 1 {
		count[key] += len(rests)
		return
	}
	sub := map[string][]string{}
	for _, r := range rests {
		if len(r) == len(key) {
			count[key+"$"]++
			continue
		}
		sub[r[:len(key)+1]] = append(sub[r[:len(key)+1]], r)
	}
	for k, rs := range sub {
		refineGroup(k, rs, maxGroup, count)
	}
}

// splitGroups cuts the sorted groups of names into k contiguous parts of
// about equal test count.
func splitGroups(names []string, k int) [][]string {
	count := groupCounts(names, (len(names)+k-1)/k)
	keys := make([]string, 0, len(count))
	for key := range count {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([][]string, k)
	acc, p := 0, 0
	for _, key := range keys {
		for p < k-1 && acc >= (p+1)*len(names)/k {
			p++
		}
		parts[p] = append(parts[p], key)
		acc += count[key]
	}
	return parts
}

// splitFlag is the go test flag for part i of k (see the split mode in the
// package comment). "" means no flag: the part runs the whole package.
func splitFlag(names []string, i, k int) string {
	if k <= 1 {
		return ""
	}
	parts := splitGroups(names, k)
	if i < k-1 {
		if len(parts[i]) == 0 {
			return "-run=^$"
		}
		return "-run=^Test(?:" + strings.Join(parts[i], "|") + ")"
	}
	var earlier []string
	for _, p := range parts[:k-1] {
		earlier = append(earlier, p...)
	}
	if len(earlier) == 0 {
		return ""
	}
	return "-skip=^Test(?:" + strings.Join(earlier, "|") + ")"
}

// ---------------------------------------------------------------- narrow

// narrowForceRules: a changed path matching any of these makes a repeat
// release commit run the FULL gate instead of a narrowed one (P-222): the
// toolchain and dependencies, the CI definitions and scripts that decide
// what runs, and the build definitions. fallbackRules and the files in no
// package are forced by classify as well.
//
// Of .github only what a ci.yml run executes forces it: ci.yml itself and
// the composite actions. Another workflow (npm-release.yml, ci-private.yml)
// is read by no ci job except tests/invariant, which every narrowed run
// tests (alwaysRun). Measured 2026-11-01: each of the three v1.37.0 fix
// forwards touched another workflow or a website page and would have run
// full under a blanket .github rule.
var narrowForceRules = []string{
	"go.mod",
	"go.sum",
	".github/workflows/ci.yml",
	".github/actions/**",
	"scripts/ci/**",
	"scripts/omit-tag-check.sh",
	"scripts/build-distro.sh",
	"Makefile",
	"Makefile.private",
	"testdata/**",
}

// narrowMaxFiles bounds a narrowed run: a repeat release commit is a small
// fix forward, and a diff above this many files runs the full gate.
const narrowMaxFiles = 300

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// narrowVerdict reports whether the changed files force the full gate, and
// why. It never narrows what `affected` would test in full.
func narrowVerdict(changed []string, pkgDirs map[string]bool) (full bool, why string) {
	if len(changed) > narrowMaxFiles {
		return true, fmt.Sprintf("%d changed files, more than %d", len(changed), narrowMaxFiles)
	}
	for _, c := range changed {
		if anyRule(narrowForceRules, c) {
			return true, "changed path forces a full run: " + c
		}
	}
	if _, all, why := classify(changed, pkgDirs); all {
		return true, why
	}
	return false, ""
}

// runNarrow implements `cipkgs narrow <base> <head>`. Every way it cannot
// judge the diff prints mode=full.
func runNarrow(root, module, base, head string, out io.Writer) error {
	emit := func(full bool, why string, n int, tags []string) {
		mode := "narrowed"
		if full {
			mode = "full"
		}
		fmt.Fprintf(out, "mode=%s\nreason=%s\nfiles=%d\n", mode, why, n)
		if !full {
			fmt.Fprintf(out, "tags=%s\n", strings.Join(tags, ","))
		}
	}
	if !shaRe.MatchString(base) {
		emit(true, "base is not a 40-hex commit sha", 0, nil)
		return nil
	}
	diff := exec.Command("git", "diff", "--name-only", base, head)
	diff.Dir = root
	o, err := diff.Output()
	if err != nil {
		emit(true, fmt.Sprintf("git diff %s %s failed: %v", base, head, err), 0, nil)
		return nil //nolint:nilerr // fail toward the full run
	}
	var changed []string
	for _, l := range strings.Split(string(o), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			changed = append(changed, l)
		}
	}
	pkgs, err := listPackages(root)
	if err != nil {
		return err
	}
	pkgDirs := map[string]bool{}
	for _, p := range pkgs {
		pkgDirs[p.rel] = true
	}
	if full, why := narrowVerdict(changed, pkgDirs); full {
		emit(true, why, len(changed), nil)
		return nil
	}
	dirs, _, _ := classify(changed, pkgDirs)
	tags, err := narrowTags(root, module, pkgs, dirs)
	if err != nil {
		return err
	}
	emit(false, "diff since base is within the narrowing bounds", len(changed), tags)
	return nil
}

// narrowTags returns the sbo_omit_* tags named in a build line of a changed
// package or of any module package in the changed packages' test
// dependency closure (go list -deps -test): the single omit-tag sets whose
// build the diff can change.
func narrowTags(root, module string, pkgs []pkgInfo, changed map[string]bool) ([]string, error) {
	if len(changed) == 0 {
		return nil, nil
	}
	files := map[string][]string{}
	for _, p := range pkgs {
		files[p.rel] = p.files
	}
	closure := map[string]bool{}
	var args []string
	for d := range changed {
		closure[d] = true
		args = append(args, importPath(module, d))
	}
	sort.Strings(args)
	ls, err := goListJSON(root, append([]string{"-deps", "-test"}, args...)...)
	if err != nil {
		return nil, err
	}
	for _, l := range ls {
		if l.Dir == "" {
			continue
		}
		rel, err := filepath.Rel(root, l.Dir)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue // the standard library or another module
		}
		closure[filepath.ToSlash(rel)] = true
	}
	tags := map[string]bool{}
	for d := range closure {
		for _, f := range files[d] {
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(d), f))
			if err != nil {
				return nil, err
			}
			for _, line := range strings.Split(string(data), "\n") {
				for _, t := range buildLineTags(line) {
					tags[t] = true
				}
			}
		}
	}
	res := make([]string, 0, len(tags))
	for t := range tags {
		res = append(res, t)
	}
	sort.Strings(res)
	return res, nil
}

var omitTagRe = regexp.MustCompile(`\bsbo_omit_[A-Za-z0-9_]+`)

// buildLineTags returns the sbo_omit_* tags a //go:build line names (none
// for any other line).
func buildLineTags(line string) []string {
	if !strings.HasPrefix(line, "//go:build ") {
		return nil
	}
	return omitTagRe.FindAllString(line, -1)
}

// ---------------------------------------------------------------- gate

// ghRun is one record of `gh run list --json
// status,conclusion,event,headBranch,displayTitle`.
type ghRun struct {
	Status       string `json:"status"`
	Conclusion   string `json:"conclusion"`
	Event        string `json:"event"`
	HeadBranch   string `json:"headBranch"`
	DisplayTitle string `json:"displayTitle"`
}

// narrowedTitle is ci.yml's run-name for a narrowed dispatch; the base it was
// narrowed against is part of the title, so the run describes itself.
var narrowedTitle = regexp.MustCompile(`^ci narrowed since ([0-9a-f]{40})$`)

func gateRuns(runs []ghRun) []ghRun {
	var sel []ghRun
	for _, r := range runs {
		if r.Event == "workflow_dispatch" && r.HeadBranch == "main" {
			sel = append(sel, r)
		}
	}
	return sel
}

func green(r ghRun) bool { return r.Status == "completed" && r.Conclusion == "success" }

// gateHead is the verdict for the commit being tagged (see the package
// comment): a green full run wins, then green narrowed runs by base.
func gateHead(runs []ghRun) []string {
	sel := gateRuns(runs)
	if len(sel) == 0 {
		return []string{"none"}
	}
	bases := map[string]bool{}
	for _, r := range sel {
		if !green(r) {
			continue
		}
		m := narrowedTitle.FindStringSubmatch(r.DisplayTitle)
		if m == nil {
			return []string{"full"}
		}
		bases[m[1]] = true
	}
	if len(bases) > 0 {
		var res []string
		for b := range bases {
			res = append(res, "narrowed "+b)
		}
		sort.Strings(res)
		return res
	}
	concl := map[string]bool{}
	for _, r := range sel {
		if r.Status != "completed" {
			return []string{"running"}
		}
		concl[r.Conclusion] = true
	}
	var cs []string
	for c := range concl {
		cs = append(cs, c)
	}
	sort.Strings(cs)
	return []string{"failed:" + strings.Join(cs, ",")}
}

// gateBase is full when a full (not narrowed) run of the commit is green.
func gateBase(runs []ghRun) string {
	for _, r := range gateRuns(runs) {
		if green(r) && !narrowedTitle.MatchString(r.DisplayTitle) {
			return "full"
		}
	}
	return "not-full"
}

// runGate implements `cipkgs gate head|base`.
func runGate(args []string, in io.Reader, out io.Writer) error {
	if len(args) != 1 || (args[0] != "head" && args[0] != "base") {
		return errors.New("usage: cipkgs gate head|base < runs.json")
	}
	var runs []ghRun
	if err := json.NewDecoder(in).Decode(&runs); err != nil {
		return fmt.Errorf("gate: decode run records: %w", err)
	}
	if args[0] == "base" {
		fmt.Fprintln(out, gateBase(runs))
		return nil
	}
	for _, l := range gateHead(runs) {
		fmt.Fprintln(out, l)
	}
	return nil
}
