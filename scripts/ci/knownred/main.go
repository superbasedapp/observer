// Command knownred reads the quarantine list of known red tests,
// scripts/ci/known-red.txt, for the local gate scripts (item 4 of the
// test-time plan). A gate that sees a failing test on the list reports it as
// "known red" instead of re-running the test on a base worktree to prove it
// was red before the merge.
//
//	go run ./scripts/ci/knownred check [--today YYYY-MM-DD]
//	    Validates the list and fails when an entry is malformed or past its
//	    expiry date: an expiry forces the owner to fix the test or to renew
//	    the entry with new evidence.
//
//	go run ./scripts/ci/knownred filter [--today YYYY-MM-DD] <go-test-log>
//	    Reads the text output of `go test` and exits 0 only when the log
//	    holds at least one failure and every failing test is on the list,
//	    unexpired, for its package, and its failure output matches the
//	    entry's signature when the entry has one. A failure that names no
//	    test (a build failure, a panic outside a test, a timeout), a test not
//	    on the list, or a listed test that fails some other way (a panic, a
//	    new assertion) exits 1: a new red still fails. Each known red prints
//	    with the tail of its own failure output, so the reader still sees
//	    what failed.
//
// The list is tab separated: test, module-relative package, owner, expiry
// (YYYY-MM-DD, the last day the entry holds), reason, evidence, and an
// optional seventh field, signature: a Go regular expression the test's
// failure output must match for the failure to count as the known one.
// Lines starting with # and blank lines are ignored.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ListFile is the module-relative path of the quarantine list.
const ListFile = "scripts/ci/known-red.txt"

const dateLayout = "2006-01-02"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "knownred:", err)
		os.Exit(1)
	}
}

// Entry is one quarantined test.
type Entry struct {
	Test, Package, Owner string
	Expiry               time.Time
	Reason, Evidence     string
	// Signature, when set, must match the test's failure output for the
	// failure to be the known one (TESTCI audit M1).
	Signature *regexp.Regexp
	Line      int
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: knownred check [--today YYYY-MM-DD] | knownred filter [--today YYYY-MM-DD] <go-test-log>")
	}
	mode := args[0]
	args = args[1:]
	today := time.Now().UTC().Truncate(24 * time.Hour)
	if len(args) >= 2 && args[0] == "--today" {
		d, err := time.Parse(dateLayout, args[1])
		if err != nil {
			return fmt.Errorf("--today: %w", err)
		}
		today = d
		args = args[2:]
	}
	root, err := repoRoot()
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(root, filepath.FromSlash(ListFile)))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	entries, err := Parse(f)
	if err != nil {
		return err
	}
	switch mode {
	case "check":
		if len(args) != 0 {
			return errors.New("usage: knownred check [--today YYYY-MM-DD]")
		}
		expired := Expired(entries, today)
		for _, e := range entries {
			state := "holds until " + e.Expiry.Format(dateLayout)
			if !Active(e, today) {
				state = "EXPIRED " + e.Expiry.Format(dateLayout)
			}
			fmt.Fprintf(out, "%s (%s) owner %s, %s\n", e.Test, e.Package, e.Owner, state)
		}
		if len(expired) > 0 {
			return fmt.Errorf("%s: %d expired entries: fix each test or renew its entry with new evidence", ListFile, len(expired))
		}
		return nil
	case "filter":
		if len(args) != 1 {
			return errors.New("usage: knownred filter [--today YYYY-MM-DD] <go-test-log>")
		}
		lf, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer func() { _ = lf.Close() }()
		module, err := modulePath(root)
		if err != nil {
			return err
		}
		res, err := Filter(lf, module, entries, today)
		if err != nil {
			return err
		}
		for i, k := range res.Known {
			fmt.Fprintf(out, "known red: %s (%s) owner %s, until %s: %s\n", k.Test, k.Package, k.Owner, k.Expiry.Format(dateLayout), k.Reason)
			for _, l := range tail(res.Output[i], tailLines) {
				fmt.Fprintf(out, "    %s\n", l)
			}
		}
		if len(res.Unknown) > 0 {
			return fmt.Errorf("not a known red: %s", strings.Join(res.Unknown, ", "))
		}
		if len(res.Known) == 0 {
			return errors.New("the log names no failing test; the failure is not a known red")
		}
		return nil
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
}

// Parse reads the list. Every entry needs the six fields, a valid date and
// a package path without a leading ./ or a trailing /; a seventh field, when
// present, must be a non-empty regular expression that compiles.
func Parse(r io.Reader) ([]Entry, error) {
	var res []Entry
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 6 && len(f) != 7 {
			return nil, fmt.Errorf("%s:%d: want 6 tab-separated fields (test, package, owner, expiry, reason, evidence) and an optional signature, got %d", ListFile, n, len(f))
		}
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
			if f[i] == "" {
				return nil, fmt.Errorf("%s:%d: field %d is empty", ListFile, n, i+1)
			}
		}
		if !strings.HasPrefix(f[0], "Test") || strings.ContainsAny(f[0], " /") {
			return nil, fmt.Errorf("%s:%d: %q is not a top-level test name", ListFile, n, f[0])
		}
		if strings.HasPrefix(f[1], "./") || strings.HasSuffix(f[1], "/") || strings.Contains(f[1], " ") {
			return nil, fmt.Errorf("%s:%d: package %q must be module-relative (cmd/observer, not ./cmd/observer/)", ListFile, n, f[1])
		}
		d, err := time.Parse(dateLayout, f[3])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: expiry %q: %w", ListFile, n, f[3], err)
		}
		e := Entry{Test: f[0], Package: f[1], Owner: f[2], Expiry: d, Reason: f[4], Evidence: f[5], Line: n}
		if len(f) == 7 {
			re, err := regexp.Compile(f[6])
			if err != nil {
				return nil, fmt.Errorf("%s:%d: signature: %w", ListFile, n, err)
			}
			e.Signature = re
		}
		res = append(res, e)
	}
	return res, sc.Err()
}

// Active reports whether the entry still holds on the given day; the expiry
// day itself is the last day it holds.
func Active(e Entry, today time.Time) bool {
	return !today.After(e.Expiry)
}

// Expired returns the entries past their expiry.
func Expired(entries []Entry, today time.Time) []Entry {
	var res []Entry
	for _, e := range entries {
		if !Active(e, today) {
			res = append(res, e)
		}
	}
	return res
}

// Result is what Filter found in a go test log.
type Result struct {
	Known   []Entry    // failing tests on the list, unexpired
	Output  [][]string // Output[i]: the failure output lines of Known[i]
	Unknown []string   // every other failure, as "Test (package)" or "package: reason"
}

// tailLines is how many lines of a known red's own output filter prints.
const tailLines = 20

var (
	failTestRe = regexp.MustCompile(`^\s*--- FAIL: (Test[^\s/]*)`)
	pkgLineRe  = regexp.MustCompile(`^(ok|FAIL)\s+(\S+)(\s+(.*))?$`)
	// markRe is any line go test writes to say which test the following
	// output belongs to (=== RUN/CONT/PAUSE/NAME, --- FAIL/PASS/SKIP), with
	// the top-level test name.
	markRe = regexp.MustCompile(`^\s*(?:=== (?:RUN|CONT|PAUSE|NAME)|--- (?:FAIL|PASS|SKIP):)\s+(Test[^\s/]*)`)
)

// Filter attributes each failing top-level test to the package whose
// summary line ("ok" or "FAIL" followed by the import path) follows it, and
// sorts the failures into known and unknown. A FAIL package line with no
// failing test of its own (a build failure, a panic, a timeout) is unknown.
func Filter(r io.Reader, module string, entries []Entry, today time.Time) (Result, error) {
	listed := map[string]Entry{}
	for _, e := range entries {
		if Active(e, today) {
			listed[e.Package+" "+e.Test] = e
		}
	}
	var res Result
	seen := map[string]bool{}
	var pending []string
	// output: each top-level test's lines in the current package, by the
	// last marker line seen (go test writes a test's output after its
	// === RUN line in -v and after its --- FAIL line otherwise).
	output := map[string][]string{}
	current := ""
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if m := markRe.FindStringSubmatch(line); m != nil {
			current = m[1]
		}
		if current != "" {
			output[current] = append(output[current], line)
		}
		if m := failTestRe.FindStringSubmatch(line); m != nil {
			pending = append(pending, m[1])
			continue
		}
		m := pkgLineRe.FindStringSubmatch(line)
		if m == nil || (m[2] != module && !strings.HasPrefix(m[2], module+"/")) {
			continue
		}
		pkg := "."
		if m[2] != module {
			pkg = strings.TrimPrefix(m[2], module+"/")
		}
		if m[1] == "FAIL" && len(pending) == 0 {
			res.Unknown = append(res.Unknown, pkg+": "+strings.TrimSpace(m[4]))
		}
		for _, t := range pending {
			key := pkg + " " + t
			if seen[key] {
				continue
			}
			seen[key] = true
			e, ok := listed[key]
			switch {
			case !ok:
				res.Unknown = append(res.Unknown, t+" ("+pkg+")")
			case e.Signature != nil && !e.Signature.MatchString(strings.Join(output[t], "\n")):
				res.Unknown = append(res.Unknown, t+" ("+pkg+"): listed, but the failure does not match its signature /"+e.Signature.String()+"/")
			default:
				res.Known = append(res.Known, e)
				res.Output = append(res.Output, output[t])
			}
		}
		pending = nil
		output = map[string][]string{}
		current = ""
	}
	// Failing tests with no package line after them (a truncated log) are
	// unknown: their package cannot be told.
	for _, t := range pending {
		res.Unknown = append(res.Unknown, t+" (package not named in the log)")
	}
	sort.Sort(byLine{&res})
	return res, sc.Err()
}

// byLine sorts Known (and Output with it) by list line.
type byLine struct{ r *Result }

func (b byLine) Len() int           { return len(b.r.Known) }
func (b byLine) Less(i, j int) bool { return b.r.Known[i].Line < b.r.Known[j].Line }
func (b byLine) Swap(i, j int) {
	b.r.Known[i], b.r.Known[j] = b.r.Known[j], b.r.Known[i]
	b.r.Output[i], b.r.Output[j] = b.r.Output[j], b.r.Output[i]
}

// tail returns the last n lines.
func tail(lines []string, n int) []string {
	if len(lines) > n {
		return lines[len(lines)-n:]
	}
	return lines
}

func repoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse --show-toplevel: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func modulePath(root string) (string, error) {
	cmd := exec.Command("go", "list", "-m")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go list -m: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}
