package secdiffobs

import (
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sectestpath"
)

// Line is one added or removed line with its line number (in the new file
// for an added line, the old file for a removed one).
type Line struct {
	N    int
	Text string
}

// FileDiff is one file's change.
type FileDiff struct {
	// Path is repository-relative and slash-separated.
	Path    string
	Deleted bool
	Added   []Line
	Removed []Line
}

// Observation is one rule hit. Message is fixed rule text.
type Observation struct {
	RuleID  string
	Path    string
	Line    int
	Message string
	// Inference marks a guess about intent (S-762 to S-766, S-770), always
	// flag-only; false is a deterministic observation.
	Inference bool
}

// Rule is one row of the closed rule table.
type Rule struct {
	ID      string
	Message string
	// Inference: the rule guesses intent (section 5.7); it runs only through
	// ObserveWith with Options.Inferences (or a prompt for S-770).
	Inference bool
}

// Rules is THE rule table.
var Rules = []Rule{
	{ID: "S-761", Message: "TLS certificate verification was switched off"},
	{ID: "S-762", Message: "inference: an authentication check (decorator or middleware) was removed or bypassed", Inference: true},
	{ID: "S-763", Message: "inference: a debug branch returns a privileged identity", Inference: true},
	{ID: "S-764", Message: "inference: a CSRF exemption was added", Inference: true},
	{ID: "S-765", Message: "inference: CORS was opened to any origin with credentials", Inference: true},
	{ID: "S-766", Message: "inference: a rate limit was removed", Inference: true},
	{ID: "S-767", Message: "a test was deleted or marked skip, xfail or only"},
	{ID: "S-768", Message: "assertions were removed from a test file"},
	{ID: "S-769", Message: "a check was weakened: a suppression comment, an always-true CI fallback or a lower coverage threshold"},
	{ID: "S-770", Message: "inference: scope drift, files in a sensitive path class changed while the prompt named none of its terms", Inference: true},
}

var ruleMsg = func() map[string]string {
	m := map[string]string{}
	for _, r := range Rules {
		m[r.ID] = r.Message
	}
	return m
}()

var ruleInference = func() map[string]bool {
	m := map[string]bool{}
	for _, r := range Rules {
		m[r.ID] = r.Inference
	}
	return m
}()

// disabledVerification are the TLS-off spellings (S-761).
var disabledVerification = regexp.MustCompile(`(?i)(\bverify\s*=\s*false\b|insecureskipverify\s*:\s*true|rejectunauthorized\s*:\s*false|node_tls_reject_unauthorized\s*[=:]\s*['"]?0|_create_unverified_context|cert_none\b|check_hostname\s*=\s*false|curlopt_ssl_verifypeer\s*,\s*(false|0)|\bcurl\b[^\n]*\s(-k|--insecure)\b|\bwget\b[^\n]*--no-check-certificate|ssl_verify\s*[=:]\s*false|strict-ssl\s*[=:]?\s*false)`)

// skipMarkers are test skip, xfail and only markers (S-767).
var skipMarkers = regexp.MustCompile(`(@pytest\.mark\.(skip|skipif|xfail)\b|@unittest\.(skip|expectedFailure)\b|\bt\.Skip(Now|f)?\(|\b(it|describe|test|context)\.(skip|only)\(|\b(xit|xdescribe|xtest|fit|fdescribe)\(|#\[ignore\]|@Disabled\b|@Ignore\b|\[Ignore\]|\bpending\(\))`)

// assertion matches an assertion line in a test file (S-768).
var assertion = regexp.MustCompile(`(\bassert\w*\s*[(\s]|\bexpect\(|\bt\.(Error|Errorf|Fatal|Fatalf|Fail)\b|\brequire\.\w+\(|\bself\.assert\w+\(|\bAssert\.\w+\(|\bshould\.\w+|\.should\b|\bassert_\w+!?\()`)

// suppressions are comment markers that silence a check (S-769).
var suppressions = regexp.MustCompile(`(#\s*nosec\b|//\s*nosec\b|eslint-disable|//\s*nolint\b|@SuppressWarnings\b|#\s*noqa\b|@ts-ignore|@ts-nocheck|NOSONAR|#\s*pragma:\s*no cover|#\s*type:\s*ignore|//\s*#nosec)`)

// alwaysTrue is an always-true fallback in a CI step (S-769).
var alwaysTrue = regexp.MustCompile(`(\|\|\s*true\b|\|\|\s*exit\s+0\b|continue-on-error:\s*true|allow_failure:\s*true)`)

// coverageKey reads a coverage threshold and its number.
var coverageKey = regexp.MustCompile(`(?i)(fail[_-]under|cov-fail-under|coveragethreshold|minimum_coverage|min_coverage|coverage_threshold|threshold)\D{0,12}?(\d+(\.\d+)?)`)

// IsTestPath reports a test file by its path class: the one original-case
// class table the code rules' per-rule test exclusion reads too
// (sectestpath.Class; lane SEC-P4 decision 13), so FooTest.java and
// FooTests.cs are tests and Latest.java or Contest.cs are not (the lowercase
// suffix match this used before read them as tests).
func IsTestPath(p string) bool {
	_, ok := sectestpath.Class(p)
	return ok
}

// IsCIPath reports a CI configuration file.
func IsCIPath(p string) bool {
	p = strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	return strings.HasPrefix(p, ".github/workflows/") || p == ".gitlab-ci.yml" || path.Base(p) == "jenkinsfile" ||
		strings.HasPrefix(p, ".circleci/") || p == "azure-pipelines.yml" || p == ".travis.yml" || strings.HasPrefix(p, ".buildkite/")
}

// Observe runs every observation rule over the files of one diff; the
// inferences stay off (ObserveWith turns them on).
func Observe(files []FileDiff) []Observation {
	return ObserveWith(files, Options{})
}

// Options select the inference rules of ObserveWith.
type Options struct {
	// Inferences runs S-762 to S-766.
	Inferences bool
	// Prompt runs S-770 when non-nil and its text is not empty. The text
	// is read at decision time and never kept: an observation carries only
	// the path class and the absent term class.
	Prompt *Prompt
}

// Prompt is the session's prompt before the change.
type Prompt struct {
	Text string
}

// ObserveWith runs the observation rules and the inferences o selects.
func ObserveWith(files []FileDiff, o Options) []Observation {
	var out []Observation
	add := func(id, p string, line int) {
		out = append(out, Observation{RuleID: id, Path: p, Line: line, Message: ruleMsg[id], Inference: ruleInference[id]})
	}
	out = append(out, inferences(files, o)...)
	for _, f := range files {
		test := IsTestPath(f.Path)
		ci := IsCIPath(f.Path)
		if test && f.Deleted {
			add("S-767", f.Path, 0)
		}
		removedAsserts, addedAsserts := 0, 0
		for _, l := range f.Removed {
			if test && assertion.MatchString(l.Text) {
				removedAsserts++
			}
		}
		firstAssertLine := 0
		for _, l := range f.Added {
			if disabledVerification.MatchString(l.Text) {
				add("S-761", f.Path, l.N)
			}
			if test && skipMarkers.MatchString(l.Text) && !markerRemovedSame(l.Text, f.Removed) {
				add("S-767", f.Path, l.N)
			}
			if test && assertion.MatchString(l.Text) {
				addedAsserts++
			}
			if suppressions.MatchString(l.Text) && !markerRemovedSame(l.Text, f.Removed) {
				add("S-769", f.Path, l.N)
			}
			if ci && alwaysTrue.MatchString(l.Text) {
				add("S-769", f.Path, l.N)
			}
		}
		if test && !f.Deleted && removedAsserts > addedAsserts {
			for _, l := range f.Removed {
				if assertion.MatchString(l.Text) {
					firstAssertLine = l.N
					break
				}
			}
			add("S-768", f.Path, firstAssertLine)
		}
		if l, ok := coverageLowered(f); ok {
			add("S-769", f.Path, l)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// markerRemovedSame reports an added line whose identical text was removed
// in the same file (a moved line, not a new marker).
func markerRemovedSame(text string, removed []Line) bool {
	t := strings.TrimSpace(text)
	for _, r := range removed {
		if strings.TrimSpace(r.Text) == t {
			return true
		}
	}
	return false
}

// coverageLowered reports an added coverage threshold lower than a
// removed one for the same key.
func coverageLowered(f FileDiff) (int, bool) {
	old := map[string]float64{}
	for _, l := range f.Removed {
		if k, v, ok := coverageValue(l.Text); ok {
			old[k] = v
		}
	}
	for _, l := range f.Added {
		if k, v, ok := coverageValue(l.Text); ok {
			if o, had := old[k]; had && v < o {
				return l.N, true
			}
		}
	}
	return 0, false
}

func coverageValue(text string) (string, float64, bool) {
	m := coverageKey.FindStringSubmatch(text)
	if m == nil {
		return "", 0, false
	}
	v, err := strconv.ParseFloat(m[2], 64)
	if err != nil {
		return "", 0, false
	}
	return strings.ToLower(strings.ReplaceAll(m[1], "-", "_")), v, true
}

// FromEdit builds a FileDiff from an edit's old and new text (the hook's
// Edit payload): the old lines removed and the new lines added, line
// numbers relative to the edit.
func FromEdit(p, oldText, newText string) FileDiff {
	f := FileDiff{Path: p}
	for i, l := range splitLines(oldText) {
		f.Removed = append(f.Removed, Line{N: i + 1, Text: l})
	}
	for i, l := range splitLines(newText) {
		f.Added = append(f.Added, Line{N: i + 1, Text: l})
	}
	return f
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// ParseUnifiedDiff reads a unified diff (any context) into file diffs.
func ParseUnifiedDiff(diff []byte) []FileDiff {
	var (
		out      []FileDiff
		cur      *FileDiff
		oldLn    int
		newLn    int
		inHunk   bool
		fromPath string
	)
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
		}
		cur, inHunk = nil, false
	}
	for _, line := range strings.Split(string(diff), "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			flush()
			fromPath = ""
		case strings.HasPrefix(line, "--- ") && !inHunk:
			fromPath = strings.TrimPrefix(trimQuotes(strings.TrimPrefix(line, "--- ")), "a/")
		case strings.HasPrefix(line, "+++ ") && !inHunk:
			p := trimQuotes(strings.TrimPrefix(line, "+++ "))
			if p == "/dev/null" {
				cur = &FileDiff{Path: fromPath, Deleted: true}
			} else {
				cur = &FileDiff{Path: strings.TrimPrefix(p, "b/")}
			}
		case strings.HasPrefix(line, "@@ "):
			oldLn, newLn = hunkStarts(line)
			inHunk = true
		case inHunk && cur != nil && strings.HasPrefix(line, "+"):
			cur.Added = append(cur.Added, Line{N: newLn, Text: line[1:]})
			newLn++
		case inHunk && cur != nil && strings.HasPrefix(line, "-"):
			cur.Removed = append(cur.Removed, Line{N: oldLn, Text: line[1:]})
			oldLn++
		case inHunk && strings.HasPrefix(line, " "):
			oldLn++
			newLn++
		}
	}
	flush()
	return out
}

func trimQuotes(p string) string {
	if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
		return p[1 : len(p)-1]
	}
	return p
}

// hunkStarts reads "@@ -a[,b] +c[,d] @@".
func hunkStarts(h string) (int, int) {
	f := strings.Fields(h)
	if len(f) < 3 {
		return 1, 1
	}
	num := func(s string) int {
		s = strings.TrimLeft(s, "-+")
		s, _, _ = strings.Cut(s, ",")
		n, err := strconv.Atoi(s)
		if err != nil || n == 0 {
			return 1
		}
		return n
	}
	return num(f[1]), num(f[2])
}

// inferences runs the inference rules o selects (S-762 to S-766, S-770).
func inferences(files []FileDiff, o Options) []Observation {
	var out []Observation
	if o.Inferences {
		for _, f := range files {
			for _, h := range inferRegressions(f) {
				out = append(out, Observation{RuleID: h.rule, Path: f.Path, Line: h.line, Message: ruleMsg[h.rule], Inference: true})
			}
		}
	}
	if o.Prompt != nil {
		for _, d := range ScopeDrift(files, o.Prompt.Text) {
			out = append(out, Observation{RuleID: "S-770", Path: d.Path, Message: ruleMsg["S-770"] + " (" + d.PathClass + " files, no " + d.TermClass + " term)", Inference: true})
		}
	}
	return out
}
