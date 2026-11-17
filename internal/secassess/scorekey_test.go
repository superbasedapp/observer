package secassess

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The yardstick of the module (depth plan sections 7 and 8, wave W2): a scorer
// that holds a checked assessment up against the answer key of the deliberately
// vulnerable fixture application. It is test support: nothing in a binary
// imports it, it needs no model and it makes no claim about model quality. The
// answer key and the golden results are owned by the fixture lane
// (testdata/secassess); this file reads the key's JSON with its own types, so
// the two lanes share a file format and no code.
//
// The scorer works on what Observer would keep: a result is first run through
// Validate against the project's own copy of the files, and only references
// that the check found at their cited line earn credit (plan section 3.4, V8).

// The schema ids of the two answer-key files the scorer reads.
const (
	scManifestSchema    = "observer.secassess.fixture-truth.v1"
	scThreatModelSchema = "observer.secassess.fixture-threatmodel-truth.v1"
)

// scManifest is truth/manifest.json: the seeded flaws, the decoys and the
// incidental properties.
type scManifest struct {
	Schema  string `json:"schema"`
	Scoring struct {
		AnchorWindowLines int `json:"anchor_window_lines"`
	} `json:"scoring"`
	Flaws      []scFlaw       `json:"flaws"`
	Decoys     []scDecoy      `json:"decoys"`
	Incidental []scIncidental `json:"incidental"`
}

// scFlaw is one seeded weakness.
type scFlaw struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	CWE       []string `json:"cwe"`
	CWEFamily []string `json:"cwe_family"`
	WSTG      []string `json:"wstg"`
	File      string   `json:"file"`
	Anchors   []string `json:"anchors"`
}

// scDecoy is a near miss a careful tester must not report.
type scDecoy struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	NearMissOf string   `json:"near_miss_of"`
	File       string   `json:"file"`
	Anchors    []string `json:"anchors"`
}

// scIncidental is a real property of the fixture that was not seeded.
type scIncidental struct {
	ID    string   `json:"id"`
	Title string   `json:"title"`
	CWE   []string `json:"cwe"`
}

// scTMKey is truth/threatmodel.json: what a complete threat model of the
// fixture contains.
type scTMKey struct {
	Schema        string `json:"schema"`
	Applicability struct {
		ExternalEntity []string `json:"external_entity"`
		Process        []string `json:"process"`
		DataStore      []string `json:"data_store"`
		DataFlow       []string `json:"data_flow"`
	} `json:"stride_applicability"`
	Actors     []scActor      `json:"actors"`
	Components []scComponent  `json:"components"`
	Flows      []scFlow       `json:"flows"`
	Threats    []scTMThreat   `json:"threats"`
	Existing   []scMitigation `json:"existing_mitigations"`
	Traps      []scTrap       `json:"traps"`
}

type scActor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type scComponent struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	File      string   `json:"file"`
	Anchors   []string `json:"anchors"`
	NameHints []string `json:"name_hints"`
	HoldsLogs *bool    `json:"holds_logs"`
}

type scFlow struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	From    string   `json:"from"`
	To      string   `json:"to"`
	Anchors []string `json:"anchors"`
}

// scElem is a component or a flow of the key.
type scElem struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// scCell is an element with a STRIDE category id.
type scCell struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Category string `json:"category"`
}

type scTMThreat struct {
	ID       string   `json:"id"`
	Flaw     string   `json:"flaw"`
	Title    string   `json:"title"`
	Element  scElem   `json:"element"`
	Category string   `json:"category"`
	Accept   []scCell `json:"accept"`
}

// scMitigation is a control that really exists in the fixture.
type scMitigation struct {
	ID      string   `json:"id"`
	Decoy   string   `json:"decoy"`
	Title   string   `json:"title"`
	File    string   `json:"file"`
	Anchors []string `json:"anchors"`
	Needle  string   `json:"needle"`
}

// scTrap is a claim of a mitigation that does not exist.
type scTrap struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	File           string   `json:"file"`
	Anchors        []string `json:"anchors"`
	DefectIfFound  bool     `json:"counts_as_validator_defect_if_found"`
	KnownLimit     bool     `json:"known_limit"`
	ExpectedStates []string `json:"expected_ref_state"`
}

// scParseManifest decodes manifest.json and checks its schema id.
func scParseManifest(data []byte) (*scManifest, error) {
	var m scManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Schema != scManifestSchema {
		return nil, fmt.Errorf("manifest: schema %q, want %q", m.Schema, scManifestSchema)
	}
	if m.Scoring.AnchorWindowLines <= 0 {
		m.Scoring.AnchorWindowLines = 5
	}
	return &m, nil
}

// scParseThreatModelKey decodes threatmodel.json and checks its schema id.
func scParseThreatModelKey(data []byte) (*scTMKey, error) {
	var k scTMKey
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, fmt.Errorf("threat model key: %w", err)
	}
	if k.Schema != scThreatModelSchema {
		return nil, fmt.Errorf("threat model key: schema %q, want %q", k.Schema, scThreatModelSchema)
	}
	return &k, nil
}

// scSource is the project a result was written about: the reference checker
// the validator uses, and whole files for resolving the key's anchors.
type scSource interface {
	RefChecker
	// File returns the lines of a project-relative file.
	File(rel string) ([]string, bool)
}

// scMem is an in-memory project (the scorer's own tests).
type scMem map[string]string

func scSplit(text string) []string {
	return strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
}

// File implements scSource.
func (m scMem) File(rel string) ([]string, bool) {
	s, ok := m[rel]
	if !ok {
		return nil, false
	}
	return scSplit(s), true
}

// Lines implements RefChecker.
func (m scMem) Lines(rel string, first, last int) ([]string, int, LookupStatus) {
	return scSlice(m, rel, first, last)
}

// scDir is a project on disk (the fixture's app copy, or a live run's project).
type scDir struct{ root string }

// File implements scSource.
func (d scDir) File(rel string) ([]string, bool) {
	p := filepath.Join(d.root, filepath.FromSlash(rel))
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return scSplit(string(b)), true
}

// Lines implements RefChecker.
func (d scDir) Lines(rel string, first, last int) ([]string, int, LookupStatus) {
	return scSlice(d, rel, first, last)
}

// scSlice returns lines first..last of a file, clipped, and the file's length.
func scSlice(s interface{ File(string) ([]string, bool) }, rel string, first, last int) ([]string, int, LookupStatus) {
	all, ok := s.File(rel)
	if !ok {
		return nil, 0, LookupMissing
	}
	total := len(all)
	if first < 1 {
		first = 1
	}
	if last > total {
		last = total
	}
	if first > last {
		return nil, total, LookupOK
	}
	return all[first-1 : last], total, LookupOK
}

// scAnchorLine resolves an anchor to its 1-based line. An anchor is a
// substring that occurs exactly once in the file and, unless allowComment is
// set, on a code line; the line is derived here from the project's own copy of
// the file, never stored in the key.
func scAnchorLine(src scSource, rel, anchor string, allowComment bool) (int, error) {
	lines, ok := src.File(rel)
	if !ok {
		return 0, fmt.Errorf("anchor %q: %s is not in the project", anchor, rel)
	}
	var hit []int
	for i, ln := range lines {
		for n := strings.Count(ln, anchor); n > 0; n-- {
			hit = append(hit, i+1)
		}
	}
	if len(hit) != 1 {
		return 0, fmt.Errorf("anchor %q occurs %d times in %s, want exactly one", anchor, len(hit), rel)
	}
	if !allowComment {
		if st, ok := commentStyleOf(rel); ok && !strings.Contains(st.codePart(lines[hit[0]-1]), anchor) {
			return 0, fmt.Errorf("anchor %q in %s is on a comment line, not a code line", anchor, rel)
		}
	}
	return hit[0], nil
}

// scAnchorLines resolves every anchor of one key entry.
func scAnchorLines(src scSource, rel string, anchors []string, allowComment bool) ([]int, error) {
	out := make([]int, 0, len(anchors))
	for _, a := range anchors {
		ln, err := scAnchorLine(src, rel, a, allowComment)
		if err != nil {
			return nil, err
		}
		out = append(out, ln)
	}
	return out, nil
}

// scDistance is how far the line range [lo, hi] is from line: zero when the
// line is inside the range.
func scDistance(lo, hi, line int) int {
	switch {
	case line < lo:
		return lo - line
	case line > hi:
		return line - hi
	}
	return 0
}

// scNear reports whether any anchor line is within window lines of the range.
func scNear(lines []int, lo, hi, window int) bool {
	for _, a := range lines {
		if scDistance(lo, hi, a) <= window {
			return true
		}
	}
	return false
}

// scRange is the line range a reference earns credit at: the line its text was
// found on when the check found it (credit is local, review M2), otherwise the
// range it cites (used to place a reference, never to credit one).
func scRange(r Ref) (int, int) {
	if r.State == RefFound && r.MatchLine > 0 {
		return r.MatchLine, r.MatchLine
	}
	hi := r.EndLine
	if hi < r.Line {
		hi = r.Line
	}
	return r.Line, hi
}

// scTouch is the line a reference is set against a trap with: the line its text
// was found on, else the first line it cites (a wide range does not "touch"
// every trap inside it).
func scTouch(r Ref) (int, int) {
	if r.State == RefFound && r.MatchLine > 0 {
		return r.MatchLine, r.MatchLine
	}
	return r.Line, r.Line
}

// scNorm normalises an id for comparison.
func scNorm(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

// scIntersect reports whether two id lists share a member.
func scIntersect(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if scNorm(x) == scNorm(y) {
				return true
			}
		}
	}
	return false
}

// scMatch is a maximum one-to-one matching of left items to right items.
// Each tier is an adjacency table (tiers[t][i] lists the right items left item
// i may take at that tier, in order of preference); earlier tiers are better
// edges. Tier by tier, the left items still unmatched are given an augmenting
// path over the edges of that tier and the ones before it, so a better edge is
// used whenever it does not cost a match, and the result is a maximum
// matching over all the edges. Kuhn's algorithm over a few dozen items; the
// result is deterministic. It returns, per left item, the right item taken or
// -1.
func scMatch(nLeft, nRight int, tiers ...[][]int) []int {
	takenBy := make([]int, nRight)
	for i := range takenBy {
		takenBy[i] = -1
	}
	matched := make([]bool, nLeft)
	var try func(adj [][]int, l int, seen []bool) bool
	try = func(adj [][]int, l int, seen []bool) bool {
		for _, r := range adj[l] {
			if seen[r] {
				continue
			}
			seen[r] = true
			if takenBy[r] < 0 || try(adj, takenBy[r], seen) {
				takenBy[r] = l
				matched[l] = true
				return true
			}
		}
		return false
	}
	union := make([][]int, nLeft)
	for _, t := range tiers {
		for l := 0; l < nLeft; l++ {
			union[l] = append(union[l], t[l]...)
		}
		for l := 0; l < nLeft; l++ {
			if !matched[l] {
				try(union, l, make([]bool, nRight))
			}
		}
	}
	out := make([]int, nLeft)
	for i := range out {
		out[i] = -1
	}
	for r, l := range takenBy {
		if l >= 0 {
			out[l] = r
		}
	}
	return out
}

// scValidator is what the validator said about a file, in counts.
type scValidator struct {
	State    ValidationState
	Fatal    string
	Refused  int // issues of severity refused
	Dropped  int
	Warned   int
	ItemsOut int // items refused or left out across the collections
	Refs     RefTally
	// Window is the match window the references were checked under (0: no files
	// were looked at). The scorer applies no redactor, the node's check does, so
	// the node can read fewer references as found on the same file: Hidden counts
	// the references whose text a redactor changed, which is 0 here.
	Window int
	Hidden int
	Codes  []string // the distinct issue codes, sorted
}

func scTally(rep Report) scValidator {
	v := scValidator{State: rep.State, Fatal: rep.Fatal, Refs: rep.Refs}
	if rc := rep.RefCheck; rc != nil {
		v.Window, v.Hidden = rc.WindowLines, rc.TextHidden
	}
	codes := map[string]bool{}
	for _, is := range rep.Issues {
		codes[is.Code] = true
		switch is.Severity {
		case SevRefused:
			v.Refused++
		case SevDropped:
			v.Dropped++
		case SevWarn:
			v.Warned++
		}
	}
	for _, c := range rep.Counts {
		v.ItemsOut += c.Refused + c.LeftOut
	}
	for c := range codes {
		v.Codes = append(v.Codes, c)
	}
	sort.Strings(v.Codes)
	return v
}

// scFixtureDir finds the fixture tree: OBSERVER_SECASSESS_FIXTURE_DIR when set
// (a copy of testdata/secassess), else the repository's own. It returns "" when
// neither holds a truth directory.
func scFixtureDir() string {
	cands := []string{os.Getenv("OBSERVER_SECASSESS_FIXTURE_DIR"), filepath.Join("..", "..", "testdata", "secassess")}
	for _, c := range cands {
		if c == "" {
			continue
		}
		if st, err := os.Stat(filepath.Join(c, "truth", "manifest.json")); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

// scLoadKeys reads the two answer-key files of a fixture tree.
func scLoadKeys(t *testing.T, dir string) (*scManifest, *scTMKey) {
	t.Helper()
	mb, err := os.ReadFile(filepath.Join(dir, "truth", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := scParseManifest(mb)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := os.ReadFile(filepath.Join(dir, "truth", "threatmodel.json"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := scParseThreatModelKey(kb)
	if err != nil {
		t.Fatal(err)
	}
	return m, k
}
