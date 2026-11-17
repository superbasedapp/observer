package secassess

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// simThr builds a threat for the scored pass: id, title, category (STRIDE unless
// the framework is given as a "linddun:" prefix), CWE list and cited places
// ("path:line" or "path:line-endline"), each cited by a missing-control row.
func simThr(id, title, cat string, cwe []string, elem string, refs ...string) Threat {
	fw := FrameworkSTRIDE
	if strings.HasPrefix(cat, "linddun:") {
		fw, cat = FrameworkLINDDUN, strings.TrimPrefix(cat, "linddun:")
	}
	t := thr(id, title, cat, Element{Kind: "component", ID: elem}, 3, 3)
	t.Framework = fw
	t.CWE = cwe
	if len(refs) > 0 {
		m := Missing{Text: "fix it"}
		for _, r := range refs {
			m.Refs = append(m.Refs, simRef(r))
		}
		t.Missing = []Missing{m}
	}
	return t
}

func simRef(s string) Ref {
	path, rest, _ := strings.Cut(s, ":")
	var from, to int
	if a, b, ok := strings.Cut(rest, "-"); ok {
		fmt.Sscanf(a, "%d", &from)
		fmt.Sscanf(b, "%d", &to)
	} else {
		fmt.Sscanf(rest, "%d", &from)
	}
	return Ref{Path: path, Line: from, EndLine: to}
}

// simFeatOf is the feature set of a threat under an element key.
func simFeatOf(t Threat, elem string) *simFeat { return newSimFeat(t, elem) }

// TestDiffSimilarLiveShape is the case the pass exists for: two independent
// runs on one project, both naming the same flaws in their own words, with other
// ids, other component names and a different category for one flaw, and each
// listing a threat the other lacks. The exact passes pair nothing (the live
// comparison read "50 added, 122 removed, 0 changed, 0 read the same"); the
// scored pass pairs the flaws by the code they cite, and lists them as probably
// the same, never as unchanged.
func TestDiffSimilarLiveShape(t *testing.T) {
	first := tmSys(map[string]string{"c_app": "Notes HTTP service", "c_db": "Notes database"},
		simThr("T-001", "Bearer tokens are accepted without verifying the HMAC signature", "spoofing", []string{"CWE-347", "CWE-287"}, "c_app", "server.py:147", "server.py:151", "server.py:153"),
		simThr("T-002", "Session and role state is held in client-writable cookies with no integrity", "tampering", []string{"CWE-565", "CWE-1004"}, "c_app", "server.py:283", "server.py:190"),
		simThr("T-003", "The q parameter is concatenated into the notes query, so any caller can read any table", "information_disclosure", []string{"CWE-89"}, "c_db", "server.py:87", "server.py:431"),
		simThr("T-004", "CORS reflects any Origin and allows credentials, so any page can read authenticated responses", "information_disclosure", []string{"CWE-942", "CWE-346"}, "c_app", "server.py:281", "server.py:286", "server.py:287"),
		simThr("T-005", "Any signed-in user can read any note by id, private notes included", "information_disclosure", []string{"CWE-639"}, "c_app", "server.py:464"),
		simThr("T-006", "Unhandled exceptions return a full traceback to the caller", "information_disclosure", []string{"CWE-209"}, "c_app", "server.py:410"),
		simThr("T-007", "No rate limit, lockout or challenge on the login route", "spoofing", []string{"CWE-307"}, "c_app", "server.py:391"),
		simThr("T-008", "Requests are logged without identity, timestamp or outcome", "repudiation", []string{"CWE-778"}, "c_app", "server.py:240"),
		// Only in the first run.
		simThr("T-009", "The seed file ships a default administrator password", "spoofing", []string{"CWE-798"}, "c_db", "notes.sqlite.seed.sql:3"),
		simThr("T-010", "Unbounded log growth fills the disk", "denial_of_service", []string{"CWE-400"}, "c_app", "server.py:600"),
	)
	second := tmSys(map[string]string{"web": "Web application", "store": "SQLite store"},
		// The same flaws, other words, other ids, other components, a place a few lines off.
		simThr("T-2", "Forged bearer token accepted: the signature is never checked", "spoofing", []string{"CWE-347"}, "web", "server.py:147", "server.py:153", "server.py:146"),
		simThr("T-5", "Search term interpolated into the SQL with an f-string", "tampering", []string{"CWE-89"}, "store", "server.py:431", "server.py:165"),
		simThr("T-9", "Request origin is reflected back with credentials allowed", "information_disclosure", []string{"CWE-942", "CWE-346"}, "web", "server.py:282", "server.py:286"),
		simThr("T-11", "A user can fetch another user's note by changing the id", "information_disclosure", []string{"CWE-639"}, "web", "server.py:465"),
		simThr("T-13", "Login has no brute-force protection", "spoofing", []string{"CWE-307"}, "web", "server.py:392"),
		simThr("T-14", "Log lines carry no time, client or identity", "repudiation", []string{"CWE-778"}, "web", "server.py:241"),
		// Only in the second run.
		simThr("T-20", "Redirect target is taken from the query string", "tampering", []string{"CWE-601"}, "web", "server.py:340"),
	)
	d := DiffModels(first, second)

	if d.Unchanged != 0 || len(d.Changed) != 0 || d.MatchedByID != 0 || d.MatchedByTitle != 0 {
		t.Fatalf("the exact passes paired something: unchanged %d changed %d byID %d byTitle %d", d.Unchanged, len(d.Changed), d.MatchedByID, d.MatchedByTitle)
	}
	got := map[string]string{}
	for _, s := range d.Similar {
		got[s.ID] = s.PrevID
	}
	want := map[string]string{"T-2": "T-001", "T-5": "T-003", "T-9": "T-004", "T-11": "T-005", "T-13": "T-007", "T-14": "T-008"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pairs %v, want %v", got, want)
	}
	if ids := itemIDs(d.Added); !reflect.DeepEqual(ids, []string{"T-20"}) {
		t.Errorf("added %v", ids)
	}
	removed := map[string]bool{}
	for _, id := range itemIDs(d.Removed) {
		removed[id] = true
	}
	for _, id := range []string{"T-002", "T-006", "T-009", "T-010"} {
		if !removed[id] {
			t.Errorf("%s should be left removed (nothing in the second run says the same): %v", id, removed)
		}
	}
	if len(d.Removed) != 4 {
		t.Errorf("removed %v", itemIDs(d.Removed))
	}
	// A different category is shown, the same one is not repeated.
	for _, s := range d.Similar {
		switch s.ID {
		case "T-5":
			if s.PrevCategory != "information_disclosure" || s.Category != "tampering" {
				t.Errorf("T-5 category %q was %q", s.Category, s.PrevCategory)
			}
		default:
			if s.PrevCategory != "" {
				t.Errorf("%s repeats an unchanged category %q", s.ID, s.PrevCategory)
			}
		}
		if len(s.Basis) == 0 || s.Basis[0] != BasisLocation {
			t.Errorf("%s: a pair of these runs is tied by place first, basis %v", s.ID, s.Basis)
		}
		if s.PrevTitle == "" || s.Title == "" {
			t.Errorf("%s: a pair shows both titles", s.ID)
		}
	}
	if d.Empty() {
		t.Error("a comparison with probably-the-same pairs is not empty")
	}
}

// TestDiffSimilarNeverReadsUnchanged: a pair this pass makes is listed as
// probably the same however alike the two read, and is in neither Changed nor
// Unchanged nor the exact counters. Identical numbers, band and status.
func TestDiffSimilarNeverReadsUnchanged(t *testing.T) {
	a := simThr("A-1", "Search term is concatenated into the query", "tampering", []string{"CWE-89"}, "api", "server.py:431")
	b := simThr("B-9", "Search term concatenated in the query string", "tampering", []string{"CWE-89"}, "api", "server.py:431")
	a.Status, b.Status = "identified", "identified"
	d := DiffModels(tmOf(a), tmOf(b))
	if len(d.Similar) != 1 || d.Unchanged != 0 || len(d.Changed) != 0 || len(d.Added) != 0 || len(d.Removed) != 0 || d.MatchedByID != 0 || d.MatchedByTitle != 0 {
		t.Fatalf("%+v", d)
	}
	s := d.Similar[0]
	if s.ID != "B-9" || s.PrevID != "A-1" || s.FromScore != s.ToScore || s.FromBand != s.ToBand {
		t.Errorf("%+v", s)
	}
	if d.Empty() {
		t.Error("an unconfirmed pair must not make two models read as the same")
	}
}

// TestSimilarSignalRows holds one case per row of the points table: what each
// signal scores, and the word it adds to a pair.
func TestSimilarSignalRows(t *testing.T) {
	loc := func(refs ...string) Threat { return simThr("x", "t", "tampering", nil, "e", refs...) }
	withState := func(state RefState, matchLine int, ref string) Threat {
		th := loc(ref)
		th.Missing[0].Refs[0].State, th.Missing[0].Refs[0].MatchLine = state, matchLine
		return th
	}
	cases := []struct {
		name   string
		signal string
		a, b   Threat
		want   int
	}{
		// location
		{"the same line", BasisLocation, loc("server.py:100"), loc("server.py:100"), simPointsNear},
		{"exactly the window apart", BasisLocation, loc("server.py:100"), loc("server.py:105"), simPointsNear},
		{"one past the window", BasisLocation, loc("server.py:100"), loc("server.py:106"), simPointsConflict},
		{"a range reaches the other's line", BasisLocation, loc("server.py:90-110"), loc("server.py:108"), simPointsNear},
		{"a range's end is within the window", BasisLocation, loc("server.py:90-100"), loc("server.py:105"), simPointsNear},
		{"another file", BasisLocation, loc("server.py:100"), loc("app.js:100"), simPointsConflict},
		{"one near place among several far ones", BasisLocation, loc("server.py:10", "server.py:500"), loc("server.py:503"), simPointsNear},
		{"one side cites nothing", BasisLocation, loc(), loc("server.py:100"), 0},
		{"neither cites anything", BasisLocation, loc(), loc(), 0},
		{"a file with no line says nothing", BasisLocation, loc("server.py:0"), loc("server.py:100"), 0},
		{"a place that is not there says nothing", BasisLocation, withState(RefMissing, 0, "server.py:100"), loc("server.py:100"), 0},
		{"an invalid reference says nothing", BasisLocation, withState(RefInvalid, 0, "server.py:100"), loc("server.py:100"), 0},
		{"the line the needle was found on wins", BasisLocation, withState(RefFound, 300, "server.py:100"), loc("server.py:301"), simPointsNear},
		{"the cited line no longer counts once the needle was found elsewhere", BasisLocation, withState(RefFound, 300, "server.py:100"), loc("server.py:100"), simPointsConflict},
		{"slash spelling does not matter", BasisLocation, loc("./src//server.py:100"), loc("src/server.py:100"), simPointsNear},
		// CWE
		{"one CWE in common", BasisCWE, simThr("x", "t", "tampering", []string{"CWE-89", "CWE-20", "CWE-74"}, "e"), simThr("x", "t", "tampering", []string{"CWE-89"}, "e"), simPointsCWESome},
		{"mostly the same CWE set", BasisCWE, simThr("x", "t", "tampering", []string{"CWE-89", "CWE-20"}, "e"), simThr("x", "t", "tampering", []string{"CWE-20", "CWE-89"}, "e"), simPointsCWEMost},
		{"half the union is the same", BasisCWE, simThr("x", "t", "tampering", []string{"CWE-89", "CWE-20"}, "e"), simThr("x", "t", "tampering", []string{"CWE-89"}, "e"), simPointsCWEMost},
		{"CWE spelt in lower case", BasisCWE, simThr("x", "t", "tampering", []string{"cwe-89"}, "e"), simThr("x", "t", "tampering", []string{"CWE-89"}, "e"), simPointsCWEMost},
		{"no CWE in common", BasisCWE, simThr("x", "t", "tampering", []string{"CWE-89"}, "e"), simThr("x", "t", "tampering", []string{"CWE-79"}, "e"), 0},
		{"no CWE at all", BasisCWE, simThr("x", "t", "tampering", nil, "e"), simThr("x", "t", "tampering", nil, "e"), 0},
		// words
		{"the same words", BasisWords, simThr("x", "Forged bearer token accepted", "tampering", nil, "e"), simThr("x", "forged BEARER token accepted!", "tampering", nil, "e"), 3},
		{"four of eight words", BasisWords, simThr("x", "alpha beta gamma delta epsilon zeta", "tampering", nil, "e"), simThr("x", "alpha beta gamma delta eta theta", "tampering", nil, "e"), 2},
		{"a third of the words", BasisWords, simThr("x", "alpha beta gamma delta", "tampering", nil, "e"), simThr("x", "alpha beta eta theta", "tampering", nil, "e"), 1},
		{"a seventh of the words", BasisWords, simThr("x", "alpha beta gamma delta", "tampering", nil, "e"), simThr("x", "alpha eta theta iota kappa lambda", "tampering", nil, "e"), 0},
		{"plurals and endings are one word", BasisWords, simThr("x", "tokens accepted", "tampering", nil, "e"), simThr("x", "token accepts", "tampering", nil, "e"), 3},
		{"stop words and short words count for nothing", BasisWords, simThr("x", "the a of and for", "tampering", nil, "e"), simThr("x", "the a of and for", "tampering", nil, "e"), 0},
		{"the redaction marker is not a shared word", BasisWords, simThr("x", "[REDACTED] one", "tampering", nil, "e"), simThr("x", "[REDACTED] two", "tampering", nil, "e"), 0},
		// category
		{"same framework and category", BasisCategory, simThr("x", "t", "tampering", nil, "e"), simThr("y", "u", "tampering", nil, "e"), simPointsCategory},
		{"another category", BasisCategory, simThr("x", "t", "tampering", nil, "e"), simThr("y", "u", "spoofing", nil, "e"), 0},
		{"the same word in another framework", BasisCategory, simThr("x", "t", "tampering", nil, "e"), simThr("y", "u", "linddun:tampering", nil, "e"), 0},
		{"no category", BasisCategory, simThr("x", "t", "", nil, "e"), simThr("y", "u", "", nil, "e"), 0},
	}
	rows := map[string]simSignal{}
	for _, r := range simSignals {
		rows[r.basis] = r
	}
	for _, tc := range cases {
		t.Run(tc.signal+": "+tc.name, func(t *testing.T) {
			row, ok := rows[tc.signal]
			if !ok {
				t.Fatalf("no row for %q", tc.signal)
			}
			var r simResult
			if got := row.score(simFeatOf(tc.a, "e"), simFeatOf(tc.b, "e"), &r); got != tc.want {
				t.Errorf("points %d, want %d", got, tc.want)
			}
		})
	}
	// element: the same key, and not the empty key.
	a, b := simFeatOf(simThr("x", "t", "tampering", nil, "e"), "k"), simFeatOf(simThr("x", "t", "tampering", nil, "e"), "k")
	if got := simScoreElement(a, b, &simResult{}); got != simPointsElement {
		t.Errorf("same element key: %d", got)
	}
	a.elem, b.elem = "", ""
	if got := simScoreElement(a, b, &simResult{}); got != 0 {
		t.Errorf("an empty element key is not an element: %d", got)
	}
	// Every signal has a row, once, and a basis word the web knows.
	seen := map[string]bool{}
	for _, r := range simSignals {
		if seen[r.basis] || r.score == nil {
			t.Errorf("row %q is repeated or has no scorer", r.basis)
		}
		seen[r.basis] = true
	}
	for _, w := range []string{BasisLocation, BasisCWE, BasisWords, BasisCategory, BasisElement} {
		if !seen[w] {
			t.Errorf("no row for %q", w)
		}
	}
}

// TestSimilarAcceptance holds the rule that turns points into a pair: enough
// points, and a tie by the code or the words, never by the weak signals alone.
func TestSimilarAcceptance(t *testing.T) {
	cases := []struct {
		name string
		a, b Threat
		want bool
	}{
		{
			"the place alone is not enough",
			simThr("a", "Alpha one", "tampering", nil, "p", "server.py:100"), simThr("b", "Beta two", "spoofing", nil, "q", "server.py:100"), false,
		},
		{
			"the place and the category",
			simThr("a", "Alpha one", "tampering", nil, "p", "server.py:100"), simThr("b", "Beta two", "tampering", nil, "q", "server.py:100"), true,
		},
		{
			"the place and the CWE",
			simThr("a", "Alpha one", "tampering", []string{"CWE-89"}, "p", "server.py:100"), simThr("b", "Beta two", "spoofing", []string{"CWE-89"}, "q", "server.py:100"), true,
		},
		{
			"the same CWE, category and element say only that they are of one kind",
			simThr("a", "Alpha one", "tampering", []string{"CWE-89"}, "p"), simThr("b", "Beta two", "tampering", []string{"CWE-89"}, "p"), false,
		},
		{
			"the same CWE and nearly the same words, no place cited",
			simThr("a", "Forged bearer token accepted without check", "tampering", []string{"CWE-347"}, "p"), simThr("b", "Forged bearer token accepted with no check", "spoofing", []string{"CWE-347"}, "q"), true,
		},
		{
			"the same words and category and element, no place, no CWE",
			simThr("a", "alpha beta gamma delta epsilon", "tampering", nil, "p"), simThr("b", "alpha beta gamma delta zeta", "tampering", nil, "p"), true,
		},
		{
			"a place near and a different place of the same file: the near one counts",
			simThr("a", "Alpha one", "tampering", nil, "p", "server.py:10", "server.py:400"), simThr("b", "Beta two", "tampering", nil, "q", "server.py:401"), true,
		},
		{
			"the same CWE and category, but cited code far apart, are different flaws",
			simThr("a", "Alpha one two", "tampering", []string{"CWE-89"}, "p", "server.py:10"), simThr("b", "Alpha one three", "tampering", []string{"CWE-89"}, "p", "server.py:400"), false,
		},
		{
			"another file entirely",
			simThr("a", "Alpha one two", "tampering", []string{"CWE-89"}, "p", "a.py:10"), simThr("b", "Alpha one three", "tampering", []string{"CWE-89"}, "p", "b.py:10"), false,
		},
		{
			"the same words with nothing else",
			simThr("a", "alpha beta gamma", "tampering", nil, "p"), simThr("b", "alpha beta gamma", "spoofing", nil, "q"), false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := simScore(simFeatOf(tc.a, elemKeyOf(tc.a)), simFeatOf(tc.b, elemKeyOf(tc.b)))
			ok := r.points >= simMinPoints && simAnchored(r)
			if ok != tc.want {
				t.Errorf("accepted %v (points %d basis %v), want %v", ok, r.points, r.basis(), tc.want)
			}
		})
	}
}

// elemKeyOf is the element key a test threat is compared under: its element id.
func elemKeyOf(t Threat) string { return t.Element.Kind + "\x00i:" + t.Element.ID }

// TestDiffSimilarOneToOneBestFirst: two earlier threats that both read like one
// new threat do not both pair with it; the better pair is made first, the other
// is left removed, and the answer is the same every time.
func TestDiffSimilarOneToOneBestFirst(t *testing.T) {
	prev := tmOf(
		simThr("P-1", "Search term concatenated into the query", "tampering", []string{"CWE-89"}, "api", "server.py:431"),
		simThr("P-2", "Tag filter concatenated into the query", "tampering", []string{"CWE-89"}, "api", "server.py:433"),
	)
	cur := tmOf(simThr("C-1", "Search term concatenated into the SQL query", "tampering", []string{"CWE-89"}, "api", "server.py:431"))
	d := DiffModels(prev, cur)
	if len(d.Similar) != 1 || d.Similar[0].PrevID != "P-1" {
		t.Fatalf("the closer words and the same line must win: %+v", d.Similar)
	}
	if got := itemIDs(d.Removed); !reflect.DeepEqual(got, []string{"P-2"}) || len(d.Added) != 0 {
		t.Errorf("removed %v added %v", got, itemIDs(d.Added))
	}
	for i := 0; i < 20; i++ {
		if again := DiffModels(prev, cur); !reflect.DeepEqual(again, d) {
			t.Fatal("the pairing is not the same on every run")
		}
	}
}

// TestDiffSimilarPairsAreOneToOne over a larger set: no earlier or new threat is
// in two pairs, and every threat is in exactly one of the buckets.
func TestDiffSimilarPairsAreOneToOne(t *testing.T) {
	var ps, cs []Threat
	for i := 0; i < 40; i++ {
		line := fmt.Sprintf("server.py:%d", 100+i*3)
		ps = append(ps, simThr(fmt.Sprintf("P-%d", i), fmt.Sprintf("Weakness number %d in the handler", i%7), "tampering", []string{"CWE-20"}, "api", line))
		cs = append(cs, simThr(fmt.Sprintf("C-%d", i), fmt.Sprintf("Handler weakness %d reported again", i%7), "tampering", []string{"CWE-20"}, "api", line))
	}
	d := DiffModels(tmOf(ps...), tmOf(cs...))
	seenP, seenC := map[string]int{}, map[string]int{}
	for _, s := range d.Similar {
		seenP[s.PrevID]++
		seenC[s.ID]++
	}
	for id, n := range seenP {
		if n != 1 {
			t.Errorf("earlier %s is in %d pairs", id, n)
		}
	}
	for id, n := range seenC {
		if n != 1 {
			t.Errorf("new %s is in %d pairs", id, n)
		}
	}
	total := len(d.Similar) + d.Unchanged + len(d.Changed)
	if got := total + len(d.Removed); got != len(ps) {
		t.Errorf("earlier threats accounted for %d of %d", got, len(ps))
	}
	if got := total + len(d.Added); got != len(cs) {
		t.Errorf("new threats accounted for %d of %d", got, len(cs))
	}
	if len(d.Similar) == 0 {
		t.Error("nothing paired")
	}
}

// TestDiffSimilarLeavesWhatTheExactPassesPaired: a threat the exact passes
// paired is never offered to the scored one, and the exact counters keep their
// meaning.
func TestDiffSimilarLeavesWhatTheExactPassesPaired(t *testing.T) {
	prev := tmOf(
		simThr("T-1", "Forged login form", "spoofing", []string{"CWE-290"}, "api", "server.py:50"),
		simThr("T-2", "Search term concatenated into the query", "tampering", []string{"CWE-89"}, "api", "server.py:431"),
	)
	cur := tmOf(
		simThr("T-1", "Forged login form", "spoofing", []string{"CWE-290"}, "api", "server.py:50"),
		simThr("X-7", "Query built from the search term by concatenation", "tampering", []string{"CWE-89"}, "api", "server.py:432"),
	)
	d := DiffModels(prev, cur)
	if d.Unchanged != 1 || d.MatchedByID != 1 || len(d.Similar) != 1 || d.Similar[0].ID != "X-7" {
		t.Fatalf("%+v", d)
	}
}

// TestDiffSimilarBeatsAnIdCoincidence: two threats with the same agent id whose
// element and category agree used to be paired as "changed: title changed", on the
// strength of numbering alone. When another threat cites the same place and the
// same weakness, the scored pass takes it first and the numbering coincidence
// pairs nothing.
func TestDiffSimilarBeatsAnIdCoincidence(t *testing.T) {
	prev := tmOf(
		simThr("T-5", "Session fixation on the login route", "spoofing", []string{"CWE-384"}, "api", "server.py:200"),
		simThr("T-9", "Credentials sent in clear text", "spoofing", []string{"CWE-319"}, "api", "static/app.js:5"),
	)
	cur := tmOf(
		simThr("T-5", "Passwords cross the network unencrypted", "spoofing", []string{"CWE-319"}, "api", "static/app.js:6"),
	)
	d := DiffModels(prev, cur)
	if len(d.Similar) != 1 || d.Similar[0].PrevID != "T-9" || len(d.Changed) != 0 || d.MatchedByID != 0 {
		t.Fatalf("%+v", d)
	}
	if ids := itemIDs(d.Removed); !reflect.DeepEqual(ids, []string{"T-5"}) {
		t.Errorf("removed %v", ids)
	}
}

// TestDiffSimilarBandAndOrder: the pair carries both bands, and the list is
// ordered like the others (score, then id).
func TestDiffSimilarBandAndOrder(t *testing.T) {
	mk := func(id string, l, i int, line string) Threat {
		th := simThr(id, "Same words in every title here "+id, "tampering", []string{"CWE-89"}, "api", line)
		th.Rating = Rating{Likelihood: l, Impact: i}
		th.Band, th.Score = BandOf(th.Rating), th.Rating.Score()
		return th
	}
	prev := tmOf(mk("P-1", 2, 2, "server.py:10"), mk("P-2", 2, 2, "server.py:200"))
	cur := tmOf(mk("C-1", 5, 5, "server.py:10"), mk("C-2", 3, 3, "server.py:200"))
	d := DiffModels(prev, cur)
	if len(d.Similar) != 2 || d.Similar[0].ID != "C-1" || d.Similar[0].FromBand != BandLow || d.Similar[0].ToBand != BandCritical || d.Similar[0].ToScore != 25 {
		t.Fatalf("%+v", d.Similar)
	}
}

// TestDiffSimilarWireMembers pins the members of a pair on the wire. The web's
// type and fixture (web/src/lib/secAssessModel.test.ts, SIMILAR_WIRE_MEMBERS)
// pin the same list, so a renamed member fails on both sides.
func TestDiffSimilarWireMembers(t *testing.T) {
	full := DiffSimilar{
		ID: "a", PrevID: "b", Title: "t", PrevTitle: "u", Element: Element{Kind: "component", ID: "c"}, Category: "tampering", PrevCategory: "spoofing",
		FromBand: BandLow, ToBand: BandHigh, FromScore: 4, ToScore: 15, Basis: []string{BasisLocation}, Points: 6,
	}
	blob, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatal(err)
	}
	var got []string
	for k := range m {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"basis", "category", "element", "from_band", "from_score", "id", "points", "prev_category", "prev_id", "prev_title", "title", "to_band", "to_score"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("members %v, want %v", got, want)
	}
	// What a pair of the same category leaves out.
	blob, _ = json.Marshal(DiffSimilar{ID: "a", Basis: []string{BasisWords}})
	if strings.Contains(string(blob), "prev_category") || strings.Contains(string(blob), "from_band") {
		t.Errorf("empty optional members are sent: %s", blob)
	}
}

// TestSimilarWordsStem: the crude stemmer reads the endings of one word as one.
func TestSimilarWordsStem(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"tokens", "token"},
		{"token", "token"},
		{"accepted", "accept"},
		{"accepts", "accept"},
		{"verifying", "verify"},
		{"queries", "query"},
		{"classes", "class"},
		{"access", "access"},
		{"status", "status"},
		{"analysis", "analysis"},
		{"the", ""},
		{"is", ""},
		{"redacted", ""},
		{"and", ""},
		{"sql", "sql"},
	} {
		if got := simStem(tc.in); got != tc.want {
			t.Errorf("simStem(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDiffNoteNamesTheGuess: the sentence that comes with every comparison says
// the scored pairs are a guess and are never counted as unchanged.
func TestDiffNoteNamesTheGuess(t *testing.T) {
	for _, want := range []string{"probably the same", "never counted as unchanged", "renamed"} {
		if !strings.Contains(DiffNote, want) {
			t.Errorf("DiffNote lacks %q", want)
		}
	}
}

// BenchmarkDiffSimilar measures the scored pass on two models of 1,500 threats
// that share nothing exact: the cross product the pass has to read.
func BenchmarkDiffSimilar(b *testing.B) {
	mk := func(prefix string) *ThreatModelDoc {
		var ts []Threat
		for i := 0; i < 1500; i++ {
			ts = append(ts, simThr(fmt.Sprintf("%s-%d", prefix, i), fmt.Sprintf("%s weakness %d in handler %d", prefix, i%97, i%13), "tampering", []string{fmt.Sprintf("CWE-%d", i%40)}, "api", fmt.Sprintf("server.py:%d", i*4)))
		}
		return tmOf(ts...)
	}
	a, c := mk("alpha"), mk("beta")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DiffModels(a, c)
	}
}
