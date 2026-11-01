package secfeed

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "net", "os/exec", "github.com/fsnotify/fsnotify"},
		Reason:    "internal/secfeed is the install gate's pure core; the network is internal/secfeed/online",
	})
}

func TestEcosystemTable(t *testing.T) {
	seen := map[Ecosystem]bool{}
	for _, e := range Ecosystems() {
		if seen[e.Eco] || e.OSV == "" || e.PublicHost == "" || e.MetadataHost == "" || e.Normalize == nil || e.NearMissMin < 1 {
			t.Errorf("row %+v incomplete or repeated", e.Eco)
		}
		seen[e.Eco] = true
		if got, ok := EcosystemFromOSV(e.OSV); !ok || got != e.Eco {
			t.Errorf("OSV name %s does not map back", e.OSV)
		}
	}
	cases := []struct {
		eco      Ecosystem
		in, want string
	}{
		{EcoPyPI, "Python_Dateutil", "python-dateutil"},
		{EcoPyPI, "zope.interface", "zope-interface"},
		{EcoNpm, "Left-Pad", "left-pad"},
		{EcoCargo, "serde_json", "serde-json"},
		{EcoGo, "github.com/Corp/X", "github.com/Corp/X"},
	}
	for _, c := range cases {
		if got := Normalize(c.eco, c.in); got != c.want {
			t.Errorf("Normalize(%s, %q) = %q, want %q", c.eco, c.in, got, c.want)
		}
	}
	if Normalize("cobol", "x") != "" {
		t.Error("unknown ecosystem normalizes to empty")
	}
}

func osv(id, eco, name string, versions ...string) []byte {
	v := `[]`
	if len(versions) > 0 {
		v = `["` + strings.Join(versions, `","`) + `"]`
	}
	return []byte(`{"id":"` + id + `","affected":[{"package":{"ecosystem":"` + eco + `","name":"` + name + `"},"versions":` + v + `}]}`)
}

func TestMaliciousFromOSV(t *testing.T) {
	recs := [][]byte{
		osv("MAL-2025-1", "npm", "Evil-Pkg"),
		osv("MAL-2025-2", "npm", "evil-pkg", "1.0.0"),
		osv("MAL-2025-3", "PyPI", "reqeusts", "2.0", "2.1"),
		osv("GHSA-xxxx", "npm", "lodash"),
		[]byte(`{"id":"MAL-2025-4","withdrawn":"2025-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"oops"}}]}`),
		osv("MAL-2025-5", "Hackage", "x"),
		[]byte(`not json`),
	}
	es, st := MaliciousFromOSV(recs)
	if st.Records != 7 || st.Kept != 3 || st.NotMAL != 1 || st.Withdrawn != 1 || st.UnknownEco != 1 || st.Malformed != 1 {
		t.Errorf("stats %+v", st)
	}
	if len(es) != 2 {
		t.Fatalf("entries %+v", es)
	}
	if e := es[0]; e.Eco != EcoNpm || e.Name != "evil-pkg" || len(e.IDs) != 2 || e.Versions != nil {
		t.Errorf("npm merge (a report for every version wins): %+v", e)
	}
	if e := es[1]; e.Eco != EcoPyPI || e.Name != "reqeusts" || len(e.Versions) != 2 {
		t.Errorf("pypi: %+v", e)
	}
}

func buildIndex(t *testing.T) *Index {
	t.Helper()
	es, _ := MaliciousFromOSV([][]byte{osv("MAL-1", "npm", "evil-pkg"), osv("MAL-2", "PyPI", "badlib", "1.0")})
	npm, err := PopularFromList(EcoNpm, []byte("# top\nreact\nlodash\nexpress\nleft-pad\nvue\n"))
	if err != nil {
		t.Fatal(err)
	}
	py, _ := PopularFromList(EcoPyPI, []byte("requests\npython-dateutil\n"))
	ix, err := ParseIndex(EncodeMalicious(es), EncodePopular(map[Ecosystem][]string{EcoNpm: npm, EcoPyPI: py}))
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

func TestLookup(t *testing.T) {
	ix := buildIndex(t)
	cases := []struct {
		eco           Ecosystem
		name, version string
		mal, pop      bool
		near          string
	}{
		{EcoNpm, "evil-pkg", "", true, false, ""},
		{EcoNpm, "Evil-Pkg", "9.9.9", true, false, ""},
		{EcoPyPI, "badlib", "1.0", true, false, ""},
		{EcoPyPI, "badlib", "2.0", false, false, ""},
		{EcoPyPI, "badlib", "", false, false, ""}, // unpinned: some versions listed, never S-741 (ListedVersions)
		{EcoNpm, "react", "", false, true, ""},
		{EcoNpm, "lodahs", "", false, false, "lodash"},    // adjacent swap
		{EcoNpm, "expres", "", false, false, "express"},   // deletion
		{EcoNpm, "exxpress", "", false, false, "express"}, // insertion
		{EcoNpm, "lodasx", "", false, false, "lodash"},    // substitution
		{EcoNpm, "leftpad", "", false, false, "left-pad"}, // separator
		{EcoNpm, "vu", "", false, false, ""},              // too short
		{EcoNpm, "vuex", "", false, false, ""},            // vue is under the minimum
		{EcoPyPI, "python_dateutil", "", false, true, ""}, // normalized, the same name
		{EcoPyPI, "reqests", "", false, false, "requests"},
		{EcoNpm, "something-else", "", false, false, ""},
	}
	for _, c := range cases {
		a := ix.Lookup(c.eco, c.name, c.version)
		if a.Malicious != c.mal || a.Popular != c.pop || a.NearMiss != c.near {
			t.Errorf("%s %s@%s: %+v", c.eco, c.name, c.version, a)
		}
	}
	if a := ix.Lookup(EcoPyPI, "badlib", ""); !a.ListedVersions || a.Malicious {
		t.Errorf("unpinned against a version listing: %+v", a)
	}
	if a := ix.Lookup(EcoPyPI, "badlib", "2.0"); a.ListedVersions || a.Malicious {
		t.Errorf("a pin outside the listing: %+v", a)
	}
	var nilIx *Index
	if a := nilIx.Lookup(EcoNpm, "react", ""); !a.MaliciousMissing || !a.PopularMissing {
		t.Errorf("no index must say both halves are missing: %+v", a)
	}
	half, _ := ParseIndex(nil, EncodePopular(map[Ecosystem][]string{EcoNpm: {"react"}}))
	if a := half.Lookup(EcoNpm, "x", ""); !a.MaliciousMissing || a.PopularMissing {
		t.Errorf("popular-only index: %+v", a)
	}
}

// TestOSVRanges is milestone 2b: the builder reads OSV ranges. A range
// introduced at 0 with no fix covers every version; a range with a fixed
// or last_affected event covers some versions it cannot enumerate, which
// only ever reads ListedVersions (S-749), never Malicious, unless a pinned
// version is enumerated too.
func TestOSVRanges(t *testing.T) {
	rec := func(id, name, ranges string, versions ...string) []byte {
		v := `[]`
		if len(versions) > 0 {
			v = `["` + strings.Join(versions, `","`) + `"]`
		}
		return []byte(`{"id":"` + id + `","affected":[{"package":{"ecosystem":"npm","name":"` + name + `"},"ranges":` + ranges + `,"versions":` + v + `}]}`)
	}
	es, _ := MaliciousFromOSV([][]byte{
		rec("MAL-1", "all-by-range", `[{"type":"SEMVER","events":[{"introduced":"0"}]}]`),
		rec("MAL-2", "fixed-range", `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]`),
		rec("MAL-3", "last-affected", `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"last_affected":"1.0.4"}]}]`),
		rec("MAL-4", "enumerated", `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.0.2"}]}]`, "1.0.0", "1.0.1"),
	})
	ix, err := ParseIndex(EncodeMalicious(es), nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, version string
		mal, some     bool
	}{
		{"all-by-range", "", true, false},
		{"all-by-range", "9.9.9", true, false},
		{"fixed-range", "", false, true},
		{"fixed-range", "1.0.0", false, true},
		{"last-affected", "1.0.2", false, true},
		{"enumerated", "1.0.1", true, false},
		{"enumerated", "1.0.2", false, false},
		{"enumerated", "", false, true},
	}
	for _, c := range cases {
		a := ix.Lookup(EcoNpm, c.name, c.version)
		if a.Malicious != c.mal || a.ListedVersions != c.some {
			t.Errorf("%s@%s: %+v", c.name, c.version, a)
		}
	}
	// An unpinned install against a version listing is S-749's verdict,
	// not S-741's.
	if c := Decide(DecideInput{Spec: InstallSpec{Eco: EcoNpm, Name: "enumerated"}, IndexFreshness: content.Fresh, Offline: ix.Lookup(EcoNpm, "enumerated", "")}); c.Verdict != policy.InstallListedVersion {
		t.Errorf("unpinned: %+v", c)
	}
}

func TestParseIndexRefusals(t *testing.T) {
	cases := map[string][]byte{
		"no header":  []byte("npm\tx\tMAL-1\t*\n"),
		"empty":      {},
		"not MAL":    []byte(maliciousHeader + "\nnpm\tx\tGHSA-1\t*\n"),
		"short line": []byte(maliciousHeader + "\nnpm\tx\n"),
	}
	for name, b := range cases {
		if _, err := ParseIndex(b, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseIndex([]byte(maliciousHeader+"\nhackage\tx\tMAL-1\t*\n"), nil); err != nil {
		t.Errorf("an unknown ecosystem is skipped, not refused: %v", err)
	}
}

func TestWithinOneEdit(t *testing.T) {
	yes := [][2]string{{"abc", "abc"}, {"abc", "abd"}, {"abc", "ab"}, {"abc", "xabc"}, {"abcd", "abdc"}, {"ab", "ba"}}
	no := [][2]string{{"abc", "xyz"}, {"abcd", "badc"}, {"abc", "a"}, {"abcd", "acbe"}}
	for _, p := range yes {
		if !withinOneEdit(p[0], p[1]) {
			t.Errorf("%q %q should be within one edit", p[0], p[1])
		}
	}
	for _, p := range no {
		if withinOneEdit(p[0], p[1]) {
			t.Errorf("%q %q should not be within one edit", p[0], p[1])
		}
	}
}

func TestBuildManifestSignsAndInstallsShape(t *testing.T) {
	data := EncodePopular(map[Ecosystem][]string{EcoNpm: {"react"}})
	m, err := BuildManifest(ManifestInput{
		Kind: content.PopularNames, ManifestVersion: 3, Epoch: 1, Issued: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC),
		Validity: 30 * 24 * time.Hour, Name: PopularArtifact, Data: data, Source: "observer:popular", License: "CC0-1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if e := m.Entries[0]; e.SHA256 != content.HashBytes(data) || e.SizeBytes != int64(len(data)) {
		t.Errorf("entry %+v", e)
	}
	if _, err := BuildManifest(ManifestInput{Kind: content.PopularNames, ManifestVersion: 1, Issued: time.Now(), Validity: 400 * 24 * time.Hour, Name: PopularArtifact, Data: data}); err == nil {
		t.Error("a validity past the kind's bound must fail")
	}
}

// TestParseIndexVerified is milestone 3e: a verified index searched in
// place answers exactly like a parsed one, and ValidateIndex refuses an
// artifact whose lines are out of order (the in-place search needs them
// sorted).
func TestParseIndexVerified(t *testing.T) {
	mal, _ := MaliciousFromOSV([][]byte{
		osv("MAL-1", "npm", "evil-pkg"), osv("MAL-2", "PyPI", "badlib", "1.0"), osv("MAL-3", "npm", "aaa-first"), osv("MAL-4", "npm", "zzz-last", "2.0.0"),
	})
	malB := EncodeMalicious(mal)
	popB := EncodePopular(map[Ecosystem][]string{EcoNpm: {"react", "lodash", "express", "left-pad"}, EcoPyPI: {"requests"}})
	if err := ValidateIndex(malB, false); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIndex(popB, true); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseIndex(malB, popB)
	if err != nil {
		t.Fatal(err)
	}
	fast, err := ParseIndexVerified(malB, popB)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []struct {
		eco     Ecosystem
		name, v string
	}{
		{EcoNpm, "evil-pkg", ""},
		{EcoNpm, "aaa-first", "1"},
		{EcoNpm, "zzz-last", "2.0.0"},
		{EcoNpm, "zzz-last", ""},
		{EcoPyPI, "badlib", "1.0"},
		{EcoPyPI, "badlib", "2.0"},
		{EcoNpm, "lodahs", ""},
		{EcoNpm, "react", ""},
		{EcoPyPI, "reqests", ""},
		{EcoNpm, "nothing-here", ""},
		{EcoCargo, "serde", ""},
	} {
		a, b := parsed.Lookup(q.eco, q.name, q.v), fast.Lookup(q.eco, q.name, q.v)
		if a.Malicious != b.Malicious || a.ListedVersions != b.ListedVersions || a.Popular != b.Popular || a.NearMiss != b.NearMiss || len(a.IDs) != len(b.IDs) {
			t.Errorf("%s %s@%s: parsed %+v, verified %+v", q.eco, q.name, q.v, a, b)
		}
	}
	unsorted := []byte(maliciousHeader + "\nnpm\tzzz\tMAL-1\t*\nnpm\taaa\tMAL-2\t*\n")
	if err := ValidateIndex(unsorted, false); err == nil {
		t.Error("an out-of-order artifact must be refused")
	}
	if err := ValidateIndex([]byte(maliciousHeader+"\nnpm\tx\tGHSA-1\t*\n"), false); err == nil {
		t.Error("ValidateIndex must check fields like ParseIndex")
	}
}
