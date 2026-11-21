package secfeed

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// build_publish_test.go pins the builder halves the feed publisher relies
// on (vendorsign secindex, deploy/feed-publisher): the streaming malicious
// builder, the line split that keeps every entry inside MaxIndexLineLen,
// the per-item caps behind it, and the popular-name reader for ranked
// name arrays. Every name and id here is synthetic.

// TestMaliciousBuilderMatchesFromOSV: feeding records one at a time gives
// exactly what the slice form gives.
func TestMaliciousBuilderMatchesFromOSV(t *testing.T) {
	recs := [][]byte{
		osv("MAL-2026-1", "npm", "evil-a"),
		osv("MAL-2026-2", "npm", "evil-b", "1.0.0", "1.0.1"),
		osv("MAL-2026-3", "npm", "Evil-B", "1.0.2"),
		osv("GHSA-xxxx", "npm", "lodash"),
		osv("MAL-2026-4", "PyPI", "bad_lib"),
		[]byte(`not json`),
	}
	want, wantSt := MaliciousFromOSV(recs)
	b := NewMaliciousBuilder()
	for _, r := range recs {
		b.Add(r)
	}
	if b.Len() != 3 || b.Stats().Kept != 4 {
		t.Errorf("Len %d Stats %+v", b.Len(), b.Stats())
	}
	got, gotSt := b.Entries()
	if !reflect.DeepEqual(got, want) || gotSt != wantSt {
		t.Errorf("builder %+v %+v, slice %+v %+v", got, gotSt, want, wantSt)
	}
}

// TestMaliciousBuilderCaps: one row per cap. An item the index cannot
// carry never vanishes silently: a bad id or name is counted malformed, a
// bad version turns the entry ranged.
func TestMaliciousBuilderCaps(t *testing.T) {
	long := strings.Repeat("v", maxMaliciousVersion+1)
	rows := []struct {
		name      string
		rec       []byte
		malformed int
		listed    bool
		ranged    bool
		versions  []string
	}{
		{"id with a comma", osv("MAL-1,MAL-2", "npm", "x-pkg"), 1, false, false, nil},
		{"id too long", osv("MAL-"+strings.Repeat("9", maxMaliciousID), "npm", "x-pkg"), 1, false, false, nil},
		{"name too long", osv("MAL-3", "npm", strings.Repeat("n", maxMaliciousName+1)), 1, false, false, nil},
		{"version too long", osv("MAL-4", "npm", "x-pkg", "1.0.0", long), 0, true, true, []string{"1.0.0"}},
		{"version with a comma", osv("MAL-5", "npm", "x-pkg", "1,0"), 0, true, true, nil},
		{"ordinary", osv("MAL-6", "npm", "x-pkg", "2.0.0"), 0, true, false, []string{"2.0.0"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			es, st := MaliciousFromOSV([][]byte{r.rec})
			if st.Malformed != r.malformed || (len(es) == 1) != r.listed {
				t.Fatalf("entries %+v stats %+v", es, st)
			}
			if r.listed && (es[0].Ranged != r.ranged || !reflect.DeepEqual(es[0].Versions, r.versions)) {
				t.Errorf("entry %+v", es[0])
			}
		})
	}
}

// TestEncodeMaliciousSplitsLongEntries: an entry too long for one line is
// written as several lines with the same key; the artifact still passes
// the node's check, and every lookup reads as it would from one line.
func TestEncodeMaliciousSplitsLongEntries(t *testing.T) {
	var versions []string
	for i := 0; i < 700; i++ {
		versions = append(versions, fmt.Sprintf("1.%d.%d-synthetic", i/10, i%10))
	}
	var ids []string
	for i := 0; i < 300; i++ {
		ids = append(ids, fmt.Sprintf("MAL-2026-%06d", i))
	}
	entries := []MaliciousEntry{
		{Eco: EcoNuGet, Name: "many.versions.pkg", IDs: []string{"MAL-2026-1"}, Versions: versions},
		{Eco: EcoNpm, Name: "many-reports", IDs: ids},
		{Eco: EcoNpm, Name: "both-long", IDs: ids, Versions: versions, Ranged: true},
		{Eco: EcoNpm, Name: "short", IDs: []string{"MAL-2026-2"}, Versions: []string{"0.1.0"}},
	}
	data := EncodeMalicious(entries)
	if err := ValidateIndex(data, false); err != nil {
		t.Fatalf("ValidateIndex: %v", err)
	}
	perName := map[string]int{}
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n")[1:] {
		if len(l) > MaxIndexLineLen {
			t.Errorf("a %d-byte line", len(l))
		}
		perName[strings.Split(l, "\t")[1]]++
	}
	if perName["many.versions.pkg"] < 2 || perName["many-reports"] < 2 || perName["both-long"] < 2 || perName["short"] != 1 {
		t.Fatalf("lines per name %v", perName)
	}
	if !bytes.Equal(data, EncodeMalicious(entries)) {
		t.Error("the encoding is not deterministic")
	}

	full, err := ParseIndex(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := ParseIndexVerified(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ix := range []*Index{full, verified} {
		last := versions[len(versions)-1]
		if a := ix.Lookup(EcoNuGet, "many.versions.pkg", last); !a.Malicious || !reflect.DeepEqual(a.IDs, []string{"MAL-2026-1"}) {
			t.Errorf("pinned version on the last line: %+v", a)
		}
		if a := ix.Lookup(EcoNuGet, "many.versions.pkg", versions[0]); !a.Malicious {
			t.Errorf("pinned version on the first line: %+v", a)
		}
		if a := ix.Lookup(EcoNuGet, "many.versions.pkg", "9.9.9"); a.Malicious || a.ListedVersions {
			t.Errorf("an unlisted pinned version: %+v", a)
		}
		// Unpinned: listed versions, the one id once, though every line names it.
		if a := ix.Lookup(EcoNuGet, "many.versions.pkg", ""); a.Malicious || !a.ListedVersions || len(a.IDs) != 1 {
			t.Errorf("unpinned: %+v", a)
		}
		if a := ix.Lookup(EcoNpm, "many-reports", "any"); !a.Malicious || !reflect.DeepEqual(a.IDs, ids) {
			t.Errorf("every version, ids split over lines: malicious %v, %d ids", a.Malicious, len(a.IDs))
		}
		// Ranged stays ranged: an unlisted pinned version may be one of the
		// unnamed ones (S-749), never clean.
		if a := ix.Lookup(EcoNpm, "both-long", "9.9.9"); a.Malicious || !a.ListedVersions || len(a.IDs) != len(ids) {
			t.Errorf("ranged, split: malicious %v listed %v, %d ids", a.Malicious, a.ListedVersions, len(a.IDs))
		}
		// Ids and versions both split: a listed pinned version still
		// carries every id, as one line would.
		if a := ix.Lookup(EcoNpm, "both-long", versions[len(versions)/2]); !a.Malicious || len(a.IDs) != len(ids) {
			t.Errorf("both split, pinned listed: malicious %v, %d ids", a.Malicious, len(a.IDs))
		}
	}
}

// TestPopularFromNames: a ranked name array normalizes and deduplicates
// like a line list, and a name no registry could hold is skipped.
func TestPopularFromNames(t *testing.T) {
	got, err := PopularFromNames(EcoPyPI, []string{"Synthetic_Lib", "synthetic-lib", "other.pkg", "has space", "ctl\x01name", "", strings.Repeat("x", MaxIndexLineLen)})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"other-pkg", "synthetic-lib"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	lines, err := PopularFromList(EcoPyPI, []byte("# comment\nSynthetic_Lib\n\nother.pkg\n"))
	if err != nil || !reflect.DeepEqual(lines, got) {
		t.Errorf("the line list reads %v (%v), the array %v", lines, err, got)
	}
	if _, err := PopularFromNames("cobol", []string{"x"}); err == nil {
		t.Error("an unknown ecosystem must be refused")
	}
	many := make([]string, MaxPopularPer+1)
	for i := range many {
		many[i] = fmt.Sprintf("pkg-%d", i)
	}
	if _, err := PopularFromNames(EcoNpm, many); err == nil {
		t.Error("more than MaxPopularPer names must be refused")
	}
}
