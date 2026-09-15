package cloudcontract

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// structuralDataDictionaryGolden pins the published data-dictionary digest.
// See TestStructuralDataDictionaryDigestIsPinned for why changing it is a
// consent decision, not a test fixup.
const structuralDataDictionaryGolden = "sha256:5c910cc1f0d66d8bc08e54ff182c3f3f26354d5e2290eba29f09f200fcd76d82"

// TestStructuralDataDictionaryDigestIsPinned is the loud gate. The digest is
// what a STANDING consent receipt binds, so a change here is a change to what
// developers agreed to share.
func TestStructuralDataDictionaryDigestIsPinned(t *testing.T) {
	got := StructuralDataDictionaryDigest()
	if got != structuralDataDictionaryGolden {
		t.Fatalf("schema changed: a NEW data-dictionary digest means existing standing grants "+
			"no longer cover the schema; bump revisions deliberately.\n"+
			"  was: %s\n  now: %s\n"+
			"If this change is intended: bump structuralDataDictionaryVersion, update this golden, "+
			"and make sure the consent surface re-confirms every live standing grant "+
			"(store.PrepareStructuralSend already refuses queued snapshots whose recorded "+
			"data-dictionary digest no longer matches their receipt).",
			structuralDataDictionaryGolden, got)
	}
}

// TestStructuralDataDictionaryDigestIsDeterministic proves the digest is a
// function of the enumeration alone (no clock, no map iteration).
func TestStructuralDataDictionaryDigestIsDeterministic(t *testing.T) {
	first := StructuralDataDictionaryDigest()
	for i := 0; i < 25; i++ {
		if got := StructuralDataDictionaryDigest(); got != first {
			t.Fatalf("digest is not deterministic: %s != %s", got, first)
		}
	}
	if !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("digest %q is missing the sha256: prefix", first)
	}
}

// TestStructuralDataDictionaryIsSorted pins the canonical ordering: the digest
// must depend on the SET of declarations, never on the order they were typed.
func TestStructuralDataDictionaryIsSorted(t *testing.T) {
	if !sort.StringsAreSorted(structuralDataDictionary) {
		t.Fatal("structuralDataDictionary is not sorted ascending — the enumeration is canonical, so it must be kept sorted")
	}
	seen := map[string]bool{}
	for _, e := range structuralDataDictionary {
		if seen[e] {
			t.Errorf("duplicate dictionary entry %q", e)
		}
		seen[e] = true
	}
}

// TestStructuralDataDictionaryCoversEverySnapshotField is what keeps the
// hand-written enumeration honest: it walks the ACTUAL structs with reflection
// and requires an exact, two-way match between their JSON field names and the
// dictionary's "field:" entries. Add a field to the snapshot without declaring
// it here and this fails — which is precisely the coupling that makes "changing
// the struct MUST change the digest" true rather than aspirational.
func TestStructuralDataDictionaryCoversEverySnapshotField(t *testing.T) {
	declared := map[string]bool{}
	for _, e := range structuralDataDictionary {
		if !strings.HasPrefix(e, "field:") {
			continue
		}
		body := strings.TrimPrefix(e, "field:")
		// "<struct>.<json name>:<type>" — trim the type tail.
		i := strings.LastIndex(body, ":")
		if i < 0 {
			t.Fatalf("malformed field entry %q (want field:<struct>.<json name>:<type>)", e)
		}
		declared[body[:i]] = true
	}

	actual := map[string]bool{}
	for structName, sample := range map[string]any{
		"structural_snapshot":              StructuralSnapshot{},
		"structural_mix_entry":             StructuralMixEntry{},
		"structural_coverage_denominators": StructuralCoverageDenominators{},
	} {
		rt := reflect.TypeOf(sample)
		for i := 0; i < rt.NumField(); i++ {
			tag := rt.Field(i).Tag.Get("json")
			name, _, _ := strings.Cut(tag, ",")
			if name == "" || name == "-" {
				t.Fatalf("%s.%s has no usable json tag %q — every wire field must be nameable in the data dictionary",
					structName, rt.Field(i).Name, tag)
			}
			actual[structName+"."+name] = true
		}
	}

	for name := range actual {
		if !declared[name] {
			t.Errorf("field %q exists on the wire but is NOT declared in the structural data dictionary — "+
				"a standing grant would authorize a field the developer never saw described", name)
		}
	}
	for name := range declared {
		if !actual[name] {
			t.Errorf("the data dictionary declares %q, which no longer exists on the wire — "+
				"a stale declaration makes the digest describe a schema that is not shipped", name)
		}
	}
}

// TestStructuralDataDictionaryPreimageIsTheJoinedEnumeration proves the exported
// preimage is exactly what a consent surface can show, and that it is what the
// digest covers.
func TestStructuralDataDictionaryPreimageIsTheJoinedEnumeration(t *testing.T) {
	pre := string(StructuralDataDictionaryPreimage())
	lines := strings.Split(pre, "\n")
	if len(lines) != len(structuralDataDictionary) {
		t.Fatalf("preimage has %d lines, enumeration has %d entries", len(lines), len(structuralDataDictionary))
	}
	for i, line := range lines {
		if line != structuralDataDictionary[i] {
			t.Fatalf("preimage line %d = %q, want %q", i, line, structuralDataDictionary[i])
		}
	}
	if got := digest(StructuralDataDictionaryPreimage()); got != StructuralDataDictionaryDigest() {
		t.Fatalf("digest is not taken over the published preimage: %s != %s", got, StructuralDataDictionaryDigest())
	}
}
