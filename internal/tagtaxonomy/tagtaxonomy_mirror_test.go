package tagtaxonomy

import (
	"os"
	"regexp"
	"sort"
	"testing"
)

// TestTypeScriptMirrorMatches guards the coupling documented in doc.go: the
// dashboard's web/src/lib/tagTaxonomy.ts must carry EXACTLY the same slug set as
// the Go source of truth. A drift (a tag added on one side only) would let the
// picker and the cloud enum disagree, so this fails loudly instead.
func TestTypeScriptMirrorMatches(t *testing.T) {
	const mirror = "../../web/src/lib/tagTaxonomy.ts"
	raw, err := os.ReadFile(mirror)
	if err != nil {
		t.Fatalf("read TS mirror %s: %v", mirror, err)
	}
	// Match the STANDARD_TAGS entries' `slug: "..."`. The category/definition
	// helpers use other keys, so anchoring on `slug:` is precise.
	re := regexp.MustCompile(`slug:\s*"([a-z0-9._-]+)"`)
	found := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		found[m[1]] = struct{}{}
	}
	tsSlugs := make([]string, 0, len(found))
	for s := range found {
		tsSlugs = append(tsSlugs, s)
	}
	sort.Strings(tsSlugs)

	goSlugs := Slugs()

	if len(tsSlugs) != len(goSlugs) {
		t.Fatalf("slug count drift: Go has %d, TS has %d\n  Go: %v\n  TS: %v",
			len(goSlugs), len(tsSlugs), goSlugs, tsSlugs)
	}
	for i := range goSlugs {
		if goSlugs[i] != tsSlugs[i] {
			t.Fatalf("slug mismatch at %d: Go=%q TS=%q\n  Go: %v\n  TS: %v",
				i, goSlugs[i], tsSlugs[i], goSlugs, tsSlugs)
		}
	}
}
