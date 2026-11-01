package seccorpus

import "strings"

// Exclusion is one ecosystem exclusion: code in the corpus that is not the
// project's own, so a finding there says nothing about the rule's precision
// on code an agent writes. A row matches a directory Segment anywhere in the
// path, a file name Suffix, or a repository-relative path Prefix.
type Exclusion struct {
	ID        string
	Ecosystem string
	Segment   string
	Suffix    string
	Prefix    string
	Why       string
}

// Exclusions is the table, walked top-down; the first row that matches
// wins. Test code is NOT excluded: an agent writes tests too, and a rule
// that fires on them is measured on them.
var Exclusions = []Exclusion{
	{ID: "deps.node_modules", Ecosystem: "javascript", Segment: "node_modules", Why: "installed packages"},
	{ID: "deps.bower", Ecosystem: "javascript", Segment: "bower_components", Why: "installed packages"},
	{ID: "deps.vendor", Ecosystem: "go, php, ruby", Segment: "vendor", Why: "vendored dependencies"},
	{ID: "deps.third_party", Ecosystem: "any", Segment: "third_party", Why: "copied third-party code"},
	{ID: "deps.third-party", Ecosystem: "any", Segment: "third-party", Why: "copied third-party code"},
	{ID: "deps.venv", Ecosystem: "python", Segment: ".venv", Why: "a virtual environment"},
	{ID: "deps.venv-plain", Ecosystem: "python", Segment: "venv", Why: "a virtual environment"},
	{ID: "deps.site-packages", Ecosystem: "python", Segment: "site-packages", Why: "installed packages"},
	{ID: "build.min-js", Ecosystem: "javascript", Suffix: ".min.js", Why: "a minified bundle"},
	{ID: "build.bundle-js", Ecosystem: "javascript", Suffix: ".bundle.js", Why: "a built bundle"},
	{ID: "gen.pb-go", Ecosystem: "go", Suffix: ".pb.go", Why: "generated protobuf code"},
	{ID: "gen.designer-cs", Ecosystem: "csharp", Suffix: ".Designer.cs", Why: "generated designer code"},
	{ID: "self.rule-fixtures", Ecosystem: "this repository", Prefix: "internal/secrulepack/testdata/", Why: "the pack's own seeded fixtures (the recall half, written to fire)"},
}

// Excluded returns the first exclusion row that matches a repository path.
func Excluded(p string) (Exclusion, bool) {
	parts := strings.Split(p, "/")
	for _, e := range Exclusions {
		if e.Prefix != "" && strings.HasPrefix(p, e.Prefix) {
			return e, true
		}
		if e.Suffix != "" && strings.HasSuffix(parts[len(parts)-1], e.Suffix) {
			return e, true
		}
		if e.Segment != "" {
			for _, s := range parts[:len(parts)-1] {
				if s == e.Segment {
					return e, true
				}
			}
		}
	}
	return Exclusion{}, false
}

// Partition splits candidate findings into those kept for labelling and a
// count of the excluded ones per exclusion id.
func Partition(cands []Finding) (kept []Finding, excluded map[string]int) {
	excluded = map[string]int{}
	for _, f := range cands {
		if e, ok := Excluded(f.Path); ok {
			excluded[e.ID]++
			continue
		}
		kept = append(kept, f)
	}
	return kept, excluded
}
