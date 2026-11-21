package secreach

// Languages an ImportSet is keyed by (Classify's imports map).
const (
	// LangGo is the Go import list.
	LangGo = "go"
	// LangJS is the JavaScript and TypeScript import list (.js .mjs .cjs
	// .jsx .ts .mts .cts .tsx), keyed by npm package name.
	LangJS = "js"
	// LangPython is the Python import list, keyed by dotted module path.
	LangPython = "python"
	// LangRust is the Rust import list, keyed by crate name.
	LangRust = "rust"
)

// recordMatcher decides one record against one language's import list.
type recordMatcher func(adv Advisory, rec Record, set ImportSet, paths []string) Tier

// ecosystemRow maps an OSV ecosystem to the language whose import list
// decides it, and the matcher. An ecosystem without a row is Unknown
// (ReasonNoMapping).
type ecosystemRow struct {
	Ecosystem string
	Language  string
	Match     recordMatcher
	// NeedsRecords: the decision reads the records (Go: the affected
	// import paths). A row without it decides on the package name alone,
	// so a finding whose local records are missing is still decided (its
	// records only add the Rust call level).
	NeedsRecords bool
	// Missing is the reason when no import list for the language was
	// handed in.
	Missing Reason
	// Artifact, when set, decides a finding read out of a build artifact
	// (Advisory.Artifact), which has no import list: an ecosystem without
	// one is Unknown (ReasonNoArtifactMapping).
	Artifact artifactMatcher
}

var ecosystemRows = []ecosystemRow{
	{Ecosystem: "Go", Language: LangGo, Match: matchGoRecord, NeedsRecords: true, Missing: ReasonNoImportData, Artifact: matchGoArtifactRecord},
	{Ecosystem: "npm", Language: LangJS, Match: matchNPMRecord, Missing: ReasonNoCodeIntel},
	{Ecosystem: "PyPI", Language: LangPython, Match: matchPyPIRecord, Missing: ReasonNoCodeIntel},
	{Ecosystem: "crates.io", Language: LangRust, Match: matchCrateRecord, Missing: ReasonNoCodeIntel},
}

// LanguageFor returns the language whose import list decides an OSV
// ecosystem, ok false for an ecosystem with no mapping. A caller builds
// only the import lists some finding needs.
func LanguageFor(ecosystem string) (string, bool) {
	if row, ok := rowFor(ecosystem); ok {
		return row.Language, true
	}
	return "", false
}

// NeedsRecords reports whether the ecosystem's decision reads the advisory
// records (a caller skips building an import list for a finding with none).
func NeedsRecords(ecosystem string) bool {
	row, ok := rowFor(ecosystem)
	return ok && row.NeedsRecords
}

func rowFor(ecosystem string) (ecosystemRow, bool) {
	for _, row := range ecosystemRows {
		if row.Ecosystem == ecosystem {
			return row, true
		}
	}
	return ecosystemRow{}, false
}

// ClassifyArtifact returns the tier of a finding read out of a build
// artifact (adv.Artifact), which no import list decides: each record is
// decided by the ecosystem's artifact rules (Go: goArtifactRules), the
// strongest decision wins, and ev is the seam symbol evidence (3b-bin)
// enters by; its zero value is "no evidence collected".
func ClassifyArtifact(adv Advisory, ev BinaryEvidence) Tier {
	row, ok := rowFor(adv.Ecosystem)
	if !ok || row.Artifact == nil {
		return UnknownTier(ReasonNoArtifactMapping)
	}
	if len(adv.Records) == 0 {
		return UnknownTier(ReasonNoAdvisory)
	}
	best := Tier{}
	for i, rec := range adv.Records {
		t := row.Artifact(adv, rec, ev)
		if i == 0 || t.SortRank() > best.SortRank() {
			best = t
		}
	}
	return best
}

// Classify returns the finding's tier: each record is decided against the
// ecosystem's import list, and the strongest decision wins (SortRank:
// Called over Imported over the tests-only forms over Unknown over
// NotImportedDirectly: one record the list cannot decide keeps the finding
// Unknown rather than "not imported"). imports is keyed by language
// (LangGo, LangJS, LangPython, LangRust).
func Classify(adv Advisory, imports map[string]ImportSet) Tier {
	row, ok := rowFor(adv.Ecosystem)
	if !ok {
		return UnknownTier(ReasonNoMapping)
	}
	records := adv.Records
	if len(records) == 0 {
		if row.NeedsRecords {
			return UnknownTier(ReasonNoAdvisory)
		}
		records = []Record{{}}
	}
	set, ok := imports[row.Language]
	if !ok {
		return UnknownTier(row.Missing)
	}
	paths := set.sortedPaths()
	best := Tier{}
	for i, rec := range records {
		t := row.Match(adv, rec, set, paths)
		if i == 0 || t.SortRank() > best.SortRank() {
			best = t
		}
	}
	return best
}

// decide turns a lookup (found, from a non-test file, the matched path)
// into a tier against the set's completeness.
func decide(set ImportSet, found, nonTest bool, match string) Tier {
	switch {
	case found:
		return Tier{Level: Imported, Source: set.Source, TestsOnly: !nonTest, Match: match}
	case set.Complete:
		return Tier{Level: NotImportedDirectly, Source: set.Source}
	}
	return UnknownTier(ReasonIncomplete)
}
