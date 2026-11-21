package secreach

import "strings"

// golang_artifact.go decides the tier of a Go binary's embedded standard
// library (OS and CI vulnerability scanning plan section 14.6, item 4, the
// operator rulings of 2026-11-05 "Item 4 Go stdlib" (b) to (d)).
//
// The finding is a version match: the binary's build info names the Go
// release it was built with, and that release is in a Go vulnerability
// database "stdlib" advisory's affected range. Nothing in it says whether
// the binary reaches the affected code, so the default tier is
// PotentiallyAffected (source "go-buildinfo"): a label and a sort rank,
// never a severity change. Only symbol evidence moves it (3b-bin, built by
// another lane): BinaryEvidence is the one seam it enters by, and
// goArtifactRules is the table it adds rows to. A binary with no symbol
// table is Unknown, not PotentiallyAffected.

// SymbolState is what symbol evidence says about a binary.
type SymbolState string

// The symbol states. The zero value is "not collected": nothing has looked
// at the binary's symbols (the state of every binary until 3b-bin lands).
// 3b-bin adds its states (called, not called) here and a row to
// goArtifactRules above the default.
const (
	// SymbolsNotCollected: no symbol evidence was collected.
	SymbolsNotCollected SymbolState = ""
	// SymbolsStripped: the binary has no symbol table, so there is nothing
	// to check an affected function against.
	SymbolsStripped SymbolState = "stripped"
)

// BinaryEvidence is what is known about one binary beyond its build info.
// The zero value is "nothing collected".
type BinaryEvidence struct {
	Symbols SymbolState
}

// artifactMatcher decides one advisory record of a build artifact.
type artifactMatcher func(adv Advisory, rec Record, ev BinaryEvidence) Tier

// goArtifactRule is one row of the Go artifact rule table: the first row
// whose When holds decides the record.
type goArtifactRule struct {
	Name   string
	When   func(adv Advisory, rec Record, ev BinaryEvidence) bool
	Decide func(adv Advisory, rec Record, ev BinaryEvidence) Tier
}

// goArtifactRules is walked top-down (one test case per row in
// golang_artifact_test.go).
var goArtifactRules = []goArtifactRule{
	{
		// The Go toolchain is its own advisory identity ("toolchain": the
		// go command, which runs where the code is built) and is never
		// attached to a binary (ruling (c)). Nothing produces such a
		// finding for a binary; this row keeps a stray one from reading as
		// a property of the binary.
		Name: "toolchain",
		When: func(adv Advisory, _ Record, _ BinaryEvidence) bool { return adv.Package == goToolchain },
		Decide: func(Advisory, Record, BinaryEvidence) Tier {
			return UnknownTier(ReasonNotALibrary)
		},
	},
	{
		// A binary with no symbol table: symbol evidence cannot exist, so
		// the match stays Unknown (ruling (d), RG-0's table).
		Name: "stripped",
		When: func(_ Advisory, _ Record, ev BinaryEvidence) bool { return ev.Symbols == SymbolsStripped },
		Decide: func(Advisory, Record, BinaryEvidence) Tier {
			return UnknownTier(ReasonStripped)
		},
	},
	{
		// An advisory whose affected packages are all under cmd/ is a flaw
		// of the go command or another toolchain program, which a compiled
		// program does not embed.
		Name: "cmd only",
		When: func(_ Advisory, rec Record, _ BinaryEvidence) bool {
			if len(rec.ImportPaths) == 0 {
				return false
			}
			for _, p := range rec.ImportPaths {
				if p != "cmd" && !strings.HasPrefix(p, "cmd/") {
					return false
				}
			}
			return true
		},
		Decide: func(Advisory, Record, BinaryEvidence) Tier {
			return UnknownTier(ReasonNotALibrary)
		},
	},
	// 3b-bin: rows that read ev for called and not-called symbols go here,
	// above the default, deciding Imported-like and NotImportedDirectly-like
	// tiers from the binary's symbols.
	{
		// The default (ruling (d)): the embedded release is in the
		// advisory's range and nothing more is known.
		Name: "release match",
		When: func(Advisory, Record, BinaryEvidence) bool { return true },
		Decide: func(Advisory, Record, BinaryEvidence) Tier {
			return Tier{Level: PotentiallyAffected, Source: SourceGoBuildinfo}
		},
	},
}

// matchGoArtifactRecord decides one Go record of a build artifact through
// goArtifactRules.
func matchGoArtifactRecord(adv Advisory, rec Record, ev BinaryEvidence) Tier {
	for _, rule := range goArtifactRules {
		if rule.When(adv, rec, ev) {
			return rule.Decide(adv, rec, ev)
		}
	}
	return UnknownTier(ReasonNoMapping)
}
