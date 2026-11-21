package secreach

// symbol.go is the Go symbol-level half of the tier (plan section 14.5
// item 3b, spike RG-0 "Answer"): Observer's OWN reading of a govulncheck
// result, never either route's as is. Two tables:
//
//   - symbolRules decides one (record, module) of one run: RG-0's rules 1
//     to 4, with rule 2 split so a record that lists some packages without
//     symbols may still be "called" through a listed symbol but never "not
//     called" (govulncheck treats such a package as wholly vulnerable, so
//     its init alone is a trace);
//   - applyRules combines the runs that covered a finding with its 3a tier
//     at view time: a result applies only to the binary or go.mod it
//     covered, so "not called" needs every place the finding was seen to
//     be covered and decided "not called".
//
// A symbol verdict ranks and labels only (ruling Q14-4), like the 3a tier.

// The symbol check's unknown reasons (Tier.SymbolNote, SymbolRun.Reason).
const (
	// ReasonStripped: the binary has no symbol table (or no Go line
	// table); govulncheck would read every known vulnerable symbol as
	// present, so it is never run (RG-0 G2).
	ReasonStripped Reason = "stripped_binary"
	// ReasonSymbolCheckFailed: the check ran and failed.
	ReasonSymbolCheckFailed Reason = "symbol_check_failed"
	// ReasonOutOfMemory: the check ran out of memory: not checked.
	ReasonOutOfMemory Reason = "out_of_memory"
	// ReasonTimedOut: the check passed its time limit: not checked.
	ReasonTimedOut Reason = "timed_out"
	// ReasonNoToolchain: source mode found no Go toolchain.
	ReasonNoToolchain Reason = "no_toolchain"
	// ReasonUnsupportedBinary: an executable govulncheck cannot read
	// (a universal Mach-O, WebAssembly, no Go build info).
	ReasonUnsupportedBinary Reason = "unsupported_binary_format"
	// ReasonBinaryCap: the scan named more Go binaries than one scan
	// checks; the rest were not checked.
	ReasonBinaryCap Reason = "binary_cap"
	// ReasonModuleCap: the project has more go.mod files than one source
	// check runs (3b-src); the rest were not checked.
	ReasonModuleCap Reason = "module_cap"
	// ReasonToolchainTooOld: the go.mod asks for a newer Go than the local
	// toolchain, and GOTOOLCHAIN=local never switches (3b-src).
	ReasonToolchainTooOld Reason = "toolchain_too_old"
	// ReasonModulesMissing: a module the go.mod needs is not in the module
	// cache, and GOPROXY=off never downloads it (3b-src).
	ReasonModulesMissing Reason = "modules_not_downloaded"
)

// SymbolVerdict is one record's symbol-level answer for one module in one
// run.
type SymbolVerdict string

// The verdicts.
const (
	// VerdictNone: no claim; 3a's tier stands.
	VerdictNone SymbolVerdict = ""
	// VerdictCalled: a symbol-level trace reaches a listed function.
	VerdictCalled SymbolVerdict = "called"
	// VerdictNotCalled: analysed, and no listed function is reachable.
	VerdictNotCalled SymbolVerdict = "not_called"
	// VerdictUnknown: the run could not decide (SymbolFacts.Failed says
	// why).
	VerdictUnknown SymbolVerdict = "unknown"
)

// SymbolFacts are what one run established for one (record, module).
type SymbolFacts struct {
	// Failed is set when the run failed, ran out of memory, timed out,
	// found no toolchain, or the binary is stripped.
	Failed Reason
	// ListsImports: the record's affected entry for the module lists
	// imports (packages).
	ListsImports bool
	// ListsSymbols: at least one listed package lists symbols.
	ListsSymbols bool
	// PackageWithoutSymbols: at least one listed package lists no symbols
	// (govulncheck then reads every function of it as vulnerable).
	PackageWithoutSymbols bool
	// SymbolTrace: a symbol-level trace reaches a function of a listed
	// package that lists symbols.
	SymbolTrace bool
	// Analysed: govulncheck reported the record against the module (a
	// module-level finding at least), so it read the module as affected and
	// checked it. A record govulncheck did not report proves nothing.
	Analysed bool
}

// symbolRule is one row of the per-record table: the first row whose When
// holds decides.
type symbolRule struct {
	Name    string
	When    func(SymbolFacts) bool
	Verdict SymbolVerdict
}

// symbolRules is walked top-down (one test case per row in
// symbol_test.go).
var symbolRules = []symbolRule{
	// RG-0 rule 1.
	{Name: "run failed", When: func(f SymbolFacts) bool { return f.Failed != "" }, Verdict: VerdictUnknown},
	// RG-0 rule 2: no function list, so no function-level claim (the
	// operator's NO-GO for advisories that list no functions).
	{Name: "no function list", When: func(f SymbolFacts) bool { return !f.ListsImports || !f.ListsSymbols }, Verdict: VerdictNone},
	// RG-0 rule 3.
	{Name: "symbol trace", When: func(f SymbolFacts) bool { return f.SymbolTrace }, Verdict: VerdictCalled},
	// RG-0 rule 2, second half: a listed package without symbols is
	// "every function", so the absence of a trace proves nothing.
	{Name: "package without symbols", When: func(f SymbolFacts) bool { return f.PackageWithoutSymbols }, Verdict: VerdictNone},
	// The run did not report the record against the module at all.
	{Name: "not reported", When: func(f SymbolFacts) bool { return !f.Analysed }, Verdict: VerdictNone},
	// RG-0 rule 4.
	{Name: "analysed, no trace", When: func(SymbolFacts) bool { return true }, Verdict: VerdictNotCalled},
}

// DecideSymbol is one (record, module)'s verdict through symbolRules.
func DecideSymbol(f SymbolFacts) SymbolVerdict {
	for _, r := range symbolRules {
		if r.When(f) {
			return r.Verdict
		}
	}
	return VerdictNone
}

// SymbolRecord is one stored (record, module) verdict of a run.
type SymbolRecord struct {
	ID      string        `json:"id"`
	Module  string        `json:"module"`
	Version string        `json:"version,omitempty"`
	Verdict SymbolVerdict `json:"verdict,omitempty"`
	// Symbol is the listed function a "called" trace reached
	// ("jwt.MapClaims.VerifyAudience"), "" otherwise.
	Symbol string `json:"symbol,omitempty"`
	// AssumedGo, on a source-mode (govulncheck-source) record of the
	// standard library, is the Go release the check evaluated it at: the
	// go.mod's toolchain line, else its go line, never the toolchain that
	// builds (spike RG-0 item 5). "" otherwise.
	AssumedGo string `json:"assumed_go,omitempty"`
}

// SymbolRun is one symbol check over one target: a binary (3b-bin) or a
// go.mod (3b-src).
type SymbolRun struct {
	// Source is SourceGovulncheckBinary or SourceGovulncheckSource.
	Source string `json:"source"`
	// Target is the project-relative path (forward slashes) of the binary
	// or go.mod the run covered.
	Target string `json:"target"`
	// Reason is set when the run could not decide anything (every record
	// of the target is unknown).
	Reason Reason `json:"reason,omitempty"`
	// Records are the decided (record, module) pairs.
	Records []SymbolRecord `json:"records,omitempty"`
}

// SymbolQuery is what a view knows of one dependency finding.
type SymbolQuery struct {
	// Module and Version are the finding's package (a Go module path, or
	// "stdlib") and version.
	Module, Version string
	// IDs are every advisory id of the finding (its rule id, the ids its
	// message names, the records read and their aliases).
	IDs []string
	// Paths are every project-relative path the finding was seen at (its
	// location and its sightings). PathsKnown false means only the
	// location is known: then "not called" is never claimed.
	Paths      []string
	PathsKnown bool
}

// coverage is one covered path's answer for the finding.
type coverage struct {
	verdict SymbolVerdict
	reason  Reason
	run     SymbolRun
	symbol  string
	assumed string
}

// applyFacts are what applyRules reads: every covered path's answer and
// whether every path the finding was seen at is covered.
type applyFacts struct {
	covered    []coverage
	allCovered bool
}

func (a applyFacts) first(v SymbolVerdict) (coverage, bool) {
	for _, c := range a.covered {
		if c.verdict == v {
			return c, true
		}
	}
	return coverage{}, false
}

func (a applyFacts) every(v SymbolVerdict) bool {
	if len(a.covered) == 0 {
		return false
	}
	for _, c := range a.covered {
		if c.verdict != v {
			return false
		}
	}
	return true
}

// applyRule is one row of the view-time combination table.
type applyRule struct {
	Name  string
	When  func(applyFacts) bool
	Apply func(base Tier, a applyFacts) Tier
}

// applyRules is walked top-down (one test case per row in symbol_test.go).
var applyRules = []applyRule{
	{
		// A listed function is reachable in one covered build: called,
		// whatever the other paths say.
		Name: "called somewhere covered",
		When: func(a applyFacts) bool { _, ok := a.first(VerdictCalled); return ok },
		Apply: func(_ Tier, a applyFacts) Tier {
			c, _ := a.first(VerdictCalled)
			return Tier{Level: Called, Source: c.run.Source, Target: c.run.Target, Match: c.symbol, AssumedGo: c.assumed}
		},
	},
	{
		// Every place the finding was seen was checked and none reaches a
		// listed function.
		Name: "not called everywhere it was seen",
		When: func(a applyFacts) bool { return a.allCovered && a.every(VerdictNotCalled) },
		Apply: func(_ Tier, a applyFacts) Tier {
			c := a.covered[0]
			return Tier{Level: NotCalled, Source: c.run.Source, Target: c.run.Target, AssumedGo: c.assumed}
		},
	},
	{
		// A binary's version-only match (PotentiallyAffected) on a stripped
		// binary stays unknown (operator ruling 2026-11-05, item 4 Go stdlib
		// (d)): without symbols nothing says whether the affected code is in
		// it, and the version alone is already all the label carries.
		Name: "stripped binary keeps a version match unknown",
		When: func(a applyFacts) bool {
			c, ok := a.first(VerdictUnknown)
			return ok && c.reason == ReasonStripped
		},
		Apply: func(base Tier, a applyFacts) Tier {
			if base.Level != PotentiallyAffected {
				c, _ := a.first(VerdictUnknown)
				base.SymbolNote = c.reason
				return base
			}
			return UnknownTier(ReasonStripped)
		},
	},
	{
		// A covering run could not decide: 3a's tier stands, with why.
		Name: "a covering check could not decide",
		When: func(a applyFacts) bool { _, ok := a.first(VerdictUnknown); return ok },
		Apply: func(base Tier, a applyFacts) Tier {
			c, _ := a.first(VerdictUnknown)
			base.SymbolNote = c.reason
			return base
		},
	},
	{
		// No claim (no function list, a path not covered, nothing run).
		Name:  "no claim",
		When:  func(applyFacts) bool { return true },
		Apply: func(base Tier, _ applyFacts) Tier { return base },
	},
}

// ApplySymbol combines a finding's 3a tier with the symbol checks that
// covered it: a run covers the finding when its target is one of the
// finding's paths. Within a run the finding's records answer by id, module
// and version (called over not called; no record of it, no claim); a run
// that could not decide answers unknown with its reason. The combination
// is applyRules. Nothing is closed or hidden.
func ApplySymbol(base Tier, q SymbolQuery, runs []SymbolRun) Tier {
	if len(runs) == 0 || q.Module == "" {
		return base
	}
	ids := make(map[string]bool, len(q.IDs))
	for _, id := range q.IDs {
		ids[id] = true
	}
	paths := q.Paths
	a := applyFacts{allCovered: q.PathsKnown && len(paths) > 0}
	for _, p := range paths {
		found := false
		for _, r := range runs {
			if r.Target != p {
				continue
			}
			found = true
			a.covered = append(a.covered, answerOf(r, q, ids))
		}
		if !found {
			a.allCovered = false
		}
	}
	for _, rule := range applyRules {
		if rule.When(a) {
			return rule.Apply(base, a)
		}
	}
	return base
}

// answerOf is one run's answer for the finding.
func answerOf(r SymbolRun, q SymbolQuery, ids map[string]bool) coverage {
	if r.Reason != "" {
		return coverage{verdict: VerdictUnknown, reason: r.Reason, run: r}
	}
	out := coverage{verdict: VerdictNone, run: r}
	for _, rec := range r.Records {
		if !ids[rec.ID] || rec.Module != q.Module || (q.Version != "" && rec.Version != "" && rec.Version != q.Version) {
			continue
		}
		switch rec.Verdict {
		case VerdictCalled:
			return coverage{verdict: VerdictCalled, run: r, symbol: rec.Symbol, assumed: rec.AssumedGo}
		case VerdictNotCalled:
			out.verdict, out.assumed = VerdictNotCalled, rec.AssumedGo
		}
	}
	return out
}
