package depscan

import (
	"path"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/secscan/gitmodules"
)

// submodules.go is the pure half of the online git submodule check (spike
// CPP-0, docs/plans/spikes/CPP-0-online-cpp-deps-2026-11.md): what a
// submodule pin is as an inventory row, how the check's answer folds into
// a response (ApplySubmodules), and which dependency files online matching
// can check (OnlineCovers, for the gap probe). The I/O (reading the pins,
// the query to api.osv.dev) is cmd/observer security_scan_submodules.go.

// SubmoduleEcosystem is the ecosystem of a submodule pin: OSV's GIT, matched
// online by the pinned commit id only. It has no row in the ecosystems
// table on purpose: that table is what the database store downloads, and
// the GIT export is never downloaded (operator ruling 2026-11-06).
const SubmoduleEcosystem = "GIT"

// SubmoduleExtractor is the Extractor of a submodule pin's inventory row.
const SubmoduleExtractor = "observer/gitmodules"

// SubmoduleCanary is the online submodule check's self-test: zlib v1.2.11's
// release commit, a public commit OSV answers with CVE-2018-25032 (spike
// CPP-0 (a), 2026-11-06). It is queried first; a check whose canary does
// not answer sends no project commit.
var SubmoduleCanary = Canary{Name: "zlib", Version: "cacf7f1d4e3d44d871b605da3b647f07d718623f", Advisory: "CVE-2018-25032"}

// The submodule check's gap reasons.
const (
	// ReasonSubmodulePinsUnreadable: a .gitmodules file, or the gitlinks
	// of its directory, could not be read (git missing or refused, not a
	// work tree, a file over the cap, too many submodules, or a gitlink
	// whose id OSV cannot match, such as a SHA-256 repository's).
	ReasonSubmodulePinsUnreadable = "submodule_pins_unreadable"
	// ReasonSubmoduleCheckFailed: the online query of a pinned commit
	// failed (the service unreachable, rate limited, a bad answer, the
	// self-test not answering), so that submodule was not checked.
	ReasonSubmoduleCheckFailed = "submodule_check_failed"
)

// The plain words of the two reasons. They are added to the gap words
// table (gaps.go) here so that file stays the gap probe's alone; fold
// them into its literal when the two lanes meet.
// onlineOnlyEcosystems are the ecosystems matched only online, with their
// finding noun and fix hint. They are never downloaded and have no canary
// in the ecosystems table.
var onlineOnlyEcosystems = map[string]ecosystemRow{
	SubmoduleEcosystem: {
		Noun:    "git submodule",
		FixHint: "Move the submodule to a commit the advisory lists as fixed (check out a fixed release inside it), then commit the new pin in the superproject.",
	},
}

// ecosystemRowOf returns an ecosystem's row from the downloaded table or the
// online-only one.
func ecosystemRowOf(eco string) (ecosystemRow, bool) {
	if r, ok := ecosystems[eco]; ok {
		return r, true
	}
	r, ok := onlineOnlyEcosystems[eco]
	return r, ok
}

// OnlineCovers reports whether online matching (`observer security scan
// --online` with its gate open) can check the dependency file at rel
// itself (relative to the project root, forward slashes): a .gitmodules
// file, whose submodules are checked by their pinned commits. The gap
// probe uses it to word a file's gap ("needs the online check") and
// ApplySubmodules to drop the gap of a file the check covered in full.
// Conan and vcpkg files are not covered: OSV has no data for them and no
// reliable mapping to an upstream release exists (spike CPP-0 (c)).
func OnlineCovers(rel string) bool {
	return path.Base(rel) == gitmodules.FileName
}

// SubmodulePin is one checked submodule: its path relative to the project
// root (the finding's location), its local name (never sent), the commit
// the superproject pins and the advisories OSV returned for that commit
// (Index unset; ApplySubmodules sets it).
type SubmodulePin struct {
	Path       string
	Name       string
	Commit     string
	Advisories []Advisory
}

// SubmoduleCheck is the online submodule check's answer for one project.
type SubmoduleCheck struct {
	// Covered are the .gitmodules files (relative to the root, forward
	// slashes) whose every pin was checked: their gaps are dropped.
	Covered []string
	// Pins are the submodules whose commit was checked.
	Pins []SubmodulePin
	// Unchecked are the files whose pins could not all be read or checked
	// (Reason, and Packages the number not checked): each becomes a gap of
	// the GIT ecosystem.
	Unchecked []Gap
	// Ran reports that the check queried the service (there was a pin to
	// check); false adds no ecosystem result.
	Ran bool
	// MatchError: the self-test query failed. CanaryHit: it answered with
	// the canary's advisory.
	MatchError bool
	CanaryHit  bool
	// Epoch is the ecosystem result's epoch ("online:<host> <time>").
	Epoch string
}

// ApplySubmodules folds the check into a response, before Finalize: each
// checked pin becomes a GIT inventory row (Name the local name, Version
// the commit, Path the submodule path) with its advisories, the GIT
// ecosystem gets its result (DecideEcosystem: the self-test must have
// answered), the gaps of the covered .gitmodules files are dropped
// (whatever the gap probe called them), and the unchecked files are gaps.
// A check whose self-test did not answer drops no gap and adds no row.
func ApplySubmodules(resp ChildResponse, c SubmoduleCheck) ChildResponse {
	out := resp
	outcome, reason := DecideEcosystem(MatchFacts{DatabaseInstalled: true, HasCanary: true, MatchError: c.MatchError, CanaryHit: c.CanaryHit})
	if !c.Ran {
		// Nothing was to be checked: the files read (no pins, or only
		// stale declarations) are covered without a query.
		outcome, reason = EcoScanned, ""
	}
	covered := map[string]bool{}
	if outcome == EcoScanned {
		for _, f := range c.Covered {
			covered[f] = true
		}
	}
	gaps := make([]Gap, 0, len(resp.Gaps)+len(c.Unchecked))
	for _, g := range resp.Gaps {
		if covered[g.Path] && OnlineCovers(g.Path) {
			continue
		}
		gaps = append(gaps, g)
	}
	for _, g := range c.Unchecked {
		g.Ecosystem = SubmoduleEcosystem
		gaps = append(gaps, g)
	}
	out.Gaps = gaps
	if !c.Ran {
		return out
	}
	eco := EcoResult{Ecosystem: SubmoduleEcosystem, Outcome: outcome, Reason: reason}
	if outcome == EcoScanned {
		out.Packages = append([]Package(nil), resp.Packages...)
		eco.Epoch = c.Epoch
		pins := append([]SubmodulePin(nil), c.Pins...)
		sort.SliceStable(pins, func(i, j int) bool { return pins[i].Path < pins[j].Path })
		for _, p := range pins {
			idx := len(out.Packages)
			out.Packages = append(out.Packages, Package{Ecosystem: SubmoduleEcosystem, Name: p.Name, Version: p.Commit, Path: p.Path, Extractor: SubmoduleExtractor})
			for _, a := range p.Advisories {
				a.Index = idx
				eco.Advisories = append(eco.Advisories, a)
			}
		}
		eco.Packages = len(pins)
	}
	ecos := make([]EcoResult, 0, len(resp.Ecosystems)+1)
	for _, e := range resp.Ecosystems {
		if e.Ecosystem != SubmoduleEcosystem {
			ecos = append(ecos, e)
		}
	}
	ecos = append(ecos, eco)
	out.Ecosystems = ecos
	return out
}
