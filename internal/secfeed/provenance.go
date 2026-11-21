package secfeed

import "github.com/marmutapp/superbased-observer/internal/policy"

// VersionProvenance is one published version's provenance fact.
type VersionProvenance struct {
	// Version is the version as the registry names it.
	Version string
	// Has reports that the version was published with build provenance
	// (npm provenance, a PyPI attestation on any of its files).
	Has bool
	// Order is the registry's own ordering of the version, assigned by
	// the reader: lower is earlier (npm by semver, PyPI by first upload).
	// Observer writes no version comparator of its own.
	Order int
}

// ProvenanceFacts is what a registry reader extracts for one install: the
// target version and every published version's provenance fact.
type ProvenanceFacts struct {
	// Target is the version the install resolves to: the pinned version,
	// else the registry's own latest ("" when the reader could not say).
	Target string
	// Versions are the registry's published versions (any order).
	Versions []VersionProvenance
}

// provenanceRow is one row of the provenance table.
type provenanceRow struct {
	name  string
	when  func(f ProvenanceFacts, target VersionProvenance, found bool) bool
	state policy.InstallProvenance
}

// provenanceTable is THE provenance decision, walked top-down; the first
// row that matches decides (plan 2026-11-13 section 4):
//
//   - no facts, or the target is not among the published versions: the
//     registry answer cannot say (unknown);
//   - the target carries provenance: present;
//   - a version the registry orders before the target carried it while
//     the target does not: regressed (the S-757 signal);
//   - else no earlier version ever carried it: absent (normal for most
//     packages, never flagged).
var provenanceTable = []provenanceRow{
	{"no_facts", func(f ProvenanceFacts, _ VersionProvenance, found bool) bool {
		return len(f.Versions) == 0 || f.Target == "" || !found
	}, policy.InstallProvenanceUnknown},
	{"present", func(_ ProvenanceFacts, t VersionProvenance, _ bool) bool { return t.Has }, policy.InstallProvenancePresent},
	{"regressed", func(f ProvenanceFacts, t VersionProvenance, _ bool) bool {
		for _, v := range f.Versions {
			if v.Has && v.Order < t.Order {
				return true
			}
		}
		return false
	}, policy.InstallProvenanceRegressed},
	{"absent", func(ProvenanceFacts, VersionProvenance, bool) bool { return true }, policy.InstallProvenanceAbsent},
}

// DecideProvenance returns the provenance state of an install from the
// registry's per-version facts. It is orthogonal to the verdict: it never
// raises, lowers or replaces one.
func DecideProvenance(f ProvenanceFacts) policy.InstallProvenance {
	var target VersionProvenance
	found := false
	for _, v := range f.Versions {
		if f.Target != "" && v.Version == f.Target {
			target, found = v, true
			break
		}
	}
	for _, r := range provenanceTable {
		if r.when(f, target, found) {
			return r.state
		}
	}
	return policy.InstallProvenanceUnknown
}
