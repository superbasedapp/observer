package seccustom

import "slices"

// OrgMode is the org's rule for custom drivers on a managed node (section
// 8.6 "Org control"). The policy itself arrives on the enforce.security
// pull (security Phase E builds the server half and the delivery); this is
// the node half: the decision over a delivered policy.
type OrgMode string

// The OrgMode values.
const (
	// OrgModeUnset: the org says nothing; local manifests run flag-only.
	OrgModeUnset OrgMode = ""
	// OrgModeCatalogOnly: only manifests from the org's catalog run.
	OrgModeCatalogOnly OrgMode = "catalog_only"
	// OrgModeRequire: catalog only, and every catalog entry must be
	// present and running (a missing one is reported).
	OrgModeRequire OrgMode = "require"
	// OrgModeForbid: no custom driver runs.
	OrgModeForbid OrgMode = "forbid"
)

// OrgBlockingRule is one catalog rule that may count toward S-791, with
// the precision figure PR7 requires.
type OrgBlockingRule struct {
	RuleID    string  `json:"rule_id"`
	Precision float64 `json:"precision"`
}

// OrgEntry is one pre-approved manifest, pinned by its manifest digest and
// its executable digest (added by a super-admin under four-eyes on the org
// server). The org never sends an executable or arguments.
type OrgEntry struct {
	ManifestSHA256   string            `json:"manifest_sha256"`
	ExecutableSHA256 string            `json:"executable_sha256"`
	BlockingRules    []OrgBlockingRule `json:"blocking_rules,omitempty"`
}

// OrgPolicy is the delivered org policy for custom drivers.
type OrgPolicy struct {
	Mode    OrgMode    `json:"mode"`
	Entries []OrgEntry `json:"entries,omitempty"`
}

// OrgFacts are the node facts the decision reads.
type OrgFacts struct {
	// Managed: the node is managed and holds the enforce.security
	// authority (resolved at the boundary).
	Managed bool
	// Isolated: this run is held by the isolation component's no-network
	// one-shot.
	Isolated bool
}

// OrgDecision is whether a record may run here, whether it is the org's,
// which of its rules may count toward blocking, and the label to show.
type OrgDecision struct {
	Run    bool
	Reason string
	// OrgApproved: the record matches a catalog entry.
	OrgApproved bool
	// Blocking are the rule ids that may count toward blocking on this run.
	Blocking []string
	// NotIsolated is shown as "not isolated" on the Scanners tab.
	NotIsolated bool
}

// BlockingRule reports whether rule may count toward blocking.
func (d OrgDecision) BlockingRule(rule string) bool { return slices.Contains(d.Blocking, rule) }

// orgRow is one row of the org decision table.
type orgRow struct {
	when func(p OrgPolicy, f OrgFacts, entry *OrgEntry) bool
	run  bool
	why  string
}

// orgTable is walked top-down. An individual node takes no remote raise or
// restriction; a managed node follows its org's mode.
var orgTable = []orgRow{
	{func(_ OrgPolicy, f OrgFacts, _ *OrgEntry) bool { return !f.Managed }, true, ""},
	{func(p OrgPolicy, _ OrgFacts, _ *OrgEntry) bool { return p.Mode == OrgModeForbid }, false, "org_forbids_custom_drivers"},
	{func(p OrgPolicy, _ OrgFacts, e *OrgEntry) bool {
		return (p.Mode == OrgModeCatalogOnly || p.Mode == OrgModeRequire) && e == nil
	}, false, "not_in_org_catalog"},
	{func(OrgPolicy, OrgFacts, *OrgEntry) bool { return true }, true, ""},
}

// DecideOrg applies the org policy to one record. Blocking needs all of:
// a managed node, a catalog entry naming the rule with a precision figure,
// and an isolated run (revision 2.3, D7: a custom scanner that cannot run
// isolated on a managed node is flag-only whatever its manifest says).
func DecideOrg(p OrgPolicy, f OrgFacts, rec Record) OrgDecision {
	var entry *OrgEntry
	for i, e := range p.Entries {
		if e.ManifestSHA256 == rec.ManifestSHA256 && e.ExecutableSHA256 == rec.Manifest.ExecutableSHA256 {
			entry = &p.Entries[i]
			break
		}
	}
	d := OrgDecision{NotIsolated: !f.Isolated}
	for _, r := range orgTable {
		if r.when(p, f, entry) {
			d.Run, d.Reason = r.run, r.why
			break
		}
	}
	if !d.Run || !f.Managed || entry == nil {
		return d
	}
	d.OrgApproved = true
	if !f.Isolated {
		return d
	}
	for _, br := range entry.BlockingRules {
		if br.Precision > 0 && br.Precision <= 1 && slices.Contains(rec.Manifest.BlockingRules, br.RuleID) {
			d.Blocking = append(d.Blocking, br.RuleID)
		}
	}
	return d
}

// RequiredMissing lists the catalog entries a require-mode policy names
// that no accepted record matches (by manifest digest).
func RequiredMissing(p OrgPolicy, f OrgFacts, recs []Record) []string {
	if !f.Managed || p.Mode != OrgModeRequire {
		return nil
	}
	var out []string
	for _, e := range p.Entries {
		found := false
		for _, r := range recs {
			found = found || (r.ManifestSHA256 == e.ManifestSHA256 && r.Manifest.ExecutableSHA256 == e.ExecutableSHA256)
		}
		if !found {
			out = append(out, e.ManifestSHA256)
		}
	}
	return out
}
