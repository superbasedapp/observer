package orgcontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
)

// securitypolicy.go is the closed body of the security module's managed pull
// (GET /api/agent/security, domain sbo-security-managed-v1, authority
// enforce.security; security plan 4.9 and 6.5, lane SEC-E milestone 3). The
// envelope, signature, version and expiry are the managed-pull kit's
// (managedpull.go); this file only says what the body may carry.
//
// What it may never carry, each pinned by a refusal test:
//   - a credential, an executable path or program arguments: the decoder is
//     closed (unknown fields refused) and every value is an enum, a
//     vocabulary id or a sha256 digest, so there is no field a path, a
//     token or an argument could ride in;
//   - git hooks: security.githooks is not a component this body may
//     switch on (PR11 holds on managed nodes too; the org can require the
//     CI check instead);
//   - the online check before the one-time disclosure: the body may ask
//     for it, but the node applies OnlineChecks "on" only once the plan 8.3
//     disclosure was shown on that node (the node consumer's rule, pinned
//     there).

// SecurityManagedPolicyVersion is the only body version this build reads.
const SecurityManagedPolicyVersion = 1

// SecurityManagedPolicyV1 is the security managed-pull body. Every field is
// optional; the empty body "{}" is the kit's signed "none".
type SecurityManagedPolicyV1 struct {
	// Version is SecurityManagedPolicyVersion.
	Version int `json:"version"`
	// Components are the security child components to switch on.
	Components []string `json:"components,omitempty"`
	// Drivers are the scanner drivers to switch on (each switches its own
	// component on).
	Drivers []string `json:"drivers,omitempty"`
	// ScannerSource is where scanner databases come from; org_mirror only.
	ScannerSource string `json:"scanner_source,omitempty"`
	// ScanSchedule is when background scans run.
	ScanSchedule string `json:"scan_schedule,omitempty"`
	// OrgDedupeKey names the org's finding dedupe key (security plan
	// 4.5.1). It is an identifier, never key material.
	OrgDedupeKey string `json:"org_dedupe_key,omitempty"`
	// CustomManifests are pre-approved custom driver manifests to switch on
	// (security plan 8.6), by digest only.
	CustomManifests []string `json:"custom_manifests,omitempty"`
	// CustomMode is the org's rule for custom drivers on a managed node
	// (security plan 8.6 "Org control", lane SEC-E4): catalog_only (only
	// catalog manifests run), require (catalog only, and every named one
	// must be present) or forbid (none runs). Empty with CustomManifests
	// named means require.
	CustomMode string `json:"custom_mode,omitempty"`
	// CustomCatalog is NEVER authored: the org server fills it at serve
	// time from its four-eyes catalog (internal/orgserver/secmanifests), one
	// entry per CustomManifests digest that a super admin added and a
	// different admin approved, each pinned by manifest and executable
	// digest. A named digest with no entry here is not approved and a node
	// refuses it (not_in_org_catalog).
	CustomCatalog []SecurityCustomCatalogEntry `json:"custom_catalog,omitempty"`
	// OnlineChecks switches the online package checks on or off.
	OnlineChecks string `json:"online_checks,omitempty"`
	// FindingShare is the org_client.share level for findings.
	FindingShare string `json:"finding_share,omitempty"`
	// Feedback switches feedback to the agent after writes.
	Feedback string `json:"feedback,omitempty"`
	// AIChangeRecord is where the AI change record goes.
	AIChangeRecord string `json:"ai_change_record,omitempty"`
	// PackageLookup is the org's package lookup posture for its managed
	// nodes (OS and CI vulnerability scanning plan sections 13.5 and 13.10,
	// lane RM-3): "off" (the default, also when absent: no managed node
	// looks a package up anywhere) or "org_mirror" (each managed node looks
	// the ecosystems its local databases do not cover up in the advisory
	// shards the org server mirrors, sending the org server only the
	// content-addressed digests of the shards its packages' hash prefixes
	// fall in; it never contacts SuperBased's shard host). The org decides:
	// there is no node-side switch on a managed node.
	PackageLookup string `json:"package_lookup,omitempty"`
	// PackageLookupPrivate is whether names the node cannot place as public
	// are looked up too: "withhold" (the default, also when absent) or
	// "send".
	PackageLookupPrivate string `json:"package_lookup_private,omitempty"`
	// PackageLookupKinds are the package kinds the lookup covers
	// (SecurityManagedLookupKinds); absent means every kind this build
	// looks up.
	PackageLookupKinds []string `json:"package_lookup_kinds,omitempty"`
	// Defaults are the managed DEFAULTS of the local experience settings
	// (the U rows of plan 6.5): the developer may change each one locally.
	Defaults *SecurityManagedDefaults `json:"defaults,omitempty"`
	// ApprovedBaselines and OrgDedupe are NEVER authored: the org server
	// fills them at serve time for the calling node only, and only when
	// the node advertised the capability (securitypull_served.go, lane
	// LEFT-SHARED).
	ApprovedBaselines []SecurityBaselineApproval `json:"approved_baselines,omitempty"`
	OrgDedupe         *SecurityOrgDedupe         `json:"org_dedupe,omitempty"`
}

// SecurityCustomCatalogEntry is one approved custom driver manifest.
type SecurityCustomCatalogEntry struct {
	ManifestSHA256   string                       `json:"manifest_sha256"`
	ExecutableSHA256 string                       `json:"executable_sha256"`
	BlockingRules    []SecurityCustomBlockingRule `json:"blocking_rules,omitempty"`
}

// SecurityCustomBlockingRule is a catalog rule that may count toward S-791,
// with its precision figure (PR7).
type SecurityCustomBlockingRule struct {
	RuleID    string  `json:"rule_id"`
	Precision float64 `json:"precision"`
}

// SecurityManagedDefaults are the U-row defaults.
type SecurityManagedDefaults struct {
	CPUPriority       string `json:"cpu_priority,omitempty"`
	PauseOnBattery    *bool  `json:"pause_on_battery,omitempty"`
	StatuslineSegment *bool  `json:"statusline_segment,omitempty"`
	MCPTools          *bool  `json:"mcp_tools,omitempty"`
	NotifyCritical    *bool  `json:"notify_critical,omitempty"`
}

// The closed vocabularies. Component ids are spelled here (orgcontract
// imports nothing of the node's policy layer); a test pins them to the
// security.scanning family's child table.
var (
	SecurityManagedComponents = []string{
		"security.trust", "security.secrets", "security.code", "security.deps",
		"security.scan.custom", "security.scan.scalibr", "security.scan.osv",
		"security.scan.opengrep", "security.scan.sarif-import", "security.scan.actionlint",
		"security.scan.trivy", "security.scan.kics",
	}
	SecurityManagedDrivers        = []string{"scalibr", "osv", "opengrep", "actionlint", "trivy", "kics"}
	SecurityManagedScannerSources = []string{"org_mirror"}
	SecurityManagedSchedules      = []string{"on_change", "hourly", "daily", "manual"}
	SecurityManagedOnOff          = []string{"on", "off"}
	SecurityManagedFindingShares  = []string{"off", "posture", "findings"}
	SecurityManagedChangeRecords  = []string{"off", "local", "org"}
	SecurityManagedCPUPriorities  = []string{"low", "normal"}
	SecurityManagedCustomModes    = []string{"catalog_only", "require", "forbid"}
	// SecurityManagedPackageLookups are package_lookup's values (lane RM-3).
	SecurityManagedPackageLookups = []string{"off", "org_mirror"}
	// SecurityManagedLookupPrivate are package_lookup_private's values.
	SecurityManagedLookupPrivate = []string{"withhold", "send"}
	// SecurityManagedLookupKinds are package_lookup_kinds' values: the
	// node's [security.deps] remote_kinds this build looks up.
	SecurityManagedLookupKinds = []string{"language", "actions"}
)

// SecurityPackageLookupOrgMirror is package_lookup's one enabling value.
const SecurityPackageLookupOrgMirror = "org_mirror"

var (
	securityDedupeKeyRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	securityManifestRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	securityRuleIDRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
)

// maxSecurityManagedBytes bounds the body.
const maxSecurityManagedBytes = 32 << 10

// ErrSecurityManagedPolicy is a body this build refuses.
var ErrSecurityManagedPolicy = errors.New("orgcontract: security managed policy refused")

// DecodeSecurityManagedPolicy parses and validates a body strictly. The
// kit's empty "none" ({} or null) decodes to the zero value with ok=false.
func DecodeSecurityManagedPolicy(raw []byte) (p SecurityManagedPolicyV1, ok bool, err error) {
	if ManagedPullBodyIsEmpty(raw) {
		return SecurityManagedPolicyV1{}, false, nil
	}
	if len(raw) > maxSecurityManagedBytes {
		return p, false, fmt.Errorf("%w: body is %d bytes, max %d", ErrSecurityManagedPolicy, len(raw), maxSecurityManagedBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return SecurityManagedPolicyV1{}, false, fmt.Errorf("%w: %w", ErrSecurityManagedPolicy, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return SecurityManagedPolicyV1{}, false, fmt.Errorf("%w: trailing data", ErrSecurityManagedPolicy)
	}
	if err := ValidateSecurityManagedPolicy(p); err != nil {
		return SecurityManagedPolicyV1{}, false, err
	}
	return p, true, nil
}

// ValidateSecurityManagedPolicy checks every field against its vocabulary.
func ValidateSecurityManagedPolicy(p SecurityManagedPolicyV1) error {
	bad := func(field, v string, want []string) error {
		return fmt.Errorf("%w: %s %q (want one of %v)", ErrSecurityManagedPolicy, field, v, want)
	}
	if p.Version != SecurityManagedPolicyVersion {
		return fmt.Errorf("%w: version %d (want %d)", ErrSecurityManagedPolicy, p.Version, SecurityManagedPolicyVersion)
	}
	lists := []struct {
		field string
		v     []string
		ok    func(string) bool
		want  []string
	}{
		{"components", p.Components, func(s string) bool { return slices.Contains(SecurityManagedComponents, s) }, SecurityManagedComponents},
		{"drivers", p.Drivers, func(s string) bool { return slices.Contains(SecurityManagedDrivers, s) }, SecurityManagedDrivers},
		{"custom_manifests", p.CustomManifests, securityManifestRe.MatchString, []string{"sha256:<64 hex>"}},
		{"package_lookup_kinds", p.PackageLookupKinds, func(s string) bool { return slices.Contains(SecurityManagedLookupKinds, s) }, SecurityManagedLookupKinds},
	}
	for _, l := range lists {
		if l.v != nil && len(l.v) == 0 {
			return fmt.Errorf("%w: %s is present but empty; leave it out instead", ErrSecurityManagedPolicy, l.field)
		}
		if len(l.v) > 64 {
			return fmt.Errorf("%w: %s has %d entries, max 64", ErrSecurityManagedPolicy, l.field, len(l.v))
		}
		for _, s := range l.v {
			if !l.ok(s) {
				return bad(l.field, s, l.want)
			}
		}
	}
	enums := []struct {
		field, v string
		want     []string
	}{
		{"scanner_source", p.ScannerSource, SecurityManagedScannerSources},
		{"scan_schedule", p.ScanSchedule, SecurityManagedSchedules},
		{"online_checks", p.OnlineChecks, SecurityManagedOnOff},
		{"finding_share", p.FindingShare, SecurityManagedFindingShares},
		{"feedback", p.Feedback, SecurityManagedOnOff},
		{"ai_change_record", p.AIChangeRecord, SecurityManagedChangeRecords},
		{"custom_mode", p.CustomMode, SecurityManagedCustomModes},
		{"package_lookup", p.PackageLookup, SecurityManagedPackageLookups},
		{"package_lookup_private", p.PackageLookupPrivate, SecurityManagedLookupPrivate},
	}
	if p.Defaults != nil {
		enums = append(enums, struct {
			field, v string
			want     []string
		}{"defaults.cpu_priority", p.Defaults.CPUPriority, SecurityManagedCPUPriorities})
	}
	for _, e := range enums {
		if e.v != "" && !slices.Contains(e.want, e.v) {
			return bad(e.field, e.v, e.want)
		}
	}
	if err := validateSecurityCustomCatalog(p); err != nil {
		return err
	}
	if err := validateSecurityServed(p); err != nil {
		return err
	}
	if p.OrgDedupeKey != "" && !securityDedupeKeyRe.MatchString(p.OrgDedupeKey) {
		return fmt.Errorf("%w: org_dedupe_key must be an identifier (letters, digits, dot, dash, underscore, at most 64)", ErrSecurityManagedPolicy)
	}
	return nil
}

// validateSecurityCustomCatalog checks the served catalog: at most 64
// entries, both digests in the sha256:<hex> form, each entry's manifest
// named in custom_manifests (the catalog only ever expands what is named),
// no duplicate, and every blocking rule an identifier with a precision in
// (0, 1].
func validateSecurityCustomCatalog(p SecurityManagedPolicyV1) error {
	if p.CustomCatalog != nil && len(p.CustomCatalog) == 0 {
		return fmt.Errorf("%w: custom_catalog is present but empty; leave it out instead", ErrSecurityManagedPolicy)
	}
	if len(p.CustomCatalog) > 64 {
		return fmt.Errorf("%w: custom_catalog has %d entries, max 64", ErrSecurityManagedPolicy, len(p.CustomCatalog))
	}
	seen := map[string]bool{}
	for _, e := range p.CustomCatalog {
		if !securityManifestRe.MatchString(e.ManifestSHA256) || !securityManifestRe.MatchString(e.ExecutableSHA256) {
			return fmt.Errorf("%w: custom_catalog digests must be sha256:<64 hex>", ErrSecurityManagedPolicy)
		}
		if !slices.Contains(p.CustomManifests, e.ManifestSHA256) || seen[e.ManifestSHA256] {
			return fmt.Errorf("%w: custom_catalog entry %s is not named once in custom_manifests", ErrSecurityManagedPolicy, e.ManifestSHA256)
		}
		seen[e.ManifestSHA256] = true
		if len(e.BlockingRules) > 64 {
			return fmt.Errorf("%w: custom_catalog entry has %d blocking rules, max 64", ErrSecurityManagedPolicy, len(e.BlockingRules))
		}
		for _, r := range e.BlockingRules {
			if !securityRuleIDRe.MatchString(r.RuleID) || !(r.Precision > 0 && r.Precision <= 1) {
				return fmt.Errorf("%w: custom_catalog blocking rule %q needs an identifier and a precision in (0, 1]", ErrSecurityManagedPolicy, r.RuleID)
			}
		}
	}
	return nil
}

// CanonicalSecurityManagedPolicy validates p and returns its canonical bytes
// (lists sorted and deduplicated), the body the server signs.
func CanonicalSecurityManagedPolicy(p SecurityManagedPolicyV1) ([]byte, error) {
	if err := ValidateSecurityManagedPolicy(p); err != nil {
		return nil, err
	}
	p.Components = securitySortedUniq(p.Components)
	p.Drivers = securitySortedUniq(p.Drivers)
	p.CustomManifests = securitySortedUniq(p.CustomManifests)
	p.PackageLookupKinds = securitySortedUniq(p.PackageLookupKinds)
	if p.CustomCatalog != nil {
		p.CustomCatalog = append([]SecurityCustomCatalogEntry(nil), p.CustomCatalog...)
		sort.Slice(p.CustomCatalog, func(i, j int) bool { return p.CustomCatalog[i].ManifestSHA256 < p.CustomCatalog[j].ManifestSHA256 })
	}
	canonicalSecurityServed(&p)
	return json.Marshal(p)
}

// SecurityManagedPolicyEnables reports whether p switches on a part that
// starts a program or reaches the network (any component, driver or custom
// manifest, or the online checks): writing such a body needs the org's
// super admin (security plan 7.2). The reasons are sorted.
func SecurityManagedPolicyEnables(p SecurityManagedPolicyV1) []string {
	var why []string
	for _, c := range p.Components {
		why = append(why, "switches on "+c)
	}
	for _, d := range p.Drivers {
		why = append(why, "switches on the "+d+" driver")
	}
	if len(p.CustomManifests) > 0 {
		why = append(why, "switches on a custom driver manifest")
	}
	if p.OnlineChecks == "on" {
		why = append(why, "switches on the online package checks")
	}
	if p.PackageLookup == SecurityPackageLookupOrgMirror {
		why = append(why, "switches on the package lookup through the org mirror")
		if p.PackageLookupPrivate == "send" {
			why = append(why, "looks private package names up too")
		}
	}
	sort.Strings(why)
	return why
}

// SecurityPackageLookupOn reports whether p turns the managed package
// lookup on (package_lookup = org_mirror).
func SecurityPackageLookupOn(p *SecurityManagedPolicyV1) bool {
	return p != nil && p.PackageLookup == SecurityPackageLookupOrgMirror
}

// securityHasPackageLookup reports whether p carries any package lookup
// field (the fields an older node does not know).
func securityHasPackageLookup(p SecurityManagedPolicyV1) bool {
	return p.PackageLookup != "" || p.PackageLookupPrivate != "" || p.PackageLookupKinds != nil
}

func securitySortedUniq(v []string) []string {
	if v == nil {
		return nil
	}
	out := append([]string(nil), v...)
	sort.Strings(out)
	return slices.Compact(out)
}
