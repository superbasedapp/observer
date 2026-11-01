package securityscanning

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/postureop"
)

// Body is the org-wire JSON shape of a security.scanning body (security
// plan 4.9). Every field is optional: an absent key sets no floor. A list
// present but empty is refused (it would allow nothing, never "any").
type Body struct {
	// Version is the body schema version; 0 reads as BodyVersion.
	Version int `json:"version,omitempty"`
	// Require holds the floors; each key raises only.
	Require *Require `json:"require,omitempty"`
	// Allow holds the allow-sets; each is intersected with the node's own.
	Allow *Allow `json:"allow,omitempty"`
	// RulePack holds the rule-pack floor.
	RulePack *RulePack `json:"rule_pack,omitempty"`
	// Sections are the per-child sections, keyed by child id ("deps").
	Sections map[string]Section `json:"sections,omitempty"`
}

// Require is the [require] table.
type Require struct {
	Components           []string `json:"components,omitempty"`
	PrelaunchTrust       string   `json:"prelaunch_trust,omitempty"`
	CommitGate           string   `json:"commit_gate,omitempty"`
	QuickScanBudgetS     *int64   `json:"quick_scan_budget_s,omitempty"`
	MaxScanStalenessMin  *int64   `json:"max_scan_staleness_min,omitempty"`
	MaxAdvisoryDBAgeH    *int64   `json:"max_advisory_db_age_h,omitempty"`
	MinBlockingSeverity  string   `json:"min_blocking_severity,omitempty"`
	InstallUnknown       string   `json:"install_unknown,omitempty"`
	OnlineChecks         string   `json:"online_checks,omitempty"`
	InstallOnlineUnknown string   `json:"install_online_unknown,omitempty"`
	HistoryScanOnEnrol   *bool    `json:"history_scan_on_enrol,omitempty"`
	// FindingRetentionDays is a retention floor; 0 means keep forever, the
	// maximum (postureop.RetentionCmp).
	FindingRetentionDays *int64 `json:"finding_retention_days,omitempty"`
}

// Allow is the [allow] table.
type Allow struct {
	Drivers         []string `json:"drivers,omitempty"`
	CustomManifests []string `json:"custom_manifests,omitempty"`
	ScannerSources  []string `json:"scanner_sources,omitempty"`
	OnlineChecks    string   `json:"online_checks,omitempty"`
}

// RulePack is the [rule_pack] table.
type RulePack struct {
	MinVersion string `json:"min_version,omitempty"`
}

// Section is one [sections.<child>] table.
type Section struct {
	// Capability must equal CapabilityToken(child).
	Capability string `json:"capability"`
}

// Bounds of the numeric floors.
const (
	maxStalenessMin = 7 * 24 * 60
	maxDBAgeH       = 30 * 24
	maxListLen      = 64
)

// manifestDigest is a pre-approved custom manifest's identity (security plan
// 8.6): its sha256.
var manifestDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ErrEmptyList is a list present but empty: it would allow nothing.
var ErrEmptyList = errors.New("policyfam/securityscanning: an empty list allows nothing; leave the key out instead")

// DecodeBody parses raw strictly (unknown fields refused, size cap, trailing
// data refused) and validates every value. It does not normalize.
func DecodeBody(raw []byte, maxBytes int64) (Body, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if int64(len(raw)) > maxBytes {
		return Body{}, fmt.Errorf("policyfam/securityscanning: body is %d bytes, max %d", len(raw), maxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b Body
	if err := dec.Decode(&b); err != nil {
		return Body{}, fmt.Errorf("policyfam/securityscanning: invalid body: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Body{}, errors.New("policyfam/securityscanning: trailing data after the body")
	}
	if err := validate(b); err != nil {
		return Body{}, err
	}
	return b, nil
}

func validate(b Body) error {
	if b.Version != 0 && b.Version != BodyVersion {
		return fmt.Errorf("policyfam/securityscanning: version %d is not supported (want %d)", b.Version, BodyVersion)
	}
	if r := b.Require; r != nil {
		if err := validateRequire(*r); err != nil {
			return err
		}
	}
	if a := b.Allow; a != nil {
		if err := validateAllow(*a); err != nil {
			return err
		}
	}
	if p := b.RulePack; p != nil && p.MinVersion != "" {
		if _, err := postureop.VersionCmp(p.MinVersion, p.MinVersion); err != nil {
			return fmt.Errorf("policyfam/securityscanning: rule_pack.min_version: %w", err)
		}
	}
	if b.Sections != nil && len(b.Sections) == 0 {
		return fmt.Errorf("policyfam/securityscanning: sections: %w", ErrEmptyList)
	}
	for id, s := range b.Sections {
		if _, ok := LookupChild(id); !ok {
			return fmt.Errorf("policyfam/securityscanning: sections.%s: unknown child (want one of %s)", id, childIDs())
		}
		if want := CapabilityToken(id); s.Capability != want {
			return fmt.Errorf("policyfam/securityscanning: sections.%s.capability is %q, want %q", id, s.Capability, want)
		}
	}
	// Impossible combination: the org cannot both require the online
	// checks and forbid them.
	if b.Require != nil && b.Allow != nil && b.Require.OnlineChecks == "required" && b.Allow.OnlineChecks == "forbidden" {
		return errors.New("policyfam/securityscanning: require.online_checks = required and allow.online_checks = forbidden contradict each other")
	}
	return nil
}

func validateRequire(r Require) error {
	if r.Components != nil {
		if err := validateList(AxisComponents, r.Components, func(v string) bool { _, ok := LookupChildComponent(v); return ok }); err != nil {
			return err
		}
	}
	enums := []struct {
		axis, v string
		vals    []string
	}{
		{AxisPrelaunchTrust, r.PrelaunchTrust, PrelaunchTrustValues},
		{AxisCommitGate, r.CommitGate, CommitGateValues},
		{AxisMinBlockingSeverity, r.MinBlockingSeverity, SeverityValues},
		{AxisInstallUnknown, r.InstallUnknown, InstallUnknownValues},
		{AxisOnlineChecks, r.OnlineChecks, OnlineChecksRequireValues},
		{AxisInstallOnlineUnknown, r.InstallOnlineUnknown, InstallOnlineUnknownValues},
	}
	for _, e := range enums {
		if e.v != "" && !slices.Contains(e.vals, e.v) {
			return fmt.Errorf("policyfam/securityscanning: %s %q (want one of %s)", e.axis, e.v, strings.Join(e.vals, ", "))
		}
	}
	if v := r.QuickScanBudgetS; v != nil && !slices.Contains(QuickScanBudgetValues, *v) {
		return fmt.Errorf("policyfam/securityscanning: %s %d (want one of %v)", AxisQuickScanBudget, *v, QuickScanBudgetValues)
	}
	if v := r.MaxScanStalenessMin; v != nil && (*v < 1 || *v > maxStalenessMin) {
		return fmt.Errorf("policyfam/securityscanning: %s %d (want 1 to %d)", AxisMaxScanStaleness, *v, maxStalenessMin)
	}
	if v := r.MaxAdvisoryDBAgeH; v != nil && (*v < 1 || *v > maxDBAgeH) {
		return fmt.Errorf("policyfam/securityscanning: %s %d (want 1 to %d)", AxisMaxAdvisoryDBAge, *v, maxDBAgeH)
	}
	if v := r.FindingRetentionDays; v != nil && !slices.Contains(RetentionDaysValues, *v) {
		return fmt.Errorf("policyfam/securityscanning: %s %d (want one of %v; 0 keeps forever)", AxisFindingRetention, *v, RetentionDaysValues)
	}
	return nil
}

func validateAllow(a Allow) error {
	if a.Drivers != nil {
		if err := validateList(AxisAllowDrivers, a.Drivers, func(v string) bool { _, ok := LookupDriver(v); return ok }); err != nil {
			return err
		}
	}
	if a.CustomManifests != nil {
		if err := validateList(AxisAllowCustomManifests, a.CustomManifests, manifestDigest.MatchString); err != nil {
			return err
		}
	}
	if a.ScannerSources != nil {
		if err := validateList(AxisAllowScannerSources, a.ScannerSources, func(v string) bool { return slices.Contains(ScannerSources, v) }); err != nil {
			return err
		}
	}
	if a.OnlineChecks != "" && !slices.Contains(OnlineChecksAllowValues, a.OnlineChecks) {
		return fmt.Errorf("policyfam/securityscanning: %s %q (want one of %s)", AxisAllowOnlineChecks, a.OnlineChecks, strings.Join(OnlineChecksAllowValues, ", "))
	}
	return nil
}

func validateList(axis string, v []string, known func(string) bool) error {
	if len(v) == 0 {
		return fmt.Errorf("policyfam/securityscanning: %s: %w", axis, ErrEmptyList)
	}
	if len(v) > maxListLen {
		return fmt.Errorf("policyfam/securityscanning: %s has %d entries, max %d", axis, len(v), maxListLen)
	}
	for _, x := range v {
		if !known(x) {
			return fmt.Errorf("policyfam/securityscanning: %s: unknown value %q", axis, x)
		}
	}
	return nil
}

func childIDs() string {
	ids := make([]string, len(Children))
	for i, c := range Children {
		ids[i] = c.ID
	}
	return strings.Join(ids, ", ")
}

// PolicySpec is the compiled form: the normalized body.
type PolicySpec struct {
	Body Body
}

// CompileBody decodes, validates and normalizes raw (lists sorted and
// deduplicated, version set) and returns the spec and the canonical bytes to
// sign and hash. Two spellings of the same body (key order, escaped
// characters, list order, duplicates) compile to the same bytes.
func CompileBody(raw []byte, maxBytes int64) (PolicySpec, []byte, error) {
	b, err := DecodeBody(raw, maxBytes)
	if err != nil {
		return PolicySpec{}, nil, err
	}
	b = normalize(b)
	canon, err := json.Marshal(b)
	if err != nil {
		return PolicySpec{}, nil, fmt.Errorf("policyfam/securityscanning: canonical encode: %w", err)
	}
	return PolicySpec{Body: b}, canon, nil
}

func normalize(b Body) Body {
	b.Version = BodyVersion
	if b.Require != nil {
		r := *b.Require
		r.Components = sortedSet(r.Components)
		b.Require = &r
		if reflect.DeepEqual(r, Require{}) {
			b.Require = nil
		}
	}
	if b.Allow != nil {
		a := *b.Allow
		a.Drivers = sortedSet(a.Drivers)
		a.CustomManifests = sortedSet(a.CustomManifests)
		a.ScannerSources = sortedSet(a.ScannerSources)
		b.Allow = &a
		if a.Drivers == nil && a.CustomManifests == nil && a.ScannerSources == nil && a.OnlineChecks == "" {
			b.Allow = nil
		}
	}
	if b.RulePack != nil && b.RulePack.MinVersion == "" {
		b.RulePack = nil
	}
	return b
}

func sortedSet(v []string) []string {
	if v == nil {
		return nil
	}
	out := append([]string(nil), v...)
	sort.Strings(out)
	return slices.Compact(out)
}

// Enforces reports whether the body needs the node's enforce consent
// (preauthorize_enforce). A floor changes what the node does the moment it
// applies, so every body does, like node.features.
func Enforces(PolicySpec) bool { return true }

// RequiredCapabilities is one token per section and per required child
// component, sorted: the org server unions them into the envelope, the node
// advertises them through LiveCapabilities.
func RequiredCapabilities(s PolicySpec) []string {
	var out []string
	for id := range s.Body.Sections {
		out = append(out, CapabilityToken(id))
	}
	if r := s.Body.Require; r != nil {
		for _, comp := range r.Components {
			if c, ok := LookupChildComponent(comp); ok {
				out = append(out, CapabilityToken(c.ID))
			}
		}
	}
	return sortedSet(out)
}

// RequiredComponents is the node catalog components require.components
// names that are known children (security plan 7.3, D-753), sorted: on a
// managed node the org server also requires them through node.components.
func RequiredComponents(s PolicySpec) []string {
	var out []string
	if r := s.Body.Require; r != nil {
		for _, comp := range r.Components {
			if c, ok := LookupChildComponent(comp); ok {
				out = append(out, c.Component)
			}
		}
	}
	return sortedSet(out)
}

// SuperAdminReason reports whether publishing this body needs the org's
// super admin (security plan 7.2), and why: a body that switches on a
// process-starting or egress-making part. The reasons are listed in a fixed
// order; need is false only when there is none.
func SuperAdminReason(s PolicySpec) (reasons []string, need bool) {
	b := s.Body
	if r := b.Require; r != nil {
		if r.OnlineChecks == "required" {
			reasons = append(reasons, "require.online_checks = required switches on the online package checks")
		}
		if r.InstallOnlineUnknown == "deny" {
			reasons = append(reasons, "require.install_online_unknown = deny is a super-admin choice")
		}
		if r.HistoryScanOnEnrol != nil && *r.HistoryScanOnEnrol {
			reasons = append(reasons, "require.history_scan_on_enrol = true starts git on enrolment")
		}
		for _, comp := range r.Components {
			if c, ok := LookupChildComponent(comp); ok && (c.StartsProcess || c.MakesEgress) {
				reasons = append(reasons, "require.components names "+comp+", which starts a program or reaches the network")
			}
		}
	}
	if a := b.Allow; a != nil {
		if len(a.CustomManifests) > 0 {
			reasons = append(reasons, "allow.custom_manifests names a custom driver manifest")
		}
		for _, id := range a.Drivers {
			if d, ok := LookupDriver(id); ok && d.StartsProcess {
				reasons = append(reasons, "allow.drivers names "+id+", which starts a program")
			}
		}
	}
	for id := range b.Sections {
		if c, ok := LookupChild(id); ok && (c.StartsProcess || c.MakesEgress) {
			reasons = append(reasons, "sections."+id+" is a part that starts a program or reaches the network")
		}
	}
	sort.Strings(reasons)
	return reasons, len(reasons) > 0
}
