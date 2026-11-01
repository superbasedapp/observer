package sandboxselect

import (
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// Auto is the request value that lets selection pick (an empty Backend
// means the same).
const Auto = "auto"

// The closed drop-verdict vocabulary (section 4.5). Each is the copy key a
// surface renders; a backend's own probe verdict is passed through at S4.
const (
	VerdictNotEligibleForEnforcement = "not_eligible_for_enforcement"
	VerdictNotInBuild                = "not_in_build"
	VerdictExplicitOnly              = "explicit_only"
	VerdictDisabledByConfig          = "disabled_by_config"
	VerdictBackendVersionUntested    = "backend_version_untested"
	VerdictUnsupportedPlatform       = "unsupported_platform"
	VerdictBetaBelowFloor            = "beta_below_floor"
	VerdictBetaNotChosen             = "beta_not_chosen"
	VerdictBelowRequestedClass       = "below_requested_class"
	VerdictBelowOrgFloor             = "below_org_floor"
	VerdictBelowMachineFloor         = "below_machine_floor"
	VerdictBelowEgressFloor          = "below_egress_floor"
	VerdictBackendNotAllowed         = "backend_not_allowed"
	VerdictRegionNotAllowed          = "region_not_allowed"
	VerdictConsentRequired           = "consent_required"
	VerdictCustodyNotAllowed         = "custody_not_allowed"
	VerdictHostMutationRequired      = "host_mutation_required"
	VerdictCustodyUnsatisfiable      = "custody_unsatisfiable"
	VerdictEgressUnsupported         = "egress_unsupported"
	VerdictSourceUnsupported         = "source_unsupported"
	VerdictToolUnmapped              = "tool_unmapped"
	VerdictToolConflict              = "tool_conflict"
	VerdictToolUnavailableInImage    = "tool_unavailable_in_image"
	VerdictNotInteractive            = "not_interactive"
	VerdictReducedCaptureNotAccepted = "reduced_capture_not_accepted"
	VerdictReducedCaptureNotAllowed  = "reduced_capture_not_allowed"
	VerdictLifetimeCapTooShort       = "lifetime_cap_too_short"
	// VerdictProbeFailed is used at S4 when a probe gave no verdict of its
	// own.
	VerdictProbeFailed = "probe_failed"
	// VerdictAvailable is the probe verdict that passes S4.
	VerdictAvailable = "available"
)

// Request is what the launch asked for.
type Request struct {
	// Backend is an explicit row id, or "" / Auto.
	Backend string
	// MinClass is the requested minimum class ("" means none).
	MinClass vocab.IsoClass
	Tier     vocab.Tier
	// Source is the workspace source (live, clone-local, clone-remote,
	// worktree).
	Source      string
	Interactive bool
	// GuardEnforce marks the guard's enforce auto-upgrade (S0).
	GuardEnforce         bool
	AcceptReducedCapture bool
	Custody              vocab.KeyCustody
	// Region is the remote region asked for ("" for a local row).
	Region            string
	MinSessionMinutes int
	// ProviderDirect is the organization's direct provider egress posture
	// in force (DEC-9; capture_rule on an individual node), so a candidate's
	// capture is the one the launch will compute.
	ProviderDirect vocab.ProviderDirect
}

// Probe is what the cmd layer found for one backend on this host.
type Probe struct {
	// Compiled: the driver is in this build.
	Compiled bool
	// Verdict is the probe verdict (VerdictAvailable or the backend's own).
	Verdict string
	Reason  string
	// Version is the installed version as read; VersionAuthenticated says
	// it came from an authenticated identity.
	Version              string
	VersionAuthenticated bool
	// Sources are the workspace sources the backend can deliver here.
	Sources []string
	// ToolMissing: the tool's binary or runtime cannot be delivered into
	// this backend (S11).
	ToolMissing bool
	// ConsentRecorded: the user consented to this remote provider.
	ConsentRecorded bool
	// ConsentChange names what differs when a consent is recorded but no
	// longer matches (a consent verdict such as consent_changed_cap); ""
	// when none is recorded.
	ConsentChange string
	// HostMutationReady: the host change a row needs is in place.
	HostMutationReady bool
	// Hint is a known issue on this host that does not refuse the row (a
	// driver's own note, such as a container runtime known to fail); ""
	// when none. Selection never reads it.
	Hint string
}

// Floors are the org and machine-owner floors in force (section 8.1).
type Floors struct {
	OrgMinClass     vocab.IsoClass
	MachineMinClass vocab.IsoClass
	// AllowedBackends nil means any; an empty non-nil list allows none.
	AllowedBackends []string
	// AllowRemote must be set for a remote row to pass S7.
	AllowRemote          bool
	MinEgress            vocab.Tier
	FloorAcceptsBeta     bool
	RequireFullCapture   bool
	AllowedRegions       []string
	ForbidProviderInject bool
}

// InForce reports whether any floor is set (S4b).
func (f Floors) InForce() bool {
	return f.OrgMinClass != "" || f.MachineMinClass != "" || f.AllowedBackends != nil ||
		f.MinEgress != "" || f.RequireFullCapture || f.AllowedRegions != nil || f.ForbidProviderInject
}

// Tool is what selection needs about the tool being launched.
type Tool struct {
	// Mapped: the tool has a grounded sandbox spec (S10).
	Mapped bool
	// NativeConflict: the agent's own sandbox conflicts and the side table
	// has no grounded per-run disable switch (S10).
	NativeConflict    bool
	ProxyRouted       bool
	CredentialInReach bool
	// SatisfiableCustody are the custody modes this tool and credential can
	// actually use (S7d); nil means only the row's own list applies.
	SatisfiableCustody []vocab.KeyCustody
}

// Input is everything one selection reads.
type Input struct {
	Request Request
	Host    sandboxbackend.HostKind
	// Enabled is the local config's backend list in preference order.
	Enabled []string
	Probes  map[string]Probe
	Floors  Floors
	Tool    Tool
}

// Drop is why one candidate was not chosen.
type Drop struct {
	Backend string
	Rule    string
	Verdict string
	Reason  string
}

// Choice is the chosen layer and what it computes to.
type Choice struct {
	Backend      string
	Class        vocab.IsoClass
	ClassSource  vocab.ClassSource
	Tier         vocab.Tier
	Capture      CaptureResult
	Beta         bool
	Verification vocab.Verification
}

// Result is the outcome: a choice, or nil with every candidate's drop.
type Result struct {
	Chosen *Choice
	Drops  []Drop
}

// candidate carries the per-row facts the rules read.
type candidate struct {
	row     sandboxbackend.Capability
	probe   Probe
	in      Input
	auto    bool
	beta    bool
	version versionStatus
	capture CaptureResult
	verify  vocab.Verification
}

// floorClass is the class a candidate counts as for a floor: a claimed
// class counts as none.
func (c candidate) floorClass() vocab.IsoClass {
	if !c.row.Iso.ClassSource.CountsForFloor() {
		return vocab.ClassNone
	}
	return c.row.Iso.Class
}

func below(have, want vocab.IsoClass) bool {
	return want != "" && have.Rank() < want.Rank()
}

func contains[T comparable](xs []T, x T) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// selectRule is one row of the ordered table: drop returns a reason when
// the candidate is dropped, "" when it passes. verdict is fixed, except S4
// and S6 and S7b, whose verdict depends on the case (dropVerdict).
type selectRule struct {
	id   string
	drop func(c candidate) (verdict, reason string)
}

// selectRules is section 4.5's table, walked top-down per candidate.
var selectRules = []selectRule{
	{"S0", func(c candidate) (string, string) {
		if !c.in.Request.GuardEnforce {
			return "", ""
		}
		switch {
		case c.row.Iso.Location != vocab.LocationLocal:
			return VerdictNotEligibleForEnforcement, "the guard's enforcement sandbox must be local"
		case c.capture.Level != vocab.CaptureFull:
			return VerdictNotEligibleForEnforcement, "the guard's enforcement sandbox must compute to full capture"
		case c.beta:
			return VerdictNotEligibleForEnforcement, "the guard's enforcement sandbox must be live-verified on this host at this version"
		}
		return "", ""
	}},
	{"S1", func(c candidate) (string, string) {
		if !c.row.Offered() {
			return VerdictNotInBuild, c.row.Note
		}
		if !c.probe.Compiled {
			return VerdictNotInBuild, "this backend's driver is not in this build"
		}
		return "", ""
	}},
	{"S1b", func(c candidate) (string, string) {
		if c.row.ExplicitOnly && (c.auto || c.in.Request.GuardEnforce) {
			return VerdictExplicitOnly, "this backend is used only when named explicitly"
		}
		return "", ""
	}},
	{"S2", func(c candidate) (string, string) {
		if !contains(c.in.Enabled, c.row.ID) {
			return VerdictDisabledByConfig, "not in the enabled backends list"
		}
		return "", ""
	}},
	{"S3", func(c candidate) (string, string) {
		if !c.row.RunsOn(c.in.Host) {
			return VerdictUnsupportedPlatform, "this backend does not run on " + string(c.in.Host)
		}
		return "", ""
	}},
	{"S4", func(c candidate) (string, string) {
		switch c.probe.Verdict {
		case VerdictAvailable:
			return "", ""
		case "":
			return VerdictProbeFailed, "the backend was not probed"
		}
		if c.probe.Reason == "" {
			return c.probe.Verdict, "the probe reported " + c.probe.Verdict
		}
		return c.probe.Verdict, c.probe.Reason
	}},
	// S2b runs after S3 and S4 (live checks 2026-10-22): a backend that is
	// absent, whose module is inactive, or that does not run on this
	// platform has no readable version, and an empty version reads as
	// refused, so S2b first would report backend_version_untested and hide
	// backend_missing, module_inactive and unsupported_platform. A probe
	// that did not pass is reported by S4 with its own verdict; S2b judges
	// the version of a backend that is there and probed available.
	{"S2b", func(c candidate) (string, string) {
		if c.version == versionRefused {
			return VerdictBackendVersionUntested, "installed version " + quoteOr(c.probe.Version, "unknown") + " is below the required minimum " + c.row.Control.Pins.RequiredMin + " or unreadable"
		}
		if c.row.Control.Pins.RequireAuthenticatedVersion && !c.probe.VersionAuthenticated {
			return VerdictBackendVersionUntested, "the version was not read from an authenticated identity"
		}
		return "", ""
	}},
	{"S4b", func(c candidate) (string, string) {
		if c.beta && c.in.Floors.InForce() && !c.in.Floors.FloorAcceptsBeta {
			return VerdictBetaBelowFloor, "a beta backend does not meet an org or machine floor unless the floor accepts beta"
		}
		return "", ""
	}},
	// S4c (ruling P-062, clarified in P-067): automatic selection never
	// picks a row whose verification on this host is documentation only
	// (not live). Listing it in backends makes it available; a launch uses
	// it only when the launch names it. The row's verification decides,
	// never the installed version: a tested row (bwrap) outside its tested
	// range stays automatically selectable and keeps its beta label. It runs
	// after S4 and S2b, so a row that is absent, inactive or unprobed keeps
	// its own verdict (D1).
	{"S4c", func(c candidate) (string, string) {
		if c.auto && c.verify.IsBeta() {
			return VerdictBetaNotChosen, "a beta backend is used only when it is chosen for the launch (observer <tool> --observer-sandbox " + c.row.ID + "); automatic selection never picks one (ruling P-062)"
		}
		return "", ""
	}},
	{"S5", func(c candidate) (string, string) {
		if below(c.floorClass(), c.in.Request.MinClass) {
			return VerdictBelowRequestedClass, "class " + string(c.floorClass()) + " is below the requested " + string(c.in.Request.MinClass)
		}
		return "", ""
	}},
	{"S6", func(c candidate) (string, string) {
		if below(c.floorClass(), c.in.Floors.OrgMinClass) {
			return VerdictBelowOrgFloor, "class " + string(c.floorClass()) + " is below the organization's floor " + string(c.in.Floors.OrgMinClass)
		}
		if below(c.floorClass(), c.in.Floors.MachineMinClass) {
			return VerdictBelowMachineFloor, "class " + string(c.floorClass()) + " is below the machine owner's floor " + string(c.in.Floors.MachineMinClass)
		}
		return "", ""
	}},
	{"S6b", func(c candidate) (string, string) {
		f := c.in.Floors.MinEgress
		if f == "" {
			return "", ""
		}
		if c.in.Request.Tier.Strictness() < f.Strictness() {
			return VerdictBelowEgressFloor, "tier " + string(c.in.Request.Tier) + " is below the egress floor " + string(f)
		}
		if !c.row.Net.EgressSource[c.in.Request.Tier].CountsForFloor() {
			return VerdictBelowEgressFloor, "this backend's " + string(c.in.Request.Tier) + " tier is only claimed"
		}
		return "", ""
	}},
	{"S7", func(c candidate) (string, string) {
		if c.in.Floors.AllowedBackends != nil && !contains(c.in.Floors.AllowedBackends, c.row.ID) {
			return VerdictBackendNotAllowed, "not in the allowed backends"
		}
		if c.row.Iso.Location == vocab.LocationRemote && !c.in.Floors.AllowRemote {
			return VerdictBackendNotAllowed, "remote backends are not allowed"
		}
		return "", ""
	}},
	{"S7b", func(c candidate) (string, string) {
		if c.row.Iso.Location != vocab.LocationRemote {
			return "", ""
		}
		if c.in.Floors.AllowedRegions != nil && !contains(c.in.Floors.AllowedRegions, c.in.Request.Region) {
			return VerdictRegionNotAllowed, "region " + quoteOr(c.in.Request.Region, "unset") + " is not allowed"
		}
		if !c.probe.ConsentRecorded {
			if c.probe.ConsentChange != "" {
				// A changed fact is said as what changed, never as no consent
				// at all (live run 2026-10-23, finding F12).
				return VerdictConsentRequired, "the recorded consent is for other facts (" + c.probe.ConsentChange + "); review what leaves this machine and agree again"
			}
			return VerdictConsentRequired, "no recorded consent for this provider"
		}
		if c.in.Request.Custody == vocab.CustodyProviderInjected && c.in.Floors.ForbidProviderInject {
			return VerdictCustodyNotAllowed, "provider key injection is forbidden"
		}
		return "", ""
	}},
	{"S7c", func(c candidate) (string, string) {
		if c.row.Iso.HostMutation && !c.probe.HostMutationReady {
			return VerdictHostMutationRequired, "this backend needs a host change that is not in place"
		}
		return "", ""
	}},
	{"S7d", func(c candidate) (string, string) {
		cu := c.in.Request.Custody
		if cu == "" {
			return "", ""
		}
		if !contains(c.row.Net.KeyCustody, cu) || (c.in.Tool.SatisfiableCustody != nil && !contains(c.in.Tool.SatisfiableCustody, cu)) {
			return VerdictCustodyUnsatisfiable, "key custody " + string(cu) + " cannot be satisfied here"
		}
		return "", ""
	}},
	{"S8", func(c candidate) (string, string) {
		t := c.in.Request.Tier
		if !c.row.OffersTier(t) || (t == vocab.TierHost && c.row.Iso.Location == vocab.LocationRemote) {
			return VerdictEgressUnsupported, "this backend does not offer the " + string(t) + " tier"
		}
		return "", ""
	}},
	{"S9", func(c candidate) (string, string) {
		if c.in.Request.Source != "" && !contains(c.probe.Sources, c.in.Request.Source) {
			return VerdictSourceUnsupported, "this backend cannot deliver the " + c.in.Request.Source + " workspace"
		}
		return "", ""
	}},
	{"S10", func(c candidate) (string, string) {
		if !c.in.Tool.Mapped {
			return VerdictToolUnmapped, "the tool has no sandbox spec"
		}
		if c.in.Tool.NativeConflict {
			return VerdictToolConflict, "the agent's own sandbox conflicts and has no grounded per-run switch"
		}
		return "", ""
	}},
	{"S11", func(c candidate) (string, string) {
		if c.probe.ToolMissing {
			return VerdictToolUnavailableInImage, "the tool cannot be delivered into this backend"
		}
		return "", ""
	}},
	{"S11b", func(c candidate) (string, string) {
		if c.in.Request.Interactive && (c.row.Term.Resize == "" || c.row.Term.Resize == sandboxbackend.ResizeNone || c.row.Term.PTYOwner == "") {
			return VerdictNotInteractive, "no resize path or PTY owner for an interactive terminal"
		}
		return "", ""
	}},
	{"S12", func(c candidate) (string, string) {
		if c.capture.Level != vocab.CaptureFull && !c.in.Request.AcceptReducedCapture {
			return VerdictReducedCaptureNotAccepted, "this run computes " + CaptureLabel(c.capture) + " capture (rule " + c.capture.Rule + ") and reduced capture was not accepted"
		}
		return "", ""
	}},
	{"S12b", func(c candidate) (string, string) {
		if c.capture.Level != vocab.CaptureFull && c.in.Floors.RequireFullCapture {
			return VerdictReducedCaptureNotAllowed, "this run computes " + CaptureLabel(c.capture) + " capture and full capture is required"
		}
		return "", ""
	}},
	{"S13", func(c candidate) (string, string) {
		lc := c.row.LifetimeCapSeconds
		if c.row.Iso.Location == vocab.LocationRemote && lc > 0 && lc < c.in.Request.MinSessionMinutes*60 {
			return VerdictLifetimeCapTooShort, "the provider's lifetime cap is shorter than the minimum session"
		}
		return "", ""
	}},
}

func quoteOr(s, empty string) string {
	if s == "" {
		return empty
	}
	return "\"" + s + "\""
}

// newCandidate fills the derived facts for one row.
func newCandidate(row sandboxbackend.Capability, in Input, auto bool) candidate {
	c := candidate{row: row, probe: in.Probes[row.ID], in: in, auto: auto}
	pins := row.Control.Pins
	c.version = classifyVersion(c.probe.Version, pins.RequiredMin, pins.TestedLow, pins.TestedHigh)
	if v, ok := row.VerificationOn(in.Host); ok {
		c.verify = v.Kind
	}
	c.beta = c.verify.IsBeta() || c.version != versionTested
	c.capture = ComputeCapture(CaptureInput{
		Row: row, Tier: in.Request.Tier, Custody: in.Request.Custody,
		ProxyRouted: in.Tool.ProxyRouted, CredentialInReach: in.Tool.CredentialInReach,
		ProviderDirect: in.Request.ProviderDirect,
	})
	return c
}

// judge walks the rule table for one candidate; ok when every row passes.
func judge(c candidate) (Drop, bool) {
	for _, r := range selectRules {
		if v, why := r.drop(c); v != "" {
			return Drop{Backend: c.row.ID, Rule: r.id, Verdict: v, Reason: why}, false
		}
	}
	return Drop{}, true
}

// autoRules are the rows of selectRules that judge only an automatic choice
// (a launch that names no backend): an explicit-only row (S1b) and a beta
// row (S4c, ruling P-062).
var autoRules = map[string]bool{"S1b": true, "S4c": true}

// AutoDrop judges one row against the automatic-choice rules only, with
// the row's verification on this host given (the launch path reads it from
// the row's availability): the version-derived beta label plays no part
// (P-067). It is how a launch that names no backend walks the enabled list:
// a row it drops is available but not chosen.
func AutoDrop(row sandboxbackend.Capability, verification vocab.Verification) (Drop, bool) {
	c := candidate{row: row, auto: true, verify: verification, beta: verification.IsBeta()}
	for _, r := range selectRules {
		if !autoRules[r.id] {
			continue
		}
		if v, why := r.drop(c); v != "" {
			return Drop{Backend: row.ID, Rule: r.id, Verdict: v, Reason: why}, true
		}
	}
	return Drop{}, false
}

// floorRules are the rows of selectRules that come from org and machine
// floors (section 8.1).
var floorRules = map[string]bool{"S4b": true, "S6": true, "S6b": true, "S7": true, "S7b": true, "S12b": true}

// IsFloorRule reports whether a drop came from a floor rule.
func IsFloorRule(id string) bool { return floorRules[id] }

// FloorDrop judges one row against the floor rules only, with the beta fact
// given (the launch path knows the row's verification, not the probe's
// version). It is the launch-time re-check of a floor: dropped is true with
// the first floor that rules the row out.
func FloorDrop(row sandboxbackend.Capability, in Input, beta bool) (Drop, bool) {
	c := newCandidate(row, in, false)
	c.beta = beta
	for _, r := range selectRules {
		if !floorRules[r.id] {
			continue
		}
		if v, why := r.drop(c); v != "" {
			return Drop{Backend: row.ID, Rule: r.id, Verdict: v, Reason: why}, true
		}
	}
	return Drop{}, false
}

// Select is the single decision point. An explicit backend is the only
// candidate and is never substituted (I1). Auto walks the enabled list in
// preference order, then every other offered row (so its drop reason is
// shown), and picks the first that survives every rule; floors and the
// requested class are rules, so auto can never pick a weaker class than
// either. When nothing survives, Chosen is nil and Drops lists every
// candidate.
func Select(in Input) Result {
	auto := in.Request.Backend == "" || in.Request.Backend == Auto
	var cands []sandboxbackend.Capability
	if !auto {
		row, ok := sandboxbackend.Get(in.Request.Backend)
		if !ok {
			return Result{Drops: []Drop{{Backend: in.Request.Backend, Rule: "S1", Verdict: VerdictNotInBuild, Reason: "no such backend"}}}
		}
		cands = []sandboxbackend.Capability{row}
	} else {
		seen := map[string]bool{}
		for _, id := range in.Enabled {
			if row, ok := sandboxbackend.Get(id); ok && !seen[id] {
				seen[id] = true
				cands = append(cands, row)
			}
		}
		for _, row := range sandboxbackend.Offered() {
			if !seen[row.ID] {
				seen[row.ID] = true
				cands = append(cands, row)
			}
		}
	}
	var res Result
	for _, row := range cands {
		c := newCandidate(row, in, auto)
		d, ok := judge(c)
		if !ok {
			res.Drops = append(res.Drops, d)
			continue
		}
		res.Chosen = &Choice{
			Backend: row.ID, Class: row.Iso.Class, ClassSource: row.Iso.ClassSource,
			Tier: in.Request.Tier, Capture: c.capture, Beta: c.beta, Verification: c.verify,
		}
		return res
	}
	return res
}
