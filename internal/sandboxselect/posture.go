package sandboxselect

import (
	"fmt"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/postureop"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// posture.go is this module's half of the result-based posture check
// (sandbox plan v2 section 8.5, SBX-GOV-5). The comparison, the merge
// operators and the axis kinds are the core leaf internal/postureop
// (roadmap F0-8); what lives here is the sandbox module's axes as data and
// the evaluator that computes this node's value on each axis from its
// settings, the host kind and the registry. It never probes: the effective
// class is that of the first backend `auto` would pick from the registry's
// static facts on this host (a claimed class counts as none), so the check
// runs only when a body is in force and costs nothing else.

// The posture axis names, the names a posture_loosened refusal carries.
const (
	AxisAutoClass       = "sandbox.auto_class"
	AxisEnginePrivilege = "sandbox.engine_privilege"
	AxisEgressTier      = "sandbox.egress_tier"
	AxisCapture         = "sandbox.capture"
	AxisKeyCustody      = "sandbox.key_custody"
	AxisLocation        = "sandbox.location"
	AxisVerification    = "sandbox.verification"
	AxisRetention       = "sandbox.workspace_retention"
	AxisEnabledSet      = "sandbox.enabled_backends"
	AxisRemoteHosts     = "sandbox.remote_allowed_hosts"
	AxisMasks           = "sandbox.mask_paths"
	AxisROBinds         = "sandbox.extra_ro_binds"
	AxisRWBinds         = "sandbox.extra_rw_binds"
	AxisEgressCIDRs     = "sandbox.egress_allow_cidrs"
	AxisRemoteClone     = "sandbox.allow_remote_clone"
	AxisWorktreeSource  = "sandbox.allow_worktree_source"
	AxisToolConfig      = "sandbox.allow_tool_config_writes"
	AxisHomeMode        = "sandbox.home_mode"
	AxisDefaultOn       = "sandbox.default_on"
)

// fixedKeyCustody is the fixed value of the one axis no shipped row varies
// yet: key custody arrives with the remote rows (P7), which replace it with
// the row's own. Engine privilege is the picked row's (enginePrivilege,
// SBX-P3A merge finding F4).
const fixedKeyCustody = string(vocab.CustodyHostBound)

// The engine privilege axis values.
const (
	enginePrivilegeRootful  = "rootful"
	enginePrivilegeRootless = "rootless"
)

// enginePrivilege is the privilege of what the auto pick runs on (SBX-P3A
// merge finding F4; it was a fixed "rootless" before the oci-runc row): a
// row driven through a container engine's API (Control.Interface
// InterfaceEngineAPIUDS, a capability, never a backend id) runs on a rootful
// engine when the settings allow one ([terminal.sandbox.oci].allow_rootful),
// which is the worst the node can run because the posture never probes;
// rootless otherwise. Every other row (bwrap's user namespaces) and no pick
// at all are rootless.
func enginePrivilege(s PostureSettings, row sandboxbackend.Capability, picked bool) string {
	if picked && row.Control.Interface == sandboxbackend.InterfaceEngineAPIUDS && s.RootfulEngineAllowed {
		return enginePrivilegeRootful
	}
	return enginePrivilegeRootless
}

// PostureAxes is the sandbox module's axis table, weaker to stronger in
// every Order (section 8.5). Compare walks it in this order, so the first
// loosened axis a refusal names is the most important one.
var PostureAxes = []postureop.Axis{
	{Name: AxisAutoClass, Kind: postureop.AxisEnum, Order: classOrder()},
	{Name: AxisEnginePrivilege, Kind: postureop.AxisEnum, Order: []string{enginePrivilegeRootful, enginePrivilegeRootless}},
	{Name: AxisEgressTier, Kind: postureop.AxisEnum, Order: []string{string(vocab.TierHost), string(vocab.TierInternet), string(vocab.TierProxyOnly), string(vocab.TierNone)}},
	{Name: AxisCapture, Kind: postureop.AxisEnum, Order: captureOrder()},
	{Name: AxisKeyCustody, Kind: postureop.AxisEnum, Order: []string{
		string(vocab.CustodyProviderInjected), string(vocab.CustodyInBoxAPIKey), string(vocab.CustodyInBoxOAuthSeed),
		string(vocab.CustodyHomeRelay), string(vocab.CustodyHostBound),
	}},
	{Name: AxisLocation, Kind: postureop.AxisEnum, Order: []string{string(vocab.LocationRemote), string(vocab.LocationLocal)}},
	{Name: AxisVerification, Kind: postureop.AxisEnum, Order: []string{"beta", string(vocab.VerifiedLive)}},
	{Name: AxisRetention, Kind: postureop.AxisRetention},
	{Name: AxisEnabledSet, Kind: postureop.AxisSubsetStronger},
	{Name: AxisRemoteHosts, Kind: postureop.AxisSubsetStronger},
	{Name: AxisMasks, Kind: postureop.AxisSupersetStronger},
	{Name: AxisROBinds, Kind: postureop.AxisSubsetStronger},
	{Name: AxisRWBinds, Kind: postureop.AxisSubsetStronger},
	{Name: AxisEgressCIDRs, Kind: postureop.AxisSubsetStronger},
	{Name: AxisRemoteClone, Kind: postureop.AxisEnum, Order: onOff},
	{Name: AxisWorktreeSource, Kind: postureop.AxisEnum, Order: onOff},
	{Name: AxisToolConfig, Kind: postureop.AxisEnum, Order: onOff},
	{Name: AxisHomeMode, Kind: postureop.AxisEnum, Order: []string{"readonly", "tmpfs"}},
	{Name: AxisDefaultOn, Kind: postureop.AxisEnum, Order: []string{"off", "on"}},
}

// onOff orders an expanding switch: on is the weaker value.
var onOff = []string{"on", "off"}

func classOrder() []string {
	out := []string{}
	for _, c := range vocab.Classes() {
		out = append(out, string(c))
	}
	return out
}

func captureOrder() []string {
	out := []string{}
	for _, c := range vocab.CaptureLevels() {
		out = append(out, string(c))
	}
	return out
}

// PostureEnumKeys lists the enum-valued settings and the axis each sits on,
// for postureop.ReviewEnums: a value added to a setting without a place on
// its axis fails this package's tests.
func PostureEnumKeys() []postureop.EnumKey {
	tiers := []string{}
	for _, t := range vocab.Tiers() {
		tiers = append(tiers, string(t))
	}
	return []postureop.EnumKey{
		{Key: "terminal.sandbox.egress", Axis: AxisEgressTier, Values: tiers},
		{Key: "terminal.sandbox.min_isolation", Axis: AxisAutoClass, Values: classOrder()},
		{Key: "terminal.sandbox.home_mode", Axis: AxisHomeMode, Values: []string{"tmpfs", "readonly"}},
	}
}

// PostureSettings is the part of a node's [terminal.sandbox] settings the
// axes read, resolved at the boundary (cmd/observer converts the config).
type PostureSettings struct {
	Enabled bool
	// Backends is the effective preference order (the legacy backend key
	// already folded in).
	Backends []string
	// Egress is the configured tier; "" means internet.
	Egress string
	// RemoteAllowedHosts empty means any host (only while no pin is in
	// force).
	RemoteAllowedHosts    []string
	MaskPaths             []string
	ExtraROBinds          []string
	ExtraRWBinds          []string
	EgressAllowCIDRs      []string
	AllowRemoteClone      bool
	AllowWorktreeSource   bool
	AllowToolConfigWrites bool
	DefaultOn             bool
	HomeMode              string
	RetentionDays         int64
	// RootfulEngineAllowed is [terminal.sandbox.oci].allow_rootful: an
	// engine-driven row may then run on a rootful engine.
	RootfulEngineAllowed bool
}

// PostureEnv is what the evaluator reads besides the settings: the host
// kind and the registry, injected so a test can stand in rows that are not
// offered yet.
type PostureEnv struct {
	Host sandboxbackend.HostKind
	// Row looks a backend up; nil means sandboxbackend.Get.
	Row func(id string) (sandboxbackend.Capability, bool)
	// Compiled reports whether a backend's driver is in this build; nil
	// means every offered row.
	Compiled func(id string) bool
}

func (e PostureEnv) row(id string) (sandboxbackend.Capability, bool) {
	if e.Row != nil {
		return e.Row(id)
	}
	return sandboxbackend.Get(id)
}

// AutoPick is the backend `auto` would pick from the settings on env's host
// without probing: the first enabled backend that is offered, compiled, runs
// on the host, is not explicit-only and offers the configured tier.
func AutoPick(s PostureSettings, env PostureEnv) (sandboxbackend.Capability, bool) {
	if !s.Enabled {
		return sandboxbackend.Capability{}, false
	}
	tier := postureTier(s.Egress)
	for _, id := range s.Backends {
		row, ok := env.row(id)
		if !ok || !row.Offered() || row.ExplicitOnly || !row.RunsOn(env.Host) || !row.OffersTier(tier) {
			continue
		}
		if env.Compiled != nil && !env.Compiled(id) {
			continue
		}
		return row, true
	}
	return sandboxbackend.Capability{}, false
}

func postureTier(egress string) vocab.Tier {
	if egress == "" {
		return vocab.TierInternet
	}
	return vocab.Tier(egress)
}

// EvaluatePosture computes the node's value on every axis. The axes that
// describe the picked backend (capture, location, verification) are present
// only when `auto` picks one: with no pick the class axis already reads
// none, and an axis absent before has nothing to loosen.
func EvaluatePosture(s PostureSettings, env PostureEnv) postureop.Posture {
	p := postureop.Posture{
		AxisAutoClass:       {S: string(vocab.ClassNone)},
		AxisEnginePrivilege: {S: enginePrivilegeRootless},
		AxisEgressTier:      {S: string(postureTier(s.Egress))},
		AxisKeyCustody:      {S: fixedKeyCustody},
		AxisRetention:       {N: s.RetentionDays},
		AxisMasks:           {Set: sortedCopy(s.MaskPaths)},
		AxisROBinds:         {Set: sortedCopy(s.ExtraROBinds)},
		AxisRWBinds:         {Set: sortedCopy(s.ExtraRWBinds)},
		AxisEgressCIDRs:     {Set: sortedCopy(s.EgressAllowCIDRs)},
		AxisRemoteClone:     {S: onOffValue(s.AllowRemoteClone)},
		AxisWorktreeSource:  {S: onOffValue(s.AllowWorktreeSource)},
		AxisToolConfig:      {S: onOffValue(s.AllowToolConfigWrites)},
		AxisHomeMode:        {S: homeMode(s.HomeMode)},
		AxisDefaultOn:       {S: onOffValue(s.DefaultOn)},
	}
	if s.Enabled {
		p[AxisEnabledSet] = postureop.Value{Set: sortedCopy(s.Backends)}
	} else {
		p[AxisEnabledSet] = postureop.Value{Set: nil}
	}
	if len(s.RemoteAllowedHosts) > 0 {
		p[AxisRemoteHosts] = postureop.Value{Set: sortedCopy(s.RemoteAllowedHosts)}
	}
	row, picked := AutoPick(s, env)
	p[AxisEnginePrivilege] = postureop.Value{S: enginePrivilege(s, row, picked)}
	if picked {
		c := candidate{row: row}
		p[AxisAutoClass] = postureop.Value{S: string(c.floorClass())}
		capture := ComputeCapture(CaptureInput{
			Row: row, Tier: postureTier(s.Egress), Custody: vocab.CustodyHostBound,
			ProxyRouted: true, CredentialInReach: true,
		})
		p[AxisCapture] = postureop.Value{S: string(capture.Level)}
		p[AxisLocation] = postureop.Value{S: string(row.Iso.Location)}
		verify := "beta"
		if v, ok := row.VerificationOn(env.Host); ok && !v.Kind.IsBeta() {
			verify = string(vocab.VerifiedLive)
		}
		p[AxisVerification] = postureop.Value{S: verify}
	}
	return p
}

func onOffValue(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func homeMode(m string) string {
	if m == "" {
		return "tmpfs"
	}
	return m
}

func sortedCopy(v []string) []string {
	if len(v) == 0 {
		return nil
	}
	out := append([]string(nil), v...)
	sort.Strings(out)
	return out
}

// PinPostureInput is one pin set's check: the node's own settings and the
// settings with the pins applied by the config overlay. A pin the overlay
// skipped (a value outside its row) is not part of the check: the overlay
// reports it not honoured, key by key, and never refuses the rest of the
// body for it (SBX-P1B merge audit finding 3). An emptied list is never a
// skip: the overlay applies what plan 10.1 says it means (no backend, no
// remote host).
type PinPostureInput struct {
	Before PostureSettings
	After  PostureSettings
	Env    PostureEnv
}

// CheckPinPosture refuses a pin set that would leave this node weaker on
// any axis. It returns the axis and the refusal; "" and nil mean the pins
// may apply.
func CheckPinPosture(in PinPostureInput) (string, error) {
	axis, detail := postureop.FirstLoosened(PostureAxes, EvaluatePosture(in.Before, in.Env), EvaluatePosture(in.After, in.Env))
	if axis == "" {
		return "", nil
	}
	return axis, fmt.Errorf("the pins would make this node's sandbox weaker: %s", detail)
}
