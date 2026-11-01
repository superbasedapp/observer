package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The managed-node guard floor (T-839 / D-672: "on a managed node, org guard
// rules win: no local weakening via [guard].enabled=false,
// [guard.prompt].enabled=false, detector modes or a local allow-regex;
// individual nodes keep full control").
//
// It is ONE resolution step at the config boundary, the last thing Load does
// after the governance overlay, so every reader (the daemon, every hook
// mechanism, every CLI surface) gets the same floored [guard] section and no
// call site re-derives it. The inputs come from the daemon's MAC'd org lock
// (internal/guardposture orglock.go): the tenancy and the floor the daemon
// resolved from the verified org bundle and the governance pins. An
// individual node's lock carries the zero floor, so its [guard] section is
// byte-identical to what it was before the floor existed; a node with no
// lock at all (no daemon, or a daemon that predates the lock) is untouched.
//
// What the config floor does NOT cover, by design: per-detector prompt modes
// and the [guard.prompt].allow list are per-RULE questions (which detector
// class did the organization pin?), so they are floored in the guard, which
// holds the org layer (internal/guard promptguard.go orgPromptReach). The
// config floor only keeps the switches that would stop the guard or the
// prompt lane from running at all.

// GuardOrgLock is the runtime record of the org lock this Load consulted. It
// is NEVER read from or written to TOML (toml:"-"): it travels on
// GuardConfig only so guard.New, which receives a GuardConfig, sees the
// daemon's tenancy, key pin and last verified org bundle without every one of
// its callers threading another option.
type GuardOrgLock struct {
	// State is "valid" or "tampered" ("" = no lock applies: absent, or the
	// read was disabled).
	State string
	// Detail says why a lock is tampered.
	Detail string
	// TenancyKnown / Managed carry the daemon's resolved tenancy (valid lock
	// only).
	TenancyKnown bool
	Managed      bool
	// KeyPinHash is the enrolment key pin the daemon verified the bundle
	// under (valid lock only).
	KeyPinHash string
	// Bundle is the last verified signed org bundle envelope (valid lock
	// only; "" = none).
	Bundle string
	// BundleExpected says the daemon recorded that this node accepted a
	// verified org bundle (valid lock only; T-864 gap 1), so a missing bundle
	// file is a deletion rather than "nothing published".
	BundleExpected bool
	// OrgExpected is the tampered-lock reading of the same fact (T-864 gap
	// 1): the lock no longer verifies, but the daemon's MAC'd posture says
	// this is a managed node with an org layer in force, or an org file is
	// on disk. Guard construction then treats a missing bundle as a
	// deletion and refuses local approvals for every rule until a verified
	// bundle (or the repaired lock) is back.
	OrgExpected bool
	// Floor is the floor that was applied (zero when none).
	Floor guardposture.GuardFloor
	// Overridden names each local setting the floor raised, as
	// "key: local VALUE, organization floor VALUE", in table order.
	Overridden []string
	// Pinned names each local setting a governance pin replaced before the
	// floor ran, as "key: local VALUE, organization pin VALUE" (T-881). It
	// is derived from the same snapshot Local carries (T-875). Read both
	// lists through OverrideLines.
	Pinned []string
	// Local is the [guard] switches exactly as the local config set them,
	// before the floor or a governance pin raised any of them (nil when no
	// lock applies; T-875 added the governance half). A switch the local
	// config never set carries the governed value. The policy-state report
	// reads it to show the organization a local weakening attempt the node
	// overrode (T-848 with D-672); nothing that enforces reads it.
	Local *GuardLocalSwitches
}

// OverrideLines is every local [guard] value this node does not apply, as
// `observer guard status` and `observer doctor` list them: the values a
// governance pin replaced (Pinned), then the ones the floor raised
// (Overridden).
func (l GuardOrgLock) OverrideLines() []string {
	if len(l.Pinned) == 0 {
		return l.Overridden
	}
	return append(append([]string{}, l.Pinned...), l.Overridden...)
}

// GuardLocalSwitches are the [guard] switches the config floor can raise,
// as the local config set them.
type GuardLocalSwitches struct {
	Enabled                  bool
	Mode                     string
	PromptEnabled            bool
	PromptHookLane           bool
	PromptEnforceIndependent bool
	PromptMode               string
	PromptDetectors          map[string]string
}

// localSwitchesOf snapshots g's floorable switches.
func localSwitchesOf(g GuardConfig) *GuardLocalSwitches {
	return &GuardLocalSwitches{
		Enabled: g.Enabled, Mode: g.Mode, PromptEnabled: g.Prompt.Enabled,
		PromptHookLane: g.Prompt.HookLane, PromptEnforceIndependent: g.Prompt.EnforceIndependent,
		PromptMode: g.Prompt.Mode, PromptDetectors: cloneDetectors(g.Prompt.Detectors),
	}
}

// ownGuardSwitches is the developer's own [guard] switches (T-875, guard
// tamper re-test 2026-10-17 C-a1): the UNGOVERNED value of each floorable
// switch the local config actually set, in a global or project TOML file or
// through its OBSERVER_* environment override. A governance pin (guard.enabled
// and guard.mode are pinnable) is applied before the floor, so without this
// the pre-floor snapshot already held the pinned values and a local
// `[guard] enabled=false` left no trace. A switch the local config never set
// is not the developer's choice and is not carried: the report keeps the
// governed value there, so an organization that pins guard.mode=enforce does
// not see every untouched node as a weakening.
type ownGuardSwitches struct {
	vals GuardLocalSwitches
	// set[i] says the local config set guardLocalRows[i].
	set []bool
}

// guardLocalRows are the floorable switches, one row each (CLAUDE.md rule
// 5): the TOML path that sets the switch, how to carry its value, and how to
// show it in an override line (T-881).
var guardLocalRows = []struct {
	path  []string
	carry func(dst *GuardLocalSwitches, src GuardLocalSwitches)
	show  func(s GuardLocalSwitches) string
}{
	{
		[]string{"guard", "enabled"},
		func(d *GuardLocalSwitches, s GuardLocalSwitches) { d.Enabled = s.Enabled },
		func(s GuardLocalSwitches) string { return strconv.FormatBool(s.Enabled) },
	},
	{
		[]string{"guard", "mode"},
		func(d *GuardLocalSwitches, s GuardLocalSwitches) { d.Mode = s.Mode },
		func(s GuardLocalSwitches) string { return s.Mode },
	},
	{
		[]string{"guard", "prompt", "enabled"},
		func(d *GuardLocalSwitches, s GuardLocalSwitches) { d.PromptEnabled = s.PromptEnabled },
		func(s GuardLocalSwitches) string { return strconv.FormatBool(s.PromptEnabled) },
	},
	{
		[]string{"guard", "prompt", "hook_lane"},
		func(d *GuardLocalSwitches, s GuardLocalSwitches) { d.PromptHookLane = s.PromptHookLane },
		func(s GuardLocalSwitches) string { return strconv.FormatBool(s.PromptHookLane) },
	},
	{[]string{"guard", "prompt", "enforce_independent"}, func(d *GuardLocalSwitches, s GuardLocalSwitches) {
		d.PromptEnforceIndependent = s.PromptEnforceIndependent
	}, func(s GuardLocalSwitches) string { return strconv.FormatBool(s.PromptEnforceIndependent) }},
	{
		[]string{"guard", "prompt", "mode"},
		func(d *GuardLocalSwitches, s GuardLocalSwitches) { d.PromptMode = s.PromptMode },
		func(s GuardLocalSwitches) string { return s.PromptMode },
	},
	{[]string{"guard", "prompt", "detectors"}, func(d *GuardLocalSwitches, s GuardLocalSwitches) {
		d.PromptDetectors = cloneDetectors(s.PromptDetectors)
	}, func(s GuardLocalSwitches) string { return showDetectors(s.PromptDetectors) }},
}

// showDetectors renders a detector map as sorted "id=mode" pairs ("defaults"
// when empty).
func showDetectors(m map[string]string) string {
	if len(m) == 0 {
		return "defaults"
	}
	pairs := make([]string, 0, len(m))
	for id, mode := range m {
		pairs = append(pairs, id+"="+mode)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, " ")
}

// pinnedLines names every switch the local config set that a governance pin
// replaced (T-881, guard tamper re-test 2026-10-17 case 4): the developer's
// value differs from governed, the value the overlay left. It reads the same
// rows and the same snapshot T-875 reports to the organization, so the local
// view and the admin's local_weakening finding name the same keys. Lines are
// "key: local VALUE, organization pin VALUE", in table order.
func (o ownGuardSwitches) pinnedLines(governed GuardLocalSwitches) []string {
	var out []string
	for i, row := range guardLocalRows {
		if i >= len(o.set) || !o.set[i] {
			continue
		}
		local, org := row.show(o.vals), row.show(governed)
		if local != org {
			out = append(out, fmt.Sprintf("%s: local %s, organization pin %s", strings.Join(row.path, "."), local, org))
		}
	}
	return out
}

// ownGuardSwitchesOf snapshots the ungoverned switches of g and records which
// of them the local config set: a key defined in any of the TOML files Load
// merged (metas), or a non-empty OBSERVER_* variable for it in env.
func ownGuardSwitchesOf(g GuardConfig, metas []toml.MetaData, env func(string) string) ownGuardSwitches {
	own := ownGuardSwitches{vals: *localSwitchesOf(g), set: make([]bool, len(guardLocalRows))}
	for i, row := range guardLocalRows {
		for j := range metas {
			if metas[j].IsDefined(row.path...) {
				own.set[i] = true
			}
		}
		if env != nil && strings.TrimSpace(env("OBSERVER_"+strings.ToUpper(strings.Join(row.path, "_")))) != "" {
			own.set[i] = true
		}
	}
	return own
}

// over writes the developer's own value onto l for every switch the local
// config set. The zero ownGuardSwitches leaves l unchanged.
func (o ownGuardSwitches) over(l *GuardLocalSwitches) {
	for i, row := range guardLocalRows {
		if i < len(o.set) && o.set[i] {
			row.carry(l, o.vals)
		}
	}
}

// WithLocalSwitches returns a copy of g whose floorable switches are the
// local config's own values (the pre-floor snapshot on g.Lock), or g
// unchanged when no lock applied. Reporting only: never feed the result to
// guard.New.
func (g GuardConfig) WithLocalSwitches() GuardConfig {
	l := g.Lock.Local
	if l == nil {
		return g
	}
	g.Enabled, g.Mode = l.Enabled, l.Mode
	g.Prompt.Enabled, g.Prompt.HookLane, g.Prompt.EnforceIndependent = l.PromptEnabled, l.PromptHookLane, l.PromptEnforceIndependent
	g.Prompt.Mode, g.Prompt.Detectors = l.PromptMode, cloneDetectors(l.PromptDetectors)
	return g
}

// guardFloorRows are the config-floor rows, walked in order (CLAUDE.md
// rule 5). Each row raises one [guard] key to the floor when the local value
// is weaker and reports the override.
var guardFloorRows = []struct {
	key   string
	apply func(g *GuardConfig, f guardposture.GuardFloor) (local, floor string, raised bool)
}{
	{"guard.enabled", func(g *GuardConfig, f guardposture.GuardFloor) (string, string, bool) {
		if !f.Enabled || g.Enabled {
			return "", "", false
		}
		g.Enabled = true
		return "false", "true", true
	}},
	{"guard.mode", func(g *GuardConfig, f guardposture.GuardFloor) (string, string, bool) {
		if !guardposture.GuardModeBelow(g.Mode, f.Mode) {
			return "", "", false
		}
		local := g.Mode
		g.Mode = f.Mode
		return local, f.Mode, true
	}},
	{"guard.prompt.enabled", func(g *GuardConfig, f guardposture.GuardFloor) (string, string, bool) {
		if !f.PromptEnabled || g.Prompt.Enabled {
			return "", "", false
		}
		g.Prompt.Enabled = true
		return "false", "true", true
	}},
	{"guard.prompt.hook_lane", func(g *GuardConfig, f guardposture.GuardFloor) (string, string, bool) {
		if !f.PromptEnabled || g.Prompt.HookLane {
			return "", "", false
		}
		g.Prompt.HookLane = true
		return "false", "true", true
	}},
	{"guard.prompt.enforce_independent", func(g *GuardConfig, f guardposture.GuardFloor) (string, string, bool) {
		if !f.PromptEnforceIndependent || g.Prompt.EnforceIndependent {
			return "", "", false
		}
		g.Prompt.EnforceIndependent = true
		return "false", "true", true
	}},
	{"guard.prompt.mode", func(g *GuardConfig, f guardposture.GuardFloor) (string, string, bool) {
		if f.PromptMode == "" || !orgcontract.LocalGuardPromptModeBelow(g.Prompt.Mode, f.PromptMode) {
			return "", "", false
		}
		local := g.Prompt.Mode
		g.Prompt.Mode = f.PromptMode
		return local, f.PromptMode, true
	}},
	{"guard.prompt.detectors", func(g *GuardConfig, f guardposture.GuardFloor) (string, string, bool) {
		if f.PromptMode == "" {
			return "", "", false
		}
		raised := floorPromptDetectors(&g.Prompt)
		if len(raised) == 0 {
			return "", "", false
		}
		return strings.Join(raised, " "), "shipped defaults", true
	}},
}

// floorPromptDetectors raises every per-detector override below that
// detector's managed floor (orgcontract.LocalGuardDetectorFloor: the lower of
// the prompt floor and the shipped default) back to the shipped default, or
// drops the override when the default set does not name the detector (it then
// follows the floored global mode). It returns "id=local" for each raised
// detector, sorted. The map is replaced, never mutated in place: a config
// that kept the seeded defaults may share that map with other readers.
func floorPromptDetectors(p *GuardPromptConfig) []string {
	if len(p.Detectors) == 0 {
		return nil
	}
	defaults := orgcontract.LocalGuardDefaultDetectorModes()
	var raised []string
	out := make(map[string]string, len(p.Detectors))
	for id, mode := range p.Detectors {
		if !orgcontract.LocalGuardPromptModeBelow(mode, orgcontract.LocalGuardDetectorFloor(id)) {
			out[id] = mode
			continue
		}
		raised = append(raised, id+"="+mode)
		if def, ok := defaults[id]; ok {
			out[id] = def
		}
	}
	if len(raised) == 0 {
		return nil
	}
	sort.Strings(raised)
	p.Detectors = out
	return raised
}

// cloneDetectors copies a detector map (nil stays nil).
func cloneDetectors(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// applyGuardFloor raises g to f and returns the override lines.
func applyGuardFloor(g *GuardConfig, f guardposture.GuardFloor) []string {
	if f.IsZero() {
		return nil
	}
	var out []string
	for _, row := range guardFloorRows {
		if local, floor, raised := row.apply(g, f); raised {
			out = append(out, fmt.Sprintf("%s: local %s, organization floor %s", row.key, local, floor))
		}
	}
	return out
}

// orgLayerPlausible reports whether an organization could hold anything on
// this node: a cached org bundle or a governance sidecar exists. It gates the
// tampered-lock fallback, so a node that was never enrolled is never floored
// because someone deleted a file.
func orgLayerPlausible(cfg Config, sidecarPath string) bool {
	for _, p := range []string{expandHome(cfg.Guard.Rules.OrgBundle), sidecarPath} {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// postureAnchor is what the daemon's MAC'd posture says about the
// organization when the org lock no longer verifies (T-864 gap 1: the lock
// and the bundle deleted together). Only a VERIFIED posture counts; its age
// does not matter here, because it is used only to stay strict, never to
// relax anything.
type postureAnchor struct {
	// managedOrg: the daemon resolved a managed node with an org layer in
	// force.
	managedOrg bool
	// enforced: that managed daemon's guard was enforcing.
	enforced bool
	// individual: the daemon resolved an individual node.
	individual bool
}

// loadPostureAnchor reads the verified posture beside globalPath.
func loadPostureAnchor(globalPath string) postureAnchor {
	if globalPath == "" {
		return postureAnchor{}
	}
	ld := guardposture.Load(guardposture.PosturePath(globalPath), guardposture.KeyPath(globalPath))
	if ld.State != guardposture.StateValid || ld.Posture == nil {
		return postureAnchor{}
	}
	p := ld.Posture
	return postureAnchor{
		managedOrg: p.Managed && p.Source == guardposture.SourceOrg,
		enforced:   p.Managed && p.Enforced,
		// Only a daemon that records tenancy in the posture (it writes the
		// org lock AND the managed bit) can vouch for an individual node; an
		// older posture says nothing either way.
		individual: !p.Managed && p.OrgLock && p.TenancyRecorded,
	}
}

// guardFloorFor maps a loaded lock onto the runtime record and the floor to
// apply (ordered by lock state; CLAUDE.md rule 5).
func guardFloorFor(ld guardposture.OrgLockLoaded, plausible bool, anchor postureAnchor) (GuardOrgLock, guardposture.GuardFloor) {
	switch ld.State {
	case guardposture.OrgLockValid:
		l := ld.Lock
		rec := GuardOrgLock{
			State: ld.State.String(), TenancyKnown: true, Managed: l.Managed, KeyPinHash: l.KeyPinHash,
			Bundle: l.Bundle, BundleExpected: l.BundleExpected || l.Bundle != "",
		}
		if !l.Managed {
			return rec, guardposture.GuardFloor{}
		}
		return rec, l.Floor
	case guardposture.OrgLockTampered:
		rec := GuardOrgLock{State: ld.State.String(), Detail: ld.Detail}
		if anchor.individual {
			// The daemon's own posture says this is an individual node:
			// local control stands while the daemon repairs the lock.
			rec.TenancyKnown = true
			return rec, guardposture.GuardFloor{}
		}
		rec.OrgExpected = anchor.managedOrg || plausible
		if !rec.OrgExpected {
			return rec, guardposture.GuardFloor{}
		}
		floor := guardposture.ConservativeFloor
		if anchor.enforced {
			// The last verified word from the daemon is "managed and
			// enforcing": keep enforcing until the lock is repaired or a
			// verified bundle arrives (the strictest safe default).
			floor.Mode = guardposture.ModeEnforce
		}
		return rec, floor
	default:
		return GuardOrgLock{}, guardposture.GuardFloor{}
	}
}

// loadOrgLockFor loads the org lock beside the global config Load read, or
// reports it absent when the read is disabled (NoGovernanceSidecar: "what
// would this machine do with no organization at all") or the path is
// unresolved.
func loadOrgLockFor(globalPath, governanceOverride string) guardposture.OrgLockLoaded {
	if governanceOverride == NoGovernanceSidecar || globalPath == "" {
		return guardposture.OrgLockLoaded{State: guardposture.OrgLockAbsent}
	}
	return guardposture.LoadOrgLock(globalPath)
}

// finishGuardFloor applies the floor to cfg's [guard] section and records
// the lock on it. It is the LAST step of Load on every return path. own is
// the developer's own switches from before the governance overlay (T-875);
// the recorded Local snapshot carries them, so the report shows what the
// developer set even where a governance pin replaced it.
func finishGuardFloor(cfg *Config, ld guardposture.OrgLockLoaded, sidecarPath, lockConfigPath string, own ownGuardSwitches) {
	if ld.State == guardposture.OrgLockAbsent {
		return
	}
	var anchor postureAnchor
	if ld.State == guardposture.OrgLockTampered {
		anchor = loadPostureAnchor(lockConfigPath)
	}
	rec, floor := guardFloorFor(ld, ld.State == guardposture.OrgLockTampered && orgLayerPlausible(*cfg, sidecarPath), anchor)
	rec.Floor = floor
	rec.Local = localSwitchesOf(cfg.Guard)
	rec.Pinned = own.pinnedLines(*rec.Local)
	own.over(rec.Local)
	rec.Overridden = applyGuardFloor(&cfg.Guard, floor)
	cfg.Guard.Lock = rec
}
