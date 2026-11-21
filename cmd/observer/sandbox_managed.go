//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxcidr"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sandbox_managed.go is the node consumer of the sandbox module's managed
// pull, GET /api/agent/sandbox (sandbox plan v2 section 8.2, phase P1c). It
// registers the "sandbox" sink on the kit's shared poll step while the
// Sandboxes and VMs module is active (managedpull_wire.go), keeps the last
// verified body in force in ONE process-wide overlay, and composes it onto
// the local [terminal.sandbox] block at the one place a launch reads the
// effective sandbox config (sandboxHolder.reload in the daemon, the CLI
// launch in terminal_sandbox_cli.go). config.toml is never rewritten.
//
// The composition order is the plan's (section 8.2 "Precedence"):
//
//  1. the machine-owner ceiling (internal/managedconfig): it has no sandbox
//     key today, so it bounds nothing yet;
//  2. org floors and pins: a key the org pinned through settings.pin keeps
//     its pinned value (the managed pull never overrides it), and the local
//     floor min_isolation and the node.features sandbox_required gate are
//     not keys of the body, so they bound every managed value;
//  3. the managed pull, only while IN FORCE (a managed node whose honoured
//     grant holds enforce.sandbox, a verified, unexpired document);
//  4. the local values, for every key the body does not set.
//
// The effective-posture comparison does not apply to this body on a managed
// node (that is the authority's point). Fail closed for an ENABLING body
// means: anything unverified, expired or not preauthorized leaves the local
// values in force, whole, so no backend stays enabled that the last
// verified body did not enable.

// sandboxManagedRail is the kit rail this file consumes.
const sandboxManagedRail = "sandbox"

// sandboxManagedCompiled reports whether this build consumes the sandbox
// managed pull (false in sandbox_managed_omit.go).
const sandboxManagedCompiled = true

func init() {
	registerManagedPullConsumer(managedPullConsumer{
		rail:   sandboxManagedRail,
		active: sandboxModuleActive,
		sink:   processSandboxManaged.observe,
		bind:   processSandboxManaged.bindGovernance,
	})
}

// sandboxManagedOverlay is the process-wide managed sandbox state: the last
// outcome of the rail and, while it is in force, its decoded body. One
// owner: observe writes it, compose reads it.
type sandboxManagedOverlay struct {
	mu      sync.RWMutex
	outcome orgclient.ManagedPullOutcome
	policy  *orgcontract.SandboxManagedPolicyV1
	bodyErr string
	gov     governanceEffective
	// gen moves on every change that can change the composed config, so
	// the sandbox holder rebuilds its runtime without a config edit.
	gen atomic.Uint64
	// waitMu guards wait, a channel closed on the next generation move: the
	// broadcast the capture relay waits on to start when a managed body turns
	// the sandbox on (SBX-P1C merge finding 1).
	waitMu sync.Mutex
	wait   chan struct{}
}

var processSandboxManaged sandboxManagedOverlay

// bindGovernance attaches the live grant the composition reads pins from.
func (o *sandboxManagedOverlay) bindGovernance(gov governanceEffective) {
	o.mu.Lock()
	o.gov = gov
	o.mu.Unlock()
	o.bump()
}

// observe is the rail's sink: it keeps a body only while it is in force and
// decodes; anything else drops back to the local values.
func (o *sandboxManagedOverlay) observe(out orgclient.ManagedPullOutcome) {
	var (
		policy  *orgcontract.SandboxManagedPolicyV1
		bodyErr string
	)
	if out.InForce && len(out.Body) > 0 {
		p, err := orgcontract.DecodeSandboxManagedPolicy(out.Body)
		if err != nil {
			bodyErr = err.Error()
		} else {
			policy = &p
		}
	}
	o.mu.Lock()
	changed := o.outcome.InForce != out.InForce || o.outcome.Version != out.Version ||
		o.outcome.ExpiresAt != out.ExpiresAt || (o.policy == nil) != (policy == nil) || o.bodyErr != bodyErr
	o.outcome, o.policy, o.bodyErr = out, policy, bodyErr
	o.mu.Unlock()
	if changed {
		o.bump()
	}
}

// generation reports the overlay's change counter.
func (o *sandboxManagedOverlay) generation() uint64 { return o.gen.Load() }

// bump moves the generation and wakes every waiter.
func (o *sandboxManagedOverlay) bump() {
	o.gen.Add(1)
	o.waitMu.Lock()
	if o.wait != nil {
		close(o.wait)
		o.wait = nil
	}
	o.waitMu.Unlock()
}

// changed returns a channel closed on the next generation move. A waiter
// takes it BEFORE reading the state it guards, so no move is missed.
func (o *sandboxManagedOverlay) changed() <-chan struct{} {
	o.waitMu.Lock()
	defer o.waitMu.Unlock()
	if o.wait == nil {
		o.wait = make(chan struct{})
	}
	return o.wait
}

// snapshot returns what composition needs: the in-force body (nil when none)
// and the pins of the live grant.
func (o *sandboxManagedOverlay) snapshot(ctx context.Context, now time.Time) (*orgcontract.SandboxManagedPolicyV1, map[string]any) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	// Version 0 is a stored document that no longer verifies (the rail
	// status's unverified row); it never composes (FX1-A5).
	if o.policy == nil || !o.outcome.InForce || o.outcome.Version == 0 || o.outcome.ExpiresAt <= now.Unix() {
		return nil, nil
	}
	var pins map[string]any
	if o.gov != nil {
		if eff := o.gov.Effective(ctx); eff.Active {
			pins = eff.Pinned
		}
	}
	return o.policy, pins
}

// effectiveSandboxConfig is the daemon's effective [terminal.sandbox]: the
// local block with the in-force managed body composed onto it.
func effectiveSandboxConfig(full config.Config) config.TerminalSandboxConfig {
	now := time.Now()
	p, pins := processSandboxManaged.snapshot(context.Background(), now)
	if p == nil {
		cfg := full.Terminal.Sandbox
		sandboxManagedNoteAuthority(&cfg, processSandboxManaged.lacksSandboxAuthority(context.Background()))
		return cfg
	}
	cfg, _ := composeSandboxManaged(full.Terminal.Sandbox, *p, sandboxManagedEnvFor(full, pins))
	return cfg
}

// lacksSandboxAuthority reports whether the bound governance is a live
// managed enrolment whose grant does not hold the sandbox rail's authority
// (enforce.sandbox), so no sandbox body can apply (FX1 item 7, live finding
// F-B2). False when no governance is bound or the node is not managed.
func (o *sandboxManagedOverlay) lacksSandboxAuthority(ctx context.Context) bool {
	o.mu.RLock()
	gov := o.gov
	o.mu.RUnlock()
	if gov == nil {
		return false
	}
	return sandboxAuthorityMissing(gov.Effective(ctx))
}

// sandboxAuthorityMissing is the one rule both compositions (the daemon's
// overlay and the CLI's stored-document read) use: a live, managed
// governance whose grant lacks the sandbox rail's authority token.
func sandboxAuthorityMissing(eff govern.Effective) bool {
	rail, ok := orgcontract.LookupManagedPullRail(sandboxManagedRail)
	return ok && eff.Active && eff.Managed && !slices.Contains(eff.Authority, rail.Authority)
}

// sandboxManagedChanged reports (and records) whether the overlay moved
// since *seen, so the sandbox holder can rebuild its runtime.
func sandboxManagedChanged(seen *uint64) bool {
	g := processSandboxManaged.generation()
	if *seen == g {
		return false
	}
	*seen = g
	return true
}

// sandboxPinnedSet reports which keys the org's pins actually set on cfg,
// through the one governance overlay (config.ApplyGovernancePinsTo), so the
// managed body composes with pins exactly as the SBX-P1B overlay applies
// them: a pin the overlay skips is not applicable for that key only (the body
// may set that key); a key an emptied list pin forces counts as pinned (an
// empty remote_allowed_hosts intersection forces allow_remote_clone=false,
// which the body may not turn back on); an emptied backends filter
// (PinnedNoBackend) keeps backends pinned, so the body cannot re-enable one.
// The daemon passes the live grant's pins, the CLI the governance sidecar's
// pins in force (the same map config.Load applied, SBX-P1C merge finding 2).
func sandboxPinnedSet(cfg config.Config, pins map[string]any) func(string) bool {
	if len(pins) == 0 {
		return func(string) bool { return false }
	}
	_, out := config.ApplyGovernancePinsTo(cfg, pins)
	set := make(map[string]bool, len(out.Applied))
	for _, k := range out.Applied {
		set[k] = true
	}
	return func(k string) bool { return set[k] }
}

// sandboxManagedEnvFor is the one composition environment for a loaded cfg
// and the pins it was loaded under.
func sandboxManagedEnvFor(cfg config.Config, pins map[string]any) sandboxManagedEnv {
	home, _ := os.UserHomeDir()
	return sandboxManagedEnv{
		pinned:       sandboxPinnedSet(cfg, pins),
		observerDir:  sandboxObserverDirFor(cfg),
		resolve:      resolveSandboxBindPath,
		home:         home,
		localRWBinds: append([]string(nil), cfg.Terminal.Sandbox.ExtraRWBinds...),
	}
}

// sandboxManagedEnv is what composition needs from the host.
type sandboxManagedEnv struct {
	// pinned reports an org pin on a full config key
	// ("terminal.sandbox.<key>").
	pinned func(string) bool
	// observerDir is the node's observer directory, which no bind may show.
	observerDir string
	// resolve resolves a path's symlinks ("" or the input when it cannot).
	resolve func(string) string
	// home is the node's home directory ("" when unknown); with it the
	// sensitive write-bind rule is checked against the real home.
	home string
	// localRWBinds are the developer's own extra_rw_binds (the one exception
	// the rule makes under ~/.config).
	localRWBinds []string
}

// SandboxManagedRefusedKey is one body key the node did not apply, with its
// reason (a closed vocabulary, never a path).
type SandboxManagedRefusedKey struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
	// Partial is set when the key still applied in part (a managed backend
	// list with an ExplicitOnly row left off, lane FU8). Node-local only:
	// the push wire carries Key and Reason.
	Partial bool `json:"partial,omitempty"`
}

// The closed refusal reasons.
const (
	sandboxRefusedPinned           = "pinned_by_org"
	sandboxRefusedNotAbsolute      = "not_absolute"
	sandboxRefusedBadCharacter     = "bad_character"
	sandboxRefusedDotDot           = "dot_dot_segment"
	sandboxRefusedLeadingDash      = "leading_dash"
	sandboxRefusedWholeRoot        = "whole_root_rw"
	sandboxRefusedObserverDir      = "exposes_observer_dir"
	sandboxRefusedCIDRNotAllowable = "cidr_not_allowable"
	// sandboxRefusedSensitive is a write bind of a sensitive host location
	// (orgcontract/sandboxbinds.go, the SBX-P1C merge bind decision).
	sandboxRefusedSensitive = string(orgcontract.SandboxRefusedSensitivePath)
	// sandboxRefusedPinnedEnabled is an empty managed backend list, which
	// would switch the sandbox off, while the org pins enabled.
	sandboxRefusedPinnedEnabled = "would_disable_pinned_enabled"
	// sandboxRefusedExplicitOnly is a managed backend list naming an
	// ExplicitOnly row (openshell and the other opt-in rows) the developer's
	// own list does not name: a body may only filter such a row, never add
	// it (lane FU8, ledger OSH-45). The row is left off and the rest of the
	// list applies; a list left with nothing is refused whole.
	sandboxRefusedExplicitOnly = "explicit_only_not_listed"
)

// sandboxPartialMark ends a row's refusal reason when the row still applied
// what it could (the filtered backend list): composition records the reason
// without the mark, flags the refusal Partial and keeps the trial. Every
// other reason refuses the whole key.
const sandboxPartialMark = "+partial"

// filterManagedBackends drops from a managed backend list every ExplicitOnly
// registry row (a capability, never a backend name) the developer's own list
// does not name. It returns the list kept and whether it dropped anything.
func filterManagedBackends(managed, local []string, mayAdd func(id string) bool) ([]string, bool) {
	kept := make([]string, 0, len(managed))
	dropped := false
	for _, id := range managed {
		if row, ok := sandboxbackend.Get(id); ok && row.ExplicitOnly && !slices.Contains(local, id) && (mayAdd == nil || !mayAdd(id)) {
			dropped = true
			continue
		}
		kept = append(kept, id)
	}
	return kept, dropped
}

// sandboxManagedField is one body key: its full config key and how it
// applies. apply returns a refusal reason, or "" when it applied (or the
// body does not set the key: then set is false).
type sandboxManagedField struct {
	key   string
	apply func(dst *config.TerminalSandboxConfig, p orgcontract.SandboxManagedPolicyV1, env sandboxManagedEnv) (set bool, refused string)
}

func setBool(get func(orgcontract.SandboxManagedPolicyV1) *bool, put func(*config.TerminalSandboxConfig, bool)) func(*config.TerminalSandboxConfig, orgcontract.SandboxManagedPolicyV1, sandboxManagedEnv) (bool, string) {
	return func(dst *config.TerminalSandboxConfig, p orgcontract.SandboxManagedPolicyV1, _ sandboxManagedEnv) (bool, string) {
		v := get(p)
		if v == nil {
			return false, ""
		}
		put(dst, *v)
		return true, ""
	}
}

func setInt(get func(orgcontract.SandboxManagedPolicyV1) *int, put func(*config.TerminalSandboxConfig, int)) func(*config.TerminalSandboxConfig, orgcontract.SandboxManagedPolicyV1, sandboxManagedEnv) (bool, string) {
	return func(dst *config.TerminalSandboxConfig, p orgcontract.SandboxManagedPolicyV1, _ sandboxManagedEnv) (bool, string) {
		v := get(p)
		if v == nil {
			return false, ""
		}
		put(dst, *v)
		return true, ""
	}
}

func setList(get func(orgcontract.SandboxManagedPolicyV1) *[]string, put func(*config.TerminalSandboxConfig, []string), check func([]string, sandboxManagedEnv) string) func(*config.TerminalSandboxConfig, orgcontract.SandboxManagedPolicyV1, sandboxManagedEnv) (bool, string) {
	return func(dst *config.TerminalSandboxConfig, p orgcontract.SandboxManagedPolicyV1, env sandboxManagedEnv) (bool, string) {
		v := get(p)
		if v == nil {
			return false, ""
		}
		if check != nil {
			if why := check(*v, env); why != "" {
				return true, why
			}
		}
		put(dst, append([]string{}, (*v)...))
		return true, ""
	}
}

func nodeOf(p orgcontract.SandboxManagedPolicyV1) orgcontract.SandboxManagedNodeV1 {
	if p.Node == nil {
		return orgcontract.SandboxManagedNodeV1{}
	}
	return *p.Node
}

// sandboxManagedFields is the closed composition table, one row per body
// key (CLAUDE.md #5), walked in order.
var sandboxManagedFields = []sandboxManagedField{
	{"terminal.sandbox.enabled", setBool(func(p orgcontract.SandboxManagedPolicyV1) *bool { return p.Enabled },
		func(d *config.TerminalSandboxConfig, v bool) { d.Enabled = v })},
	{"terminal.sandbox.backends", func(dst *config.TerminalSandboxConfig, p orgcontract.SandboxManagedPolicyV1, env sandboxManagedEnv) (bool, string) {
		if p.Backends == nil {
			return false, ""
		}
		if len(*p.Backends) == 0 {
			// An empty managed list enables no backend: the legacy single
			// backend must not slip back in, so the sandbox is off (a launch
			// that requires one is refused). That side effect never
			// overrides a pinned enabled: the list is refused instead.
			if env.pinned != nil && env.pinned("terminal.sandbox.enabled") {
				return true, sandboxRefusedPinnedEnabled
			}
			dst.Backends, dst.Enabled = nil, false
			return true, ""
		}
		// The one exception to the filter rule (g1-design.md section 8.3,
		// lane G4): a row the same verified body publishes (the org-hosted
		// gateway) may be added; it stays ExplicitOnly.
		kept, dropped := filterManagedBackends(*p.Backends, dst.Backends, func(id string) bool { return sandboxManagedPublishesRow(p, id) })
		if len(kept) == 0 {
			// Only rows the body may not add: the developer's own list stays.
			return true, sandboxRefusedExplicitOnly
		}
		dst.Backends = kept
		if dropped {
			return true, sandboxRefusedExplicitOnly + sandboxPartialMark
		}
		return true, ""
	}},
	{"terminal.sandbox.default_on", setBool(func(p orgcontract.SandboxManagedPolicyV1) *bool { return p.DefaultOn },
		func(d *config.TerminalSandboxConfig, v bool) { d.DefaultOn = v })},
	{"terminal.sandbox.egress", func(dst *config.TerminalSandboxConfig, p orgcontract.SandboxManagedPolicyV1, _ sandboxManagedEnv) (bool, string) {
		if p.Egress == nil {
			return false, ""
		}
		dst.Egress = *p.Egress
		return true, ""
	}},
	{"terminal.sandbox.egress_allow_cidrs", setList(func(p orgcontract.SandboxManagedPolicyV1) *[]string { return p.EgressAllowCIDRs },
		func(d *config.TerminalSandboxConfig, v []string) { d.EgressAllowCIDRs = v },
		func(v []string, _ sandboxManagedEnv) string {
			if _, err := sandboxcidr.ParseAllowCIDRs(v); err != nil {
				return sandboxRefusedCIDRNotAllowable
			}
			return ""
		})},
	{"terminal.sandbox.allow_tool_config_writes", setBool(func(p orgcontract.SandboxManagedPolicyV1) *bool { return p.AllowToolConfigWrites },
		func(d *config.TerminalSandboxConfig, v bool) { d.AllowToolConfigWrites = v })},
	{"terminal.sandbox.allow_remote_clone", setBool(func(p orgcontract.SandboxManagedPolicyV1) *bool { return p.AllowRemoteClone },
		func(d *config.TerminalSandboxConfig, v bool) { d.AllowRemoteClone = v })},
	{"terminal.sandbox.remote_allowed_hosts", setList(func(p orgcontract.SandboxManagedPolicyV1) *[]string { return p.RemoteAllowedHosts },
		func(d *config.TerminalSandboxConfig, v []string) { d.RemoteAllowedHosts = v }, nil)},
	{"terminal.sandbox.workspace_retention_days", setInt(func(p orgcontract.SandboxManagedPolicyV1) *int { return p.WorkspaceRetentionDays },
		func(d *config.TerminalSandboxConfig, v int) { d.WorkspaceRetentionDays = v })},
	{"terminal.sandbox.mask_paths", setList(func(p orgcontract.SandboxManagedPolicyV1) *[]string { return p.MaskPaths },
		// Managed masks ADD to the developer's own (the union, P1b's
		// DirAdditiveMask): a body never unmasks a path the developer hid.
		func(d *config.TerminalSandboxConfig, v []string) { d.MaskPaths = unionPaths(d.MaskPaths, v) },
		func(v []string, env sandboxManagedEnv) string { return checkManagedPaths(v, false, false, env) })},
	{"terminal.sandbox.prep_timeout_seconds", setInt(func(p orgcontract.SandboxManagedPolicyV1) *int { return p.PrepTimeoutSeconds },
		func(d *config.TerminalSandboxConfig, v int) { d.PrepTimeoutSeconds = v })},
	// The per-node path overrides, validated like a local value. There is no
	// workspaces_dir row: the managed-workspace root stays the developer's
	// own (SBX-P1C merge finding 3, refused by name in the body).
	{"terminal.sandbox.extra_ro_binds", setList(func(p orgcontract.SandboxManagedPolicyV1) *[]string { return nodeOf(p).ExtraROBinds },
		func(d *config.TerminalSandboxConfig, v []string) { d.ExtraROBinds = v },
		func(v []string, env sandboxManagedEnv) string { return checkManagedPaths(v, false, true, env) })},
	{"terminal.sandbox.extra_rw_binds", setList(func(p orgcontract.SandboxManagedPolicyV1) *[]string { return nodeOf(p).ExtraRWBinds },
		func(d *config.TerminalSandboxConfig, v []string) { d.ExtraRWBinds = v },
		func(v []string, env sandboxManagedEnv) string { return checkManagedPaths(v, true, true, env) })},
	// The org-published E2B endpoint (lane SBX-UPD, SBX-GOV-2): data only.
	// It never adds e2b to backends (the developer's list and consent
	// decide), and a credential is sent there only when it was connected
	// for it (SBX-GOV-4); it is the one endpoint that may leave E2B's own
	// domain, because the org, not a file on the node, published it.
	{"terminal.sandbox.hosted.e2b.endpoint", func(dst *config.TerminalSandboxConfig, p orgcontract.SandboxManagedPolicyV1, _ sandboxManagedEnv) (bool, string) {
		e := p.HostedE2B
		if e == nil {
			return false, ""
		}
		dst.Hosted.E2B.Endpoint = strings.ToLower(strings.TrimSuffix(e.Origin, "/"))
		dst.Hosted.E2B.EndpointSPKISHA256 = e.SPKISHA256
		dst.Hosted.E2B.OrgPublished = true
		if e.Template != "" {
			dst.Hosted.E2B.Template = e.Template
		}
		return true, ""
	}},
	// The container sandboxes' install-script floor (lane LEFT-SBX, ruling
	// P-136): restrictive only. The mode can only lower the node's, a tool
	// list narrows it (sandboxoci.FloorScriptPolicy, the one rule), and the
	// org's signed pins are added beside the developer's own. It never turns
	// install_cache on.
	{"terminal.sandbox.oci.install_scripts", func(dst *config.TerminalSandboxConfig, p orgcontract.SandboxManagedPolicyV1, _ sandboxManagedEnv) (bool, string) {
		if p.InstallScripts == nil {
			return false, ""
		}
		return sandboxManagedInstallScriptsFloor(dst, *p.InstallScripts), ""
	}},
	// The org's sign-in seeding forbid (lane BOXSIGNIN, ruling P-180 (6)
	// 6): lowering only. true clears the developer's remembered consent
	// and refuses a per-launch one by name; false or absent leaves the
	// node's own choice (it can never turn seeding on).
	// The org-hosted gateway (lane G4, g1-design.md section 8.1): data only,
	// it never adds the row to backends by itself.
	{sandboxManagedPublishedKey, sandboxManagedComposePublished},
	{"terminal.sandbox.sign_in_seed_tools", func(dst *config.TerminalSandboxConfig, p orgcontract.SandboxManagedPolicyV1, _ sandboxManagedEnv) (bool, string) {
		if p.SignInSeedForbidden == nil || !*p.SignInSeedForbidden {
			return false, ""
		}
		dst.SignInSeedTools, dst.SignInSeedForbidden = nil, true
		return true, ""
	}},
}

// unionPaths is local then every managed entry local does not already list.
func unionPaths(local, managed []string) []string {
	out := append([]string(nil), local...)
	seen := make(map[string]bool, len(out))
	for _, p := range out {
		seen[p] = true
	}
	for _, p := range managed {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// composeSandboxManaged applies body p onto local in table order. A pinned
// key keeps its pinned (local) value; a key whose value the node cannot use
// keeps the local value too; each is reported. The body never touches
// min_isolation (a floor), home_mode, allow_worktree_source or workspaces_dir
// (not on the pull).
func composeSandboxManaged(local config.TerminalSandboxConfig, p orgcontract.SandboxManagedPolicyV1, env sandboxManagedEnv) (config.TerminalSandboxConfig, []SandboxManagedRefusedKey) {
	out := local
	out.Backends = append([]string(nil), local.Backends...)
	var refused []SandboxManagedRefusedKey
	for _, f := range sandboxManagedFields {
		trial := out
		set, why := f.apply(&trial, p, env)
		if !set {
			continue
		}
		if env.pinned != nil && env.pinned(f.key) {
			refused = append(refused, SandboxManagedRefusedKey{Key: f.key, Reason: sandboxRefusedPinned})
			continue
		}
		if why != "" {
			reason, partial := strings.CutSuffix(why, sandboxPartialMark)
			refused = append(refused, SandboxManagedRefusedKey{Key: f.key, Reason: reason, Partial: partial})
			if !partial {
				continue
			}
		}
		out = trial
	}
	return out, refused
}

// checkManagedPaths applies the bind-plan path rules to a managed path list
// (internal/sandbox validateAbs and the relay's observer-dir rule, on the
// written and the resolved spelling). It returns the first refusal reason.
func checkManagedPaths(paths []string, rw, bind bool, env sandboxManagedEnv) string {
	for _, p := range paths {
		if why := checkManagedPath(p, rw); why != "" {
			return why
		}
		if !bind {
			continue
		}
		spellings := []string{filepath.Clean(p)}
		if env.resolve != nil {
			if r := env.resolve(p); r != "" && filepath.Clean(r) != spellings[0] {
				spellings = append(spellings, filepath.Clean(r))
			}
		}
		if why := observerDirExposed(spellings, env); why != "" {
			return why
		}
		if rw && sensitiveWriteBind(spellings, env) {
			return sandboxRefusedSensitive
		}
	}
	return ""
}

// sensitiveWriteBind applies the bind decision's rule (orgcontract) to every
// spelling of a write bind, with this node's real home and own binds.
func sensitiveWriteBind(spellings []string, env sandboxManagedEnv) bool {
	host := orgcontract.SandboxBindHost{Home: filepath.ToSlash(env.home), Known: env.home != "", CaseSensitive: sandboxHostCaseSensitive()}
	for _, b := range env.localRWBinds {
		host.LocalRWBinds = append(host.LocalRWBinds, filepath.ToSlash(filepath.Clean(b)))
	}
	for _, q := range spellings {
		if orgcontract.SandboxSensitiveWriteBind(filepath.ToSlash(q), host) {
			return true
		}
	}
	return false
}

// sandboxHostCaseSensitive reports whether this node compares paths
// case-sensitively (ruling P-054: macOS and Windows do not; a WSL drive mount
// never does, which the rule itself knows). A seam for tests.
var sandboxHostCaseSensitive = func() bool { return runtime.GOOS != "darwin" && runtime.GOOS != "windows" }

// sandboxManagedOrgRWBinds is the write binds an in-force managed body p set
// on this node (its per-node extra_rw_binds, native spelling), or nil when p
// is nil, sets none, or the key was refused (the developer's own binds then
// stand). The launch re-binds each one's repository hooks and config
// read-only (ruling P-054, SBX-P2E audit finding 8).
func sandboxManagedOrgRWBinds(p *orgcontract.SandboxManagedPolicyV1, refused []SandboxManagedRefusedKey) []string {
	if p == nil || p.Node == nil || p.Node.ExtraRWBinds == nil {
		return nil
	}
	for _, r := range refused {
		if r.Key == "terminal.sandbox.extra_rw_binds" {
			return nil
		}
	}
	var out []string
	for _, b := range *p.Node.ExtraRWBinds {
		out = append(out, filepath.Clean(filepath.FromSlash(b)))
	}
	return out
}

// sandboxOrgBinds is what an in-force managed body set on this node's write
// binds: the binds themselves (rw) and the ones the org asserts hold no
// repositories (skipScan, a subset of rw).
type sandboxOrgBinds struct {
	rw       []string
	skipScan []string
}

// sandboxManagedOrgBindsFor is sandboxManagedOrgRWBinds plus the binds
// node.skip_repo_scan names (ruling P-060, ledger SBX-GOV-3): only entries
// that are one of the applied org write binds, so a refused extra_rw_binds
// key takes its skip list with it and the developer's own binds are always
// walked.
func sandboxManagedOrgBindsFor(p *orgcontract.SandboxManagedPolicyV1, refused []SandboxManagedRefusedKey) sandboxOrgBinds {
	out := sandboxOrgBinds{rw: sandboxManagedOrgRWBinds(p, refused)}
	if out.rw == nil || p.Node.SkipRepoScan == nil {
		return out
	}
	for _, e := range *p.Node.SkipRepoScan {
		c := filepath.Clean(filepath.FromSlash(e))
		if slices.Contains(out.rw, c) && !slices.Contains(out.skipScan, c) {
			out.skipScan = append(out.skipScan, c)
		}
	}
	return out
}

// effectiveSandboxOrgBinds is sandboxManagedOrgBindsFor for the daemon's
// in-force body (effectiveSandboxConfig's composition).
func effectiveSandboxOrgBinds(full config.Config) sandboxOrgBinds {
	p, pins := processSandboxManaged.snapshot(context.Background(), time.Now())
	if p == nil {
		return sandboxOrgBinds{}
	}
	_, refused := composeSandboxManaged(full.Terminal.Sandbox, *p, sandboxManagedEnvFor(full, pins))
	return sandboxManagedOrgBindsFor(p, refused)
}

// sandboxSkipRepoScanLabel is how every surface names the org's assertion.
const sandboxSkipRepoScanLabel = "Repository check skipped (the organization asserts these write binds hold no repositories)"

// sandboxSkipRepoScanDoctorChecks is doctor's line for node.skip_repo_scan
// (ruling P-060: doctor says when it is set), read from the stored document
// like `observer sandbox status` and composed with pins, the governance pins
// in force (the ones `observer sandbox status` and the CLI launch compose
// with), so a pinned extra_rw_binds key that refuses the org's binds also
// drops their skip (audit finding 5 of lane SHR-FOLLOWUPS). pinsKnown is
// false when doctor could not read those pins; the line then says it shows
// the body as served. Nothing when no in-force body sets it.
func sandboxSkipRepoScanDoctorChecks(ctx context.Context, cfg config.Config, pins map[string]any, pinsKnown bool) []diag.Check {
	_, org := cliEffectiveSandbox(ctx, cfg, pins)
	return sandboxSkipRepoScanDoctorLine(org.skipScan, pinsKnown)
}

// sandboxSkipRepoScanDoctorLine renders doctor's skip_repo_scan check from
// the binds the composed launch skips.
func sandboxSkipRepoScanDoctorLine(skip []string, pinsKnown bool) []diag.Check {
	if len(skip) == 0 {
		return nil
	}
	msg := "the organization asserts " + strings.Join(skip, ", ") +
		" hold no repositories; the walk for repositories below them is skipped (the bind itself is still checked)"
	if !pinsKnown {
		msg += "; as served by the organization, before this node's own pins (the governance pins could not be read here)"
	}
	return []diag.Check{{Name: "sandbox.org_bind_scan", Status: diag.StatusOK, Message: msg}}
}

// sandboxDoctorGovernancePins reads the governance pins in force the way
// `observer sandbox status` and the CLI launch do (config.LoadGovernance on
// the same config path); ok is false when the config cannot be loaded.
func sandboxDoctorGovernancePins(configPath string) (map[string]any, bool) {
	_, gov, err := config.LoadGovernance(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return nil, false
	}
	return gov.PinsInForce, true
}

// observerDirExposed is the relay's observer-dir rule on every spelling: no
// bind may be the observer directory, lie inside it outside its workspaces
// tree, or contain it.
func observerDirExposed(spellings []string, env sandboxManagedEnv) string {
	if env.observerDir != "" {
		obs := []string{filepath.Clean(env.observerDir)}
		if env.resolve != nil {
			if r := env.resolve(env.observerDir); r != "" && filepath.Clean(r) != obs[0] {
				obs = append(obs, filepath.Clean(r))
			}
		}
		for _, q := range spellings {
			for _, o := range obs {
				if pathWithin(o, q) || (pathWithin(q, o) && !pathWithin(q, filepath.Join(o, "workspaces"))) {
					return sandboxRefusedObserverDir
				}
			}
		}
	}
	return ""
}

// checkManagedPath is validateAbs's rule set (internal/sandbox/plan.go).
func checkManagedPath(p string, rw bool) string {
	switch {
	case strings.HasPrefix(p, "-"):
		return sandboxRefusedLeadingDash
	case strings.IndexFunc(p, func(r rune) bool { return r == 0 || unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
		return sandboxRefusedBadCharacter
	case hasDotDotSegment(p):
		return sandboxRefusedDotDot
	case !filepath.IsAbs(p):
		return sandboxRefusedNotAbsolute
	case rw && wholeRootPath(p):
		return sandboxRefusedWholeRoot
	}
	return ""
}

// wholeRootPath reports a path that is a whole file system root: "/" on
// POSIX, a drive root ("C:\") or a share root ("\\host\share\") on Windows.
// Before, only "/" was refused, so a Windows node took a writable bind of
// C:\ (WINFIX4 audit, TestComposeSandboxManagedNodePathRules).
func wholeRootPath(p string) bool {
	c := filepath.Clean(p)
	rest := c[len(filepath.VolumeName(c)):]
	return rest == "" || rest == string(filepath.Separator) || rest == "/"
}

func hasDotDotSegment(p string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// pathWithin reports whether child is parent or lies inside it.
func pathWithin(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// sandboxManagedRailStatus is the rail's state as `observer sandbox status`
// shows it.
type sandboxManagedRailStatus struct {
	// State is one of in_force, not_preauthorized, expired, not_supported,
	// cleared, not_enrolled, unverified, refused.
	State     string                     `json:"state"`
	Version   int64                      `json:"version,omitempty"`
	ExpiresAt string                     `json:"expires_at,omitempty"`
	Applied   []string                   `json:"applied,omitempty"`
	Refused   []SandboxManagedRefusedKey `json:"refused,omitempty"`
	Detail    string                     `json:"detail,omitempty"`
	// SkipRepoScan are the applied org write binds the organization
	// asserts hold no repositories (node.skip_repo_scan, ruling P-060).
	SkipRepoScan []string `json:"skip_repo_scan,omitempty"`
}

// The rail states the status shows.
const (
	sandboxRailInForce          = "in_force"
	sandboxRailNotPreauthorized = "not_preauthorized"
	sandboxRailExpired          = "expired"
	sandboxRailNotSupported     = "not_supported"
	sandboxRailCleared          = "cleared"
	sandboxRailNotEnrolled      = "not_enrolled"
	sandboxRailRefused          = "refused"
	sandboxRailUnverified       = "unverified"
)

// sandboxRailFacts is what the status decision reads.
type sandboxRailFacts struct {
	enrolled  bool
	haveRow   bool
	tombstone bool
	outcome   orgclient.ManagedPullOutcome
	bodyErr   string
	now       int64
	// lacksAuthority: a managed grant without enforce.sandbox (F-B2).
	lacksAuthority bool
}

// sandboxRailStatusRows decides the shown state, top-down (CLAUDE.md #5).
var sandboxRailStatusRows = []struct {
	match func(sandboxRailFacts) bool
	state string
}{
	{func(f sandboxRailFacts) bool { return !f.enrolled }, sandboxRailNotEnrolled},
	{func(f sandboxRailFacts) bool { return f.tombstone }, sandboxRailCleared},
	{func(f sandboxRailFacts) bool { return !f.haveRow }, sandboxRailNotSupported},
	// A stored document that no longer verifies (the org key rotated): it
	// can never apply.
	{func(f sandboxRailFacts) bool { return f.outcome.Version == 0 }, sandboxRailUnverified},
	{func(f sandboxRailFacts) bool { return f.outcome.ExpiresAt <= f.now }, sandboxRailExpired},
	{func(f sandboxRailFacts) bool { return !f.outcome.InForce }, sandboxRailNotPreauthorized},
	{func(f sandboxRailFacts) bool { return f.bodyErr != "" }, sandboxRailRefused},
	{func(sandboxRailFacts) bool { return true }, sandboxRailInForce},
}

func decideSandboxRailState(f sandboxRailFacts) string {
	for _, r := range sandboxRailStatusRows {
		if r.match(f) {
			return r.state
		}
	}
	return sandboxRailNotSupported
}

// sandboxManagedStatus reads the rail's stored document the way the daemon
// does at start (re-verified against the pinned org key, consent from the
// honoured grant) and reports its state and what it changes on local cfg.
// pins are the governance sidecar's pins in force cfg was loaded under
// (config.GovernanceOutcome.PinsInForce), so a pinned key shows as refused
// here exactly as on the daemon path (SBX-P1C merge finding 2). It makes no
// request.
func sandboxManagedStatus(ctx context.Context, cfg config.Config, pins map[string]any) sandboxManagedRailStatus {
	st, cleanup, err := openSandboxManagedStore(ctx, cfg)
	if err != nil {
		return sandboxManagedRailStatus{State: sandboxRailNotEnrolled, Detail: "the node database could not be opened"}
	}
	defer cleanup()
	out, facts := loadSandboxManagedFacts(ctx, cfg, st)
	status := sandboxManagedRailStatus{State: decideSandboxRailState(facts)}
	if facts.haveRow && !facts.tombstone && out.Version > 0 {
		status.Version = out.Version
		status.ExpiresAt = time.Unix(out.ExpiresAt, 0).UTC().Format(time.RFC3339)
	}
	status.Detail = facts.bodyErr
	if status.State != sandboxRailInForce {
		return status
	}
	p, err := orgcontract.DecodeSandboxManagedPolicy(out.Body)
	if err != nil {
		status.State, status.Detail = sandboxRailRefused, err.Error()
		return status
	}
	env := sandboxManagedEnvFor(cfg, pins)
	_, status.Refused = composeSandboxManaged(cfg.Terminal.Sandbox, p, env)
	status.Applied = sandboxManagedApplied(p, env, status.Refused)
	status.SkipRepoScan = sandboxManagedOrgBindsFor(&p, status.Refused).skipScan
	return status
}

// sandboxManagedApplied lists the full keys body p sets that composition did
// not refuse, in table order (a key applied in part, with a partial
// refusal reason, is listed too).
func sandboxManagedApplied(p orgcontract.SandboxManagedPolicyV1, env sandboxManagedEnv, refused []SandboxManagedRefusedKey) []string {
	skip := map[string]bool{}
	for _, r := range refused {
		// A partial refusal (the filtered backends row) still applied.
		skip[r.Key] = skip[r.Key] || !r.Partial
	}
	var out []string
	for _, f := range sandboxManagedFields {
		var probe config.TerminalSandboxConfig
		if set, _ := f.apply(&probe, p, env); set && !skip[f.key] {
			out = append(out, f.key)
		}
	}
	return out
}

// cliEffectiveSandboxConfig is the CLI launch's effective [terminal.sandbox]:
// the same composition as the daemon's, from the stored document (a CLI
// process polls nothing), with the governance sidecar's pins in force cfg was
// loaded under (SBX-P1C merge finding 2).
func cliEffectiveSandboxConfig(ctx context.Context, cfg config.Config, pins map[string]any) config.TerminalSandboxConfig {
	eff, _ := cliEffectiveSandbox(ctx, cfg, pins)
	return eff
}

// cliEffectiveSandbox is cliEffectiveSandboxConfig plus the write binds the
// in-force body set (sandboxManagedOrgBindsFor), for the CLI launch.
func cliEffectiveSandbox(ctx context.Context, cfg config.Config, pins map[string]any) (config.TerminalSandboxConfig, sandboxOrgBinds) {
	if !sandboxModuleActive(componentSnapshotForConfig(cfg)) {
		return cfg.Terminal.Sandbox, sandboxOrgBinds{}
	}
	st, cleanup, err := openSandboxManagedStore(ctx, cfg)
	if err != nil {
		return cfg.Terminal.Sandbox, sandboxOrgBinds{}
	}
	defer cleanup()
	out, facts := loadSandboxManagedFacts(ctx, cfg, st)
	if decideSandboxRailState(facts) != sandboxRailInForce {
		eff := cfg.Terminal.Sandbox
		sandboxManagedNoteAuthority(&eff, facts.lacksAuthority)
		return eff, sandboxOrgBinds{}
	}
	p, err := orgcontract.DecodeSandboxManagedPolicy(out.Body)
	if err != nil {
		return cfg.Terminal.Sandbox, sandboxOrgBinds{}
	}
	eff, refused := composeSandboxManaged(cfg.Terminal.Sandbox, p, sandboxManagedEnvFor(cfg, pins))
	return eff, sandboxManagedOrgBindsFor(&p, refused)
}

// openSandboxManagedStore opens the node database read-side for a CLI read.
// A node with no database yet has nothing stored.
func openSandboxManagedStore(ctx context.Context, cfg config.Config) (*store.Store, func(), error) {
	if cfg.Observer.DBPath == "" {
		return nil, nil, errors.New("no database path")
	}
	if _, err := os.Stat(cfg.Observer.DBPath); err != nil {
		return nil, nil, fmt.Errorf("sandbox managed: %w", err)
	}
	database, cleanup, err := openDBForConfig(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	return store.New(database), cleanup, nil
}

// loadSandboxManagedFacts reads the stored rail document and the consent
// (the grant alone decides it; the pins come from the caller's load).
func loadSandboxManagedFacts(ctx context.Context, cfg config.Config, st *store.Store) (orgclient.ManagedPullOutcome, sandboxRailFacts) {
	facts := sandboxRailFacts{now: time.Now().Unix()}
	rail, _ := orgcontract.LookupManagedPullRail(sandboxManagedRail)
	var eff govern.Effective
	if loader := governanceIdentityLoader(st); loader != nil {
		if grant, live, err := loader(ctx); err == nil && grant != nil {
			eff = govern.Resolve(govern.Delivered{}, grant, live, time.Now().UTC())
		}
	}
	facts.lacksAuthority = sandboxAuthorityMissing(eff)
	client := orgclient.New(cfg.OrgClient, st, nil, "", nil, nil)
	out, err := client.LoadPersistedManagedPull(ctx, sandboxManagedRail, managedPullConsent(eff, rail))
	if err != nil {
		return out, facts
	}
	facts.enrolled = true
	facts.outcome = out
	if enr, eerr := st.LoadEnrolment(ctx); eerr == nil && enr != nil {
		orgKey := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
		if gen, ok, gerr := st.LoadEnrolmentGeneration(ctx, orgKey); gerr == nil && ok {
			if row, have, lerr := st.LoadManagedPull(ctx, sandboxManagedRail, orgKey, gen.Generation); lerr == nil && have {
				facts.haveRow, facts.tombstone = true, row.Tombstone
			}
		}
	}
	if out.InForce && len(out.Body) > 0 {
		if _, derr := orgcontract.DecodeSandboxManagedPolicy(out.Body); derr != nil {
			facts.bodyErr = derr.Error()
		}
	}
	return out, facts
}

// sandboxManagedStatusLines is the one-line copy per rail state.
var sandboxManagedStatusLines = map[string]string{
	sandboxRailInForce:          "Organization managed settings: in force",
	sandboxRailNotPreauthorized: "Organization managed settings: received but not applied (not_preauthorized: this enrolment's grant does not hold enforce.sandbox)",
	sandboxRailExpired:          "Organization managed settings: expired; this machine's own settings apply",
	sandboxRailNotSupported:     "Organization managed settings: none published to this node (not_supported); this machine's own settings apply",
	sandboxRailCleared:          "Organization managed settings: cleared by the organization; this machine's own settings apply",
	sandboxRailNotEnrolled:      "Organization managed settings: not enrolled in an organization",
	sandboxRailUnverified:       "Organization managed settings: the stored document no longer verifies (unverified); this machine's own settings apply",
	sandboxRailRefused:          "Organization managed settings: refused (the body does not validate); this machine's own settings apply",
}

// sandboxManagedStatusLine renders the rail state for `observer sandbox
// status`.
func sandboxManagedStatusLine(s sandboxManagedRailStatus) string {
	line := sandboxManagedStatusLines[s.State]
	if line == "" {
		line = "Organization managed settings: " + s.State
	}
	if s.Version > 0 {
		line += fmt.Sprintf(" (version %d, expires %s)", s.Version, s.ExpiresAt)
	}
	if len(s.Applied) > 0 {
		line += "\n  set by the organization: " + strings.Join(s.Applied, ", ")
	}
	for _, r := range s.Refused {
		line += "\n  not applied: " + r.Key + " (" + r.Reason + ")"
	}
	if len(s.SkipRepoScan) > 0 {
		line += "\n  repository check skipped (the organization asserts no repositories): " + strings.Join(s.SkipRepoScan, ", ")
	}
	return line
}

// sandboxManagedRefusedForPush is the body keys the in-force managed body
// could not apply on this node, with their closed reasons, for the push
// wire (SandboxCapabilityRow.ManagedRefused, SBX-P2E): the org's developer
// page shows why a node refused a path the admin set. nil when no body is
// in force, so an individual node and a managed node without the rail do no
// work beyond the overlay check. A seam for tests.
var sandboxManagedRefusedForPush = func(ctx context.Context) []orgcontract.SandboxManagedRefusedKeyRow {
	p, pins := processSandboxManaged.snapshot(ctx, time.Now())
	if p == nil {
		return nil
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: daemonConfigPath()})
	if err != nil {
		return nil
	}
	_, refused := composeSandboxManaged(cfg.Terminal.Sandbox, *p, sandboxManagedEnvFor(cfg, pins))
	return sandboxManagedRefusedRows(refused)
}

// sandboxManagedRefusedRows maps the node's refusals onto the wire rows (the
// key without its prefix), clamped to the wire's closed sets.
func sandboxManagedRefusedRows(refused []SandboxManagedRefusedKey) []orgcontract.SandboxManagedRefusedKeyRow {
	var out []orgcontract.SandboxManagedRefusedKeyRow
	for _, r := range refused {
		out = append(out, orgcontract.SandboxManagedRefusedKeyRow{Key: strings.TrimPrefix(r.Key, sandboxPinPrefix), Reason: r.Reason})
	}
	return orgcontract.ClampSandboxManagedRefused(out)
}
