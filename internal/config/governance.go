package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern/sidecar"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/postureop"
	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// Admin-controlled Plane B, Phase 1b: the config half of the governance
// sidecar (docs/plans/admin-controlled-plane-b-phase-1b-mini-spec-2026-08-15.md
// §1.2/§1.3).
//
// The package split is deliberate (review m1): internal/govern/sidecar is
// stdlib-only because it is read on the hook path, so the PATH RESOLVER —
// which needs a Config — and the PER-KEY RULES — which need the config
// shape — live here, beside ResolveGlobalPath, which is the existing
// precedent for "a path resolver that needs a Config".

// GovernanceSidecarFilename is the sidecar's basename. It sits BESIDE the
// database rather than inside policy-resource/<org_key>/<gen>/ deliberately:
// a reader must be able to find it WITHOUT resolving an org key, which is
// the whole point. The name is distinct from node.governance.json (the
// signed LKG resource cache) so nobody confuses the DELIVERED body with the
// RESOLVED, grant-intersected posture.
const GovernanceSidecarFilename = "governance-effective.json"

// NoGovernanceSidecar disables the sidecar read entirely. It is used by the
// solo-parity invariant test and by `observer config show --local`, which
// must be able to show what the machine would do with no organization at
// all. It is a sentinel rather than a bool so LoadOptions keeps exactly one
// governance field.
const NoGovernanceSidecar = "\x00none"

// FeaturesSidecarFilename is the node-local node.features tools.disallow LKG
// sidecar (P7 gateway-arc / P6 item 5), placed beside the DB exactly like the
// governance sidecar so a WSL-daemon / Windows-tool bridge resolves the same
// file, and so a bare CLI launcher and `observer adapters` see the live
// disallow list without the daemon.
const FeaturesSidecarFilename = "features-effective.json"

// NoFeaturesSidecar is the FeaturesSidecar override that disables the sidecar
// entirely (mirrors NoGovernanceSidecar).
const NoFeaturesSidecar = "\x00none"

// ResolveFeaturesSidecarPath returns the node.features LKG sidecar path,
// derived from the DB path exactly like ResolveGovernanceSidecarPath. The same
// local-escape caveat applies (advisory on processes the org does not own).
func ResolveFeaturesSidecarPath(cfg Config, override string) string {
	if override == NoFeaturesSidecar {
		return ""
	}
	if override != "" {
		return override
	}
	dbPath := expandHome(cfg.Observer.DBPath)
	if strings.TrimSpace(dbPath) == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(dbPath), FeaturesSidecarFilename)
}

// ResolveGovernanceSidecarPath returns the sidecar path Load would use.
//
// It is derived from the DB path, which the developer controls through the
// global TOML, a project TOML and the env. That is a real, cheap, local
// escape and it is NOT claimed otherwise: §1.8 concedes the whole class
// (the sidecar is advisory on processes the organization does not own). The
// derivation is kept because it is what makes the file converge with the DB
// under the documented WSL-daemon / Windows-tool hook bridge — the hook
// executes in the daemon's OS context and resolves the daemon's own sidecar
// natively.
func ResolveGovernanceSidecarPath(cfg Config, override string) string {
	if override == NoGovernanceSidecar {
		return ""
	}
	if override != "" {
		return override
	}
	dbPath := expandHome(cfg.Observer.DBPath)
	if strings.TrimSpace(dbPath) == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(dbPath), GovernanceSidecarFilename)
}

// governancePinnableKey mirrors one row of
// internal/policyfam/nodegov.PinnableKeys.
//
// It is a HAND COPY for the same reason policyResourceSupportedFamilies is:
// internal/config must not import the policy layer at runtime. The copy is
// kept honest by TestPinnableKeysMirrorInSyncWithPolicyfam, in the shape of
// the existing policyfam_sync_test.go — a test-only import closes the drift
// class without coupling the packages.
type governancePinnableKey struct {
	Key       string
	Kind      string
	Enum      []any
	Direction string
	Safe      any
	// Format mirrors nodegov.PinnableKey.Format (postureop.CheckFormat).
	Format string
	// Min / Max are an int row's inclusive bounds (both zero = unbounded).
	Min, Max int64
	// Hot mirrors nodegov.PinnableKey.Hot (the daemon also applies the key
	// live, so it is excluded from the pending_restart comparison).
	Hot bool
}

// The direction names are postureop's (roadmap F0-8): the same table
// nodegov.compilePinned walks at publish and accept, imported here because
// internal/postureop is a stdlib-only leaf, which internal/config may import
// (the policy layer it may not).
const (
	governanceDirFree            = string(postureop.DirFree)
	governanceDirRestrictiveOnly = string(postureop.DirRestrictiveOnly)
	// governanceDirLoweringOnly is the numeric CEILING direction for an int
	// row: the org value applies unless the node's own value is already
	// lower (postureop.LowerInt).
	governanceDirLoweringOnly = string(postureop.DirLoweringOnly)
)

// GovernanceHotKey reports whether a pinnable key is applied live by the
// daemon (see governancePinnableKey.Hot). cmd/observer uses it to keep hot
// keys out of the pending_restart comparison.
func GovernanceHotKey(key string) bool {
	row, ok := governancePinnableByKey[key]
	return ok && row.Hot
}

// GovernanceLowerInt composes a node's own int value with an org CEILING:
// a positive local value below the org's wins, anything else takes the org's
// value. Zero/negative org means "no directive" and returns local. It is the
// one definition the config overlay AND the daemon's live re-application use,
// so the restart-time and the hot value can never disagree.
func GovernanceLowerInt(local, org int64) int64 {
	return postureop.LowerInt(local, org)
}

// GovernancePinnedPushInterval returns the org's push-interval ceiling from a
// resolved pinned map, or 0 when the map carries none (or a value outside the
// row's bounds). It is the daemon's hot-apply read: the push loop composes it
// with its own configured interval through GovernanceLowerInt.
func GovernancePinnedPushInterval(pinned map[string]any) int64 {
	const key = "org_client.push_interval_seconds"
	raw, ok := pinned[key]
	if !ok {
		return 0
	}
	row := governancePinnableByKey[key]
	norm, err := coerceGovernanceValue(row.Kind, raw)
	if err != nil {
		return 0
	}
	n, _ := norm.(int64)
	if n < row.Min || n > row.Max {
		return 0
	}
	return n
}

// governancePinnableKeys is the mirror. Order is irrelevant (it is indexed
// below); the SET and each row's Kind/Enum/Direction/Safe are what the sync
// test pins.
var governancePinnableKeys = []governancePinnableKey{
	{Key: "guard.enabled", Kind: "bool", Direction: governanceDirFree},
	{Key: "guard.mode", Kind: "string", Enum: []any{"off", "observe", "enforce"}, Direction: governanceDirFree},
	// guard.strict mirrors internal/policyfam/nodegov.PinnableKeys' row: a
	// fail-posture choice (fail-open vs fail-closed on judge/policy-engine
	// internal error), not a privacy-sharing direction, so it is free like
	// guard.mode rather than restrictive-only like the scrubbing toggle
	// below.
	{Key: "guard.strict", Kind: "bool", Direction: governanceDirFree},
	// The org-budget posture pair (org-budget plan §3.3a). Mirrors
	// nodegov.PinnableKeys row for row: guard.budget.hard is restrictive-only
	// with Safe=true (the restrictive value of a spend-BLOCKING flag is true),
	// guard.budget.from_org is free (whether to apply the org's budget here at
	// all is a posture, and the lowering-only direction of an applied org
	// budget is enforced by govern.LowerFloat/LowerInt, not by this row).
	{Key: "guard.budget.hard", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: true},
	{Key: "guard.budget.from_org", Kind: "bool", Direction: governanceDirFree},
	// guard.budget.fail_closed (D-502): the org's explicit opt-in to B-625
	// refusing traffic while no verified budget is in hand. Restrictive-only,
	// Safe=true: the org may turn blocking ON, never force it off.
	{Key: "guard.budget.fail_closed", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: true},
	{Key: "observer.secrets.enable_scrubbing", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: true},
	{Key: "compression.conversation.enabled", Kind: "bool", Direction: governanceDirFree},
	{Key: "codeintel.enabled", Kind: "bool", Direction: governanceDirFree},
	{Key: "cachetrack.enabled", Kind: "bool", Direction: governanceDirFree},
	{Key: "predict.enabled", Kind: "bool", Direction: governanceDirFree},
	{Key: "tasks.enabled", Kind: "bool", Direction: governanceDirFree},
	{Key: "browser.enabled", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: false},
	{Key: "observer.process.enabled", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: false},
	{Key: "remote.enabled", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: false},
	// routing.enabled mirrors nodegov.PinnableKeys' row (W5,
	// docs/plans/org-observer-fundamentals-fix-plan-2026-09-13.md R4): a
	// plain posture toggle, free like guard.budget.from_org. routing.mode
	// is NOT here — it stays on the separate signed org routing-policy body,
	// gated by govern.Effective.GrantsRoutingEnforcement (enforce.routing).
	{Key: "routing.enabled", Kind: "bool", Direction: governanceDirFree},
	// org_client.push_interval_seconds mirrors nodegov.PinnableKeys' row
	// (2026-10-02 budget-latency arc): an int CEILING, lowering-only, bounded
	// 30..3600, hot.
	{Key: "org_client.push_interval_seconds", Kind: "int", Direction: governanceDirLoweringOnly, Min: 30, Max: 3600, Hot: true},
	// proxy.maintain_routes mirrors nodegov.PinnableKeys' row (lane P1): the
	// admin's managed route-maintenance switch, free, hot.
	{Key: "proxy.maintain_routes", Kind: "bool", Direction: governanceDirFree, Hot: true},
	// shell_wrap.org_maintain mirrors nodegov.PinnableKeys' row (CLI-1b,
	// D6): the admin's managed command-wrapping switch, free, hot.
	{Key: "shell_wrap.org_maintain", Kind: "bool", Direction: governanceDirFree, Hot: true},
	// The sandboxed-terminal rows mirror nodegov.PinnableKeys (lane SBX-P1B,
	// sandbox plan v2 section 10.1).
	{Key: "terminal.sandbox.backends", Kind: "string_list", Direction: string(postureop.DirOrderedFilter)},
	{Key: "terminal.sandbox.remote_allowed_hosts", Kind: "string_list", Direction: string(postureop.DirSetIntersection)},
	{Key: "terminal.sandbox.mask_paths", Kind: "string_list", Direction: string(postureop.DirAdditiveMask)},
	{Key: "terminal.sandbox.workspace_retention_days", Kind: "int", Direction: string(postureop.DirRetention), Max: 3650},
	{Key: "terminal.sandbox.home_mode", Kind: "string", Enum: []any{"tmpfs", "readonly"}, Direction: governanceDirRestrictiveOnly, Safe: "tmpfs"},
	{Key: "terminal.sandbox.default_on", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: true},
	{Key: "terminal.sandbox.allow_remote_clone", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: false},
	{Key: "terminal.sandbox.allow_worktree_source", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: false},
	{Key: "terminal.sandbox.allow_tool_config_writes", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: false},
	{Key: "terminal.sandbox.egress_allow_cidrs", Kind: "string_list", Direction: governanceDirRestrictiveOnly, Safe: []string{}},
	// The agent-run host allow-list (lane LEFT-SBX): an org list narrows the
	// node's (an empty node list takes the org's); nothing in common allows
	// no host (governanceEmptied).
	{Key: "terminal.sandbox.egress_allow_hosts", Kind: "string_list", Direction: string(postureop.DirSetIntersection)},
	{Key: "terminal.sandbox.extra_ro_binds", Kind: "string_list", Direction: governanceDirRestrictiveOnly, Safe: []string{}},
	{Key: "terminal.sandbox.extra_rw_binds", Kind: "string_list", Direction: governanceDirRestrictiveOnly, Safe: []string{}},
	{Key: "terminal.sandbox.prep_timeout_seconds", Kind: "int", Direction: governanceDirFree, Min: 30, Max: 3600},
	// lane SBX-P3D: both values keep isolation, so the org may pin either.
	{Key: "terminal.sandbox.vendor_forced_native", Kind: "string", Enum: []any{"nest_or_refuse", "refuse"}, Direction: governanceDirFree},
	// Lane SBX-UPD: how soon a deferred update asks (neither value ends a run).
	{Key: "terminal.sandbox.live_run_update_policy", Kind: "string", Enum: []any{"defer", "ask_immediately"}, Direction: governanceDirFree},
	// The container driver's rows (lane SBX-P3A).
	{Key: "terminal.sandbox.oci.allow_rootful", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: false},
	{Key: "terminal.sandbox.oci.allow_devcontainer_image", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: false},
	// The first-start install cache (lane SBX-P3C).
	{Key: "terminal.sandbox.oci.install_cache", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: false},
	// The install-script allowance (lane LEFT-SBX, ruling P-136): none is safe.
	{Key: "terminal.sandbox.oci.install_scripts", Kind: "string", Enum: []any{"none", "pinned"}, Direction: governanceDirRestrictiveOnly, Safe: "none"},
	{Key: "terminal.sandbox.oci.podman_userns", Kind: "string", Enum: []any{"keep-id", "default"}, Direction: governanceDirFree},
	{Key: "terminal.sandbox.oci.stop_grace_seconds", Kind: "int", Direction: governanceDirFree, Min: 0, Max: 600},
	// The org image pins (lane SBX-P3B): only an image pinned by digest.
	{Key: "terminal.sandbox.oci.image", Kind: "string", Direction: governanceDirFree, Format: postureop.FormatImageDigestRef},
	{Key: "terminal.sandbox.apple_container.image", Kind: "string", Direction: governanceDirFree, Format: postureop.FormatImageDigestRef},
	{Key: "terminal.sandbox.mxc.stop_grace_seconds", Kind: "int", Direction: governanceDirFree, Min: 0, Max: 600},
	{Key: "terminal.sandbox.mxc.probe_timeout_seconds", Kind: "int", Direction: governanceDirFree, Min: 5, Max: 300},
	// The macOS drivers' rows (lane SBX-P5).
	{Key: "terminal.sandbox.seatbelt.allow_keychain", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: false},
	// Lane SBX-UPD: an org may hold the node on the built driver only.
	{Key: "terminal.sandbox.seatbelt.driver", Kind: "string", Enum: []any{"sandbox-exec", "mxc-exec-mac"}, Direction: governanceDirRestrictiveOnly, Safe: "sandbox-exec"},
	{Key: "terminal.sandbox.apple_container.memory_mib", Kind: "int", Direction: governanceDirFree, Min: 512, Max: 262144},
	{Key: "terminal.sandbox.apple_container.cpus", Kind: "int", Direction: governanceDirFree, Min: 1, Max: 64},
	// The Landlock-only row's floor (lane SBX-P3B): an org may only raise it.
	{Key: "terminal.sandbox.landlock.min_abi", Kind: "int", Direction: string(postureop.DirRaisingOnly), Min: 9, Max: 64},
	// The hosted rows' shared settings (lane SBX-P7).
	{Key: "terminal.sandbox.hosted.min_session_minutes", Kind: "int", Direction: governanceDirLoweringOnly, Min: 5, Max: 1440},
	{Key: "terminal.sandbox.hosted.max_run_minutes", Kind: "int", Direction: governanceDirLoweringOnly, Min: 5, Max: 1440},
	{Key: "terminal.sandbox.hosted.daily_box_minutes", Kind: "int", Direction: governanceDirLoweringOnly, Min: 5, Max: 10080},
	{Key: "terminal.sandbox.hosted.checkpoint_minutes", Kind: "int", Direction: governanceDirLoweringOnly, Min: 1, Max: 60},
	{Key: "terminal.sandbox.hosted.memory_images", Kind: "string", Enum: []any{"avoid", "refuse"}, Direction: governanceDirRestrictiveOnly, Safe: "refuse"},
	// The opt-in in-box database export (ruling P-141): an org may only
	// keep it off.
	{Key: "terminal.sandbox.hosted.db_export", Kind: "bool", Direction: governanceDirRestrictiveOnly, Safe: false},
	// Local re-adoption (lane GATES-SBX, R-034): an org may only shorten
	// the bound and shrink the checkpoint cap.
	{Key: "terminal.sandbox.readopt.bound_minutes", Kind: "int", Direction: governanceDirLoweringOnly, Min: 1, Max: 1440},
	{Key: "terminal.sandbox.readopt.checkpoint_cap_mib", Kind: "int", Direction: governanceDirLoweringOnly, Min: 1, Max: 1 << 20},
	// The MXC tier floor (R-034): an org may only pin ProcessContainer.
	{Key: "terminal.sandbox.windows.mxc_tier", Kind: "string", Enum: []any{"process_container", "appcontainer"}, Direction: governanceDirRestrictiveOnly, Safe: "process_container"},
	// The direct provider egress posture (DEC-9, OBS-8a): free, because it
	// takes effect only on a managed node (sandboxProviderDirectInForce).
	{Key: SandboxProviderDirectKey, Kind: "string", Enum: []any{"refuse_all", "capture_rule", "allow"}, Direction: governanceDirFree},
}

// SandboxProviderDirectKey is the node.governance pinnable key for the
// organization's direct provider egress posture (DEC-9; nodegov PinnableKeys
// row of the same name).
const SandboxProviderDirectKey = "terminal.sandbox.provider_direct"

// sandboxProviderDirectInForce resolves what a sandboxed launch applies for
// SandboxProviderDirectKey (DEC-9): the organization's pin, only when the
// overlay applied it AND this node's verified org lock records managed
// tenancy; capture_rule otherwise. An individual node (or a node whose lock
// does not verify) keeps today's behaviour whatever its own file or a pin
// says, and a managed node's own file value is never read: on a managed node
// the organization decides, and only through its signed pin.
func sandboxProviderDirectInForce(cfg Config, out GovernanceOutcome) string {
	managed := cfg.Guard.Lock.TenancyKnown && cfg.Guard.Lock.Managed
	if !managed || out.Discarded {
		return string(sandboxvocab.ProviderDirectCaptureRule)
	}
	for _, k := range out.Applied {
		if k == SandboxProviderDirectKey {
			return string(sandboxvocab.ProviderDirect(cfg.Terminal.Sandbox.ProviderDirect).Normalize())
		}
	}
	return string(sandboxvocab.ProviderDirectCaptureRule)
}

// EffectiveProviderDirect is the direct provider egress posture a launch
// applies (ProviderDirectInForce, normalized: "" reads capture_rule).
func (c TerminalSandboxConfig) EffectiveProviderDirect() sandboxvocab.ProviderDirect {
	return sandboxvocab.ProviderDirect(c.ProviderDirectInForce).Normalize()
}

// governanceListLocal resolves the node's own list for a list row whose
// config field alone does not say it. terminal.sandbox.backends is the one
// case: an empty list means the legacy one-element `backend` key (bwrap when
// that is empty too), and an org ordered filter applies to that effective
// order, so a pin can never be side-stepped by leaving `backends` empty.
var governanceListLocal = map[string]func(cfg *Config) []string{
	"terminal.sandbox.backends": SandboxEffectiveBackends,
}

// governanceIntLocal resolves the node's own value for an int row whose
// zero is a default, not "unset" (LEFT2 audit S1). postureop.LowerInt reads
// a local 0 as "no value" and takes the org's ceiling, which for these rows
// would RAISE a node that kept the default (an org pin of 1440 minutes over
// the 10-minute default). Resolving 0 to the default first keeps the row
// truly lowering-only: the merge keeps the lower of the default and the pin.
var governanceIntLocal = map[string]func(cfg *Config) int64{
	"terminal.sandbox.readopt.bound_minutes": func(cfg *Config) int64 {
		return intOrDefault(cfg.Terminal.Sandbox.Readopt.BoundMinutes, SandboxReadoptDefaultBoundMinutes)
	},
	"terminal.sandbox.readopt.checkpoint_cap_mib": func(cfg *Config) int64 {
		return intOrDefault(cfg.Terminal.Sandbox.Readopt.CheckpointCapMiB, SandboxReadoptDefaultCheckpointCapMiB)
	},
}

// intOrDefault is v, or def when v is 0 (the config's "default").
func intOrDefault(v, def int) int64 {
	if v == 0 {
		return int64(def)
	}
	return int64(v)
}

// governanceEmptied is the table of list pins whose merge may leave nothing
// (SBX-P1B merge audit finding 2): the result is what plan 10.1 says, never a
// skip that would keep the node's own list. Each row applies the empty
// result to cfg. The overlay runs on every config load, so a developer who
// edits the list after the pin was accepted gets the same answer then.
var governanceEmptied = map[string]func(cfg *Config){
	// An ordered filter that removes every backend enables none: a sandboxed
	// launch is refused, naming the pin (PinnedNoBackend).
	"terminal.sandbox.backends": func(cfg *Config) {
		cfg.Terminal.Sandbox.Backends = nil
		cfg.Terminal.Sandbox.PinnedNoBackend = "terminal.sandbox.backends"
	},
	// An empty host intersection allows no host: remote clones are off. The
	// node's own host list stays as it was (it is never widened to the org's).
	"terminal.sandbox.remote_allowed_hosts": func(cfg *Config) {
		cfg.Terminal.Sandbox.AllowRemoteClone = false
	},
	// An empty agent-run host intersection allows no host at all (an empty
	// list would read as the tier's own, unrestricted behaviour).
	"terminal.sandbox.egress_allow_hosts": func(cfg *Config) {
		cfg.Terminal.Sandbox.EgressAllowHosts = nil
		cfg.Terminal.Sandbox.PinnedNoEgressHost = "terminal.sandbox.egress_allow_hosts"
	},
}

// governanceEmptiedForces lists, per emptied key, the further keys its row
// sets, so they report as applied (set by the organization) too.
var governanceEmptiedForces = map[string][]string{
	"terminal.sandbox.remote_allowed_hosts": {"terminal.sandbox.allow_remote_clone"},
}

// errGovernanceEmptied is governanceMerge's signal that the merge left
// nothing for a key governanceEmptied handles.
const errGovernanceEmptied = "governance: the merge left nothing (governanceEmptied)"

// SandboxEffectiveBackends is the node's own sandbox backend preference
// order: [terminal.sandbox].backends when set, else the legacy one-element
// `backend` (bwrap when that is empty). It ignores `enabled`. An
// organization pin that left no backend (PinnedNoBackend) gives none.
func SandboxEffectiveBackends(cfg *Config) []string {
	ts := cfg.Terminal.Sandbox
	if ts.PinnedNoBackend != "" {
		return nil
	}
	var out []string
	for _, b := range ts.Backends {
		if b = strings.TrimSpace(b); b != "" {
			out = append(out, b)
		}
	}
	if len(out) > 0 {
		return out
	}
	if b := strings.TrimSpace(ts.Backend); b != "" {
		return []string{b}
	}
	return []string{"bwrap"}
}

// ApplyGovernancePinsTo returns cfg with the pinned map applied exactly as
// the governance overlay applies it (applyGovernancePins), and what that
// did. cfg is copied, never changed. The sandbox module's posture check
// (lane SBX-P1B) uses it to compute a node's settings AFTER a pin set from
// the node's own settings, through the one overlay, so the check and the
// overlay can never disagree about what a pin does.
func ApplyGovernancePinsTo(cfg Config, pinned map[string]any) (Config, GovernanceOutcome) {
	var out GovernanceOutcome
	applyGovernancePins(&cfg, pinned, &out)
	return cfg, out
}

var governancePinnableByKey = func() map[string]governancePinnableKey {
	m := make(map[string]governancePinnableKey, len(governancePinnableKeys))
	for _, k := range governancePinnableKeys {
		m[k.Key] = k
	}
	return m
}()

// GovernanceOutcome records what the governance overlay did to this Load.
// It exists for the disclosure surfaces (`observer org grant show`,
// `observer doctor governance`) — a developer must be able to see the
// mechanism, not just its output — and for the daemon's startup identity
// (§1.6), which is what makes pending_restart reachable.
//
// It is returned, never logged: the hook path must not write to stderr about
// governance, because several AI clients surface hook stderr on every tool
// call.
type GovernanceOutcome struct {
	// Path is the sidecar path this Load consulted ("" when disabled).
	Path string
	// Reason names why no overlay was applied (a sidecar.Reason* value).
	// Empty means an overlay WAS read; it may still have been discarded —
	// see Discarded.
	Reason string
	// Version / Hash identify the posture the returned Config is built from.
	// They are empty when nothing was applied. The daemon retains them as
	// its startupSidecar so it can report pending_restart honestly.
	Version int64
	Hash    string
	// WrittenAt is the sidecar's own stamp (informational).
	WrittenAt time.Time
	// OrgName is carried for the disclosure copy.
	OrgName string
	// GrantExpiresAt is the hard clock the reader enforced.
	GrantExpiresAt time.Time
	// Applied lists the pinned keys this Config actually took, sorted.
	Applied []string
	// Skipped maps a pinned key onto why it was not applied (unknown key,
	// kind mismatch, enum violation, direction violation).
	Skipped map[string]string
	// Discarded is the review-B4 backstop: the merged config failed
	// Validate WITH the overlay, so the WHOLE overlay was thrown away and
	// the ungoverned config returned. Load never fails because of
	// governance.
	Discarded bool
	// DiscardErr is that validation error, for the disclosure surfaces.
	DiscardErr string
	// Pinned is the sidecar's pinned map AS READ, before the per-key rules.
	// The daemon hashes it to decide pending_restart (§1.6): it must be the
	// map the running process was BUILT from, not a reconstruction.
	Pinned map[string]any
	// Share / Features are carried through for the surfaces that render the
	// posture. Load itself does NOT apply them: share is merged hot at the
	// org-push seam (§2.4) and features are display-only (§3).
	Share    map[string]any
	Features map[string]bool
	// HotLocal holds, for every HOT key the overlay touched, the node's own
	// value BEFORE the overlay (see governancePinnableKey.Hot).
	HotLocal map[string]any
	// Excepted maps each pinned key a feature-access grant lifted in THIS
	// Load onto the grant id (request-grants G8). The key kept the node's
	// own value.
	Excepted map[string]int64
	// PinsInForce is the pinned map this Load applied: the sidecar's pins
	// minus every key a feature-access exception lifts
	// (governancePinsInForce). nil when no sidecar applied or the overlay was
	// discarded. A consumer that composes onto the loaded config and must
	// leave the pinned keys alone (the sandbox managed pull on the CLI path,
	// SBX-P1C merge finding 2) reads it instead of resolving an empty grant.
	PinsInForce map[string]any
	// Verified reports that the posture came from the daemon's MAC'd org
	// lock (its own last write) rather than from the file on disk (T-845).
	Verified bool
	// Tampered names a governance file that does not match the daemon's
	// verified copy, or an unverifiable org lock ("" when neither).
	Tampered string
}

// HotLocalInt returns the node's own pre-governance value of a hot int key,
// or fallback when the overlay never touched it (in which case the loaded
// config already carries the node's own value).
func (o GovernanceOutcome) HotLocalInt(key string, fallback int64) int64 {
	switch v := o.HotLocal[key].(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case int32:
		return int64(v)
	default:
		return fallback
	}
}

// Governed reports whether the returned Config actually carries org pins.
func (o GovernanceOutcome) Governed() bool { return len(o.Applied) > 0 && !o.Discarded }

// readGovernanceSidecar resolves the path and reads it, returning nil when
// nothing applies. It never errors.
//
// T-845: when the daemon's MAC'd org lock is valid and records the
// governance bytes it last wrote (GovernanceKnown), THAT copy is the posture,
// not the on-disk file: a sidecar edited or stripped on disk is ignored
// (Tampered names it for the disclosure surfaces, and the daemon repairs the
// file and reports the tamper). With no valid lock the on-disk file applies
// exactly as before. The returned exceptions source is the lock's copy in the
// first case and nil (read the file beside the sidecar) in the second.
func readGovernanceSidecar(cfg Config, override string, now time.Time, lock guardposture.OrgLockLoaded) (*sidecar.File, GovernanceOutcome, *string) {
	out := GovernanceOutcome{Path: ResolveGovernanceSidecarPath(cfg, override)}
	if out.Path == "" {
		out.Reason = sidecar.ReasonAbsent
		return nil, out, nil
	}
	var f *sidecar.File
	var reason string
	var exceptions *string
	if lock.State == guardposture.OrgLockValid && lock.Lock.GovernanceKnown {
		out.Verified = true
		f, reason = sidecar.ReadBytes([]byte(lock.Lock.Governance), now)
		ex := lock.Lock.GovernanceExceptions
		exceptions = &ex
		disk, derr := os.ReadFile(out.Path) //nolint:gosec // the node's own resolved sidecar path
		switch {
		case derr != nil && lock.Lock.Governance != "":
			out.Tampered = "the governance file is missing or unreadable; the daemon's last verified copy applies"
		case derr == nil && string(disk) != lock.Lock.Governance:
			out.Tampered = "the governance file on disk does not match the daemon's last verified copy, which applies instead"
		}
	} else {
		if lock.State == guardposture.OrgLockTampered {
			out.Tampered = "the org lock does not verify (" + lock.Detail + "); the governance file on disk applies until the daemon repairs it"
		}
		f, reason = sidecar.Read(out.Path, now)
	}
	out.Reason = reason
	if f == nil {
		return nil, out, exceptions
	}
	out.Version = f.FamilyVersion
	out.Hash = f.EffectiveHash
	out.OrgName = f.OrgName
	out.Pinned, out.Share, out.Features = f.Pinned, f.Share, f.Features
	if t, ok := sidecar.ParseTime(f.WrittenAt); ok {
		out.WrittenAt = t
	}
	if t, ok := sidecar.ParseTime(f.GrantExpiresAt); ok {
		out.GrantExpiresAt = t
	}
	return f, out, exceptions
}

// governancePinsInForce returns the sidecar's pins minus every key a
// feature-access exception lifts at now (request-grants G8), and the lifted
// keys' grant ids. The exceptions come from their OWN file beside the
// sidecar (sidecar.ExceptionsPath), honoured only while it is bound to this
// sidecar's effective hash; any failure reading it leaves every pin in
// force. exceptionsRaw, when non-nil, is the daemon's last verified copy of
// that file (T-845), used instead of the file on disk.
func governancePinsInForce(f *sidecar.File, sidecarPath string, now time.Time, exceptionsRaw *string) (map[string]any, map[string]int64) {
	var exceptions map[string]sidecar.Exception
	if exceptionsRaw != nil {
		exceptions, _ = sidecar.ReadExceptionsBytes([]byte(*exceptionsRaw), f.EffectiveHash)
	} else {
		exceptions, _ = sidecar.ReadExceptions(sidecar.ExceptionsPath(sidecarPath), f.EffectiveHash)
	}
	return sidecar.PinsInForce(f.Pinned, exceptions, now)
}

// applyGovernancePins writes the sidecar's pinned map onto cfg, skipping —
// never failing on — any key the mirror does not recognise or whose value
// does not satisfy its row. Per-key skipping is the §1.3 table: "that key
// skipped; the rest applied".
func applyGovernancePins(cfg *Config, pinned map[string]any, out *GovernanceOutcome) {
	if len(pinned) == 0 {
		return
	}
	root := reflect.ValueOf(cfg).Elem()
	for _, key := range sortedGovernanceKeys(pinned) {
		val := pinned[key]
		row, known := governancePinnableByKey[key]
		if !known {
			out.skip(key, "not a pinnable key in this build")
			continue
		}
		norm, err := coerceGovernanceValue(row.Kind, val)
		if err != nil {
			out.skip(key, err.Error())
			continue
		}
		if len(row.Enum) > 0 && !governanceValueInSet(norm, row.Enum) {
			out.skip(key, "value outside the key's permitted set")
			continue
		}
		if err := postureop.CheckFormat(row.Format, norm); err != nil {
			out.skip(key, err.Error())
			continue
		}
		if row.Direction == governanceDirRestrictiveOnly && !governanceValuesEqual(norm, row.Safe) {
			out.skip(key, "this key is restrictive-only and may only be set to its safe value")
			continue
		}
		if err := postureop.CheckPin(postureop.Direction(row.Direction), row.Kind, norm, row.Safe); err != nil {
			out.skip(key, err.Error())
			continue
		}
		if n, isInt := norm.(int64); isInt && (row.Min != 0 || row.Max != 0) && (n < row.Min || n > row.Max) {
			out.skip(key, "value outside the key's permitted range")
			continue
		}
		fv, ok := resolveGovernanceField(root, key)
		if !ok || !fv.CanSet() {
			out.skip(key, "the key does not resolve in this build's config")
			continue
		}
		if row.Hot && fv.CanInterface() {
			// Record the node's OWN value before the overlay, so the daemon's
			// live re-application composes against it rather than against an
			// already-lowered number (which would ratchet: a raised org
			// ceiling could then never be released without a restart).
			if out.HotLocal == nil {
				out.HotLocal = map[string]any{}
			}
			out.HotLocal[key] = fv.Interface()
		}
		merged, why := governanceMerge(row, fv, norm, cfg)
		if why == errGovernanceEmptied {
			governanceEmptied[key](cfg)
			out.Applied = append(out.Applied, key)
			out.Applied = append(out.Applied, governanceEmptiedForces[key]...)
			continue
		}
		if why != "" {
			out.skip(key, why)
			continue
		}
		norm = merged
		if !setGovernanceField(fv, norm) {
			out.skip(key, "the config field has an unexpected type")
			continue
		}
		out.Applied = append(out.Applied, key)
	}
	sort.Strings(out.Applied)
}

// governanceMerge composes the node's own value (fv, before the overlay) with
// the org's normalized value under the row's direction, through the one
// postureop operator for that direction. It returns the value to set, or a
// skip reason. DirFree and DirRestrictiveOnly replace; DirLoweringOnly keeps
// its shipped ceiling rule (postureop.LowerInt); DirRetention is raise-only,
// so a local 0 (forever) survives any finite org value; the list directions
// filter, intersect (an empty result is skipped, never read as "any") or add.
func governanceMerge(row governancePinnableKey, fv reflect.Value, org any, cfg *Config) (any, string) {
	dir := postureop.Direction(row.Direction)
	if dir == postureop.DirFree || dir == postureop.DirRestrictiveOnly {
		return org, ""
	}
	var local any
	switch fv.Kind() {
	case reflect.Int, reflect.Int32, reflect.Int64:
		local = fv.Int()
	case reflect.Slice:
		if fv.Type().Elem().Kind() == reflect.String {
			local = append([]string{}, fv.Interface().([]string)...) //nolint:forcetypeassert // the Kind check above
		}
	}
	if f, ok := governanceListLocal[row.Key]; ok {
		local = f(cfg)
	}
	if f, ok := governanceIntLocal[row.Key]; ok {
		local = f(cfg)
	}
	if _, isInt := org.(int64); isInt {
		if _, localInt := local.(int64); !localInt {
			return nil, string(dir) + " applies to whole numbers only"
		}
	}
	_, emptiedRow := governanceEmptied[row.Key]
	merged, err := postureop.Merge(dir, local, org)
	if errors.Is(err, postureop.ErrEmptyIntersection) && emptiedRow {
		return nil, errGovernanceEmptied
	}
	if err != nil {
		return nil, err.Error()
	}
	if l, isList := merged.([]string); isList && len(l) == 0 && dir == postureop.DirOrderedFilter {
		// An ordered filter that removes every entry would leave an empty
		// list, which this config reads as "the default". A row in
		// governanceEmptied says what the empty result means instead; any
		// other row is skipped, never read as the default.
		if emptiedRow {
			return nil, errGovernanceEmptied
		}
		return nil, "the organization list removes every entry of the node's own list"
	}
	return merged, ""
}

func (o *GovernanceOutcome) skip(key, why string) {
	if o.Skipped == nil {
		o.Skipped = map[string]string{}
	}
	o.Skipped[key] = why
}

func sortedGovernanceKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resolveGovernanceField walks a dotted TOML path against the Config struct,
// mirroring applyEnvToStruct's traversal exactly (toml tag, first
// comma-separated segment, "-" skipped) so the two never disagree about what
// a dotted key means.
func resolveGovernanceField(root reflect.Value, dotted string) (reflect.Value, bool) {
	cur := root
	for _, seg := range strings.Split(dotted, ".") {
		if cur.Kind() != reflect.Struct {
			return reflect.Value{}, false
		}
		t := cur.Type()
		found := false
		for i := 0; i < cur.NumField(); i++ {
			tag := t.Field(i).Tag.Get("toml")
			if tag == "" {
				tag = t.Field(i).Name
			}
			tag = strings.SplitN(tag, ",", 2)[0]
			if tag == "-" {
				continue
			}
			if tag == seg {
				cur = cur.Field(i)
				found = true
				break
			}
		}
		if !found {
			return reflect.Value{}, false
		}
	}
	return cur, true
}

func setGovernanceField(fv reflect.Value, norm any) bool {
	switch v := norm.(type) {
	case bool:
		if fv.Kind() != reflect.Bool {
			return false
		}
		fv.SetBool(v)
	case string:
		if fv.Kind() != reflect.String {
			return false
		}
		fv.SetString(v)
	case int64:
		switch fv.Kind() {
		case reflect.Int, reflect.Int32, reflect.Int64:
			fv.SetInt(v)
		default:
			return false
		}
	case []string:
		if fv.Kind() != reflect.Slice || fv.Type().Elem().Kind() != reflect.String {
			return false
		}
		// Replace the slice HEADER, never mutate a shared backing array —
		// the ungoverned Config this was copied from must stay untouched.
		fv.Set(reflect.ValueOf(append([]string{}, v...)))
	default:
		return false
	}
	return true
}

// coerceGovernanceValue normalizes a JSON-decoded sidecar value onto the
// row's declared kind. It is the same normalization nodegov.Compile does at
// publish and accept time; repeating it here is the backstop for a posture
// that did NOT come through today's compiler (an older LKG, a hand-edited
// file).
func coerceGovernanceValue(kind string, val any) (any, error) {
	switch kind {
	case "bool":
		b, ok := val.(bool)
		if !ok {
			return nil, errors.New("value is not a boolean")
		}
		return b, nil
	case "string":
		s, ok := val.(string)
		if !ok {
			return nil, errors.New("value is not a string")
		}
		return s, nil
	case "int":
		switch n := val.(type) {
		case float64:
			if n != math.Trunc(n) {
				return nil, errors.New("value is not a whole number")
			}
			return int64(n), nil
		case int64:
			return n, nil
		default:
			return nil, errors.New("value is not a number")
		}
	case "string_list":
		switch items := val.(type) {
		case []string:
			return append([]string{}, items...), nil
		case []any:
			out := make([]string, 0, len(items))
			for _, it := range items {
				s, ok := it.(string)
				if !ok {
					return nil, errors.New("value is not a list of strings")
				}
				out = append(out, s)
			}
			return out, nil
		default:
			return nil, errors.New("value is not a list of strings")
		}
	default:
		return nil, fmt.Errorf("unsupported kind %q", kind)
	}
}

func governanceValueInSet(v any, set []any) bool {
	for _, cand := range set {
		if governanceValuesEqual(v, cand) {
			return true
		}
	}
	return false
}

func governanceValuesEqual(a, b any) bool {
	switch av := a.(type) {
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case int64:
		switch bv := b.(type) {
		case int64:
			return av == bv
		case int:
			return av == int64(bv)
		}
	case []string:
		bv, ok := b.([]string)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
		return true
	}
	return false
}

// PinnableEffectiveValues returns the LIVE value of each dotted config path
// in keys, as an `any` typed by the field's Go kind (bool / string / int /
// []string). A path that does not resolve is absent from the map rather than
// zero-valued: "this build has no such key" and "this key is false" are
// different facts.
//
// It exists for the Track C item 3 effective-pin report
// (docs/plans/org-guardrail-control-wave-2026-09-21.md): the org needs to
// know what a governed key is ACTUALLY set to on a node, not only what the
// node acked. It reuses resolveGovernanceField so "what a dotted key means"
// keeps exactly one definition — the reason that helper carries its own
// mirror-applyEnvToStruct note.
//
// It is READ-ONLY and takes cfg by value; callers get values, never a handle
// into the config tree.
func PinnableEffectiveValues(cfg Config, keys []string) map[string]any {
	if len(keys) == 0 {
		return nil
	}
	root := reflect.ValueOf(&cfg).Elem()
	out := make(map[string]any, len(keys))
	for _, key := range keys {
		fv, ok := resolveGovernanceField(root, key)
		if !ok || !fv.IsValid() {
			continue
		}
		switch fv.Kind() {
		case reflect.Bool:
			out[key] = fv.Bool()
		case reflect.String:
			out[key] = fv.String()
		case reflect.Int, reflect.Int32, reflect.Int64:
			out[key] = int(fv.Int())
		case reflect.Slice:
			if fv.Type().Elem().Kind() == reflect.String {
				out[key] = append([]string{}, fv.Interface().([]string)...)
			}
		}
	}
	return out
}
