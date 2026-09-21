package config

import (
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern/sidecar"
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
}

const (
	governanceDirFree            = "free"
	governanceDirRestrictiveOnly = "restrictive_only"
)

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
}

// Governed reports whether the returned Config actually carries org pins.
func (o GovernanceOutcome) Governed() bool { return len(o.Applied) > 0 && !o.Discarded }

// readGovernanceSidecar resolves the path and reads it, returning nil when
// nothing applies. It never errors.
func readGovernanceSidecar(cfg Config, override string, now time.Time) (*sidecar.File, GovernanceOutcome) {
	out := GovernanceOutcome{Path: ResolveGovernanceSidecarPath(cfg, override)}
	if out.Path == "" {
		out.Reason = sidecar.ReasonAbsent
		return nil, out
	}
	f, reason := sidecar.Read(out.Path, now)
	out.Reason = reason
	if f == nil {
		return nil, out
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
	return f, out
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
		if row.Direction == governanceDirRestrictiveOnly && !governanceValuesEqual(norm, row.Safe) {
			out.skip(key, "this key is restrictive-only and may only be set to its safe value")
			continue
		}
		fv, ok := resolveGovernanceField(root, key)
		if !ok || !fv.CanSet() {
			out.skip(key, "the key does not resolve in this build's config")
			continue
		}
		if !setGovernanceField(fv, norm) {
			out.skip(key, "the config field has an unexpected type")
			continue
		}
		out.Applied = append(out.Applied, key)
	}
	sort.Strings(out.Applied)
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
