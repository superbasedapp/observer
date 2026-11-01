package nodegov

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Target is everything a node.governance body must respect to compile on one
// node, as three independent axes. A body is delivered to a node projected
// onto its Target (ProjectToTarget), so a released build never sees an id,
// key or schema it would fail the whole body on.
type Target struct {
	// Level is the section and page-tab vocabulary level (vocablevel.go).
	Level int
	// MaxSchema is the highest body schema the build decodes (wire.go).
	MaxSchema int
	// KeyGen is the generation of the pinned / share / feature key
	// vocabularies (pinnable.go) the build compiles.
	KeyGen int
}

// CurrentKeyGen is the key-vocabulary generation this build compiles. Bump it,
// and add each new key to pinSince / shareSince / featureSince at the new
// generation, whenever PinnableKeys, ShareKeys or Features grows. target_test.go
// fails when a key is missing from both the first-generation baseline and the
// since tables.
const CurrentKeyGen = 5

// FirstKeyGen is the key vocabulary of the first node.governance build
// (v1.31.0).
const FirstKeyGen = 1

// pinSince / shareSince / featureSince name the generation at which each key
// joined its vocabulary; a key absent from its table has been there since
// FirstKeyGen. Generations 1-4 are released builds (literal key lists in
// target_test.go, taken from the tags; 4, v1.36.0, is the first that
// advertises its generation); 5 is unreleased.
var (
	pinSince = map[string]int{
		"guard.strict":          3, // v1.33.0
		"guard.budget.hard":     3, // v1.33.0
		"guard.budget.from_org": 3, // v1.33.0
		"routing.enabled":       3, // v1.33.0
		"tasks.enabled":         3, // v1.33.0
		// after v1.34.0 (the 2026-10-02 budget-latency arc)
		"org_client.push_interval_seconds": 4,
		// D-502 (structured unenrol). Generation 4 is still unreleased: the
		// held v1.35.0 ships as one combined release with this work (D-400).
		"guard.budget.fail_closed": 4,
		// lane P1 (managed route maintenance, the admin's routing switch).
		"proxy.maintain_routes": 5,
		// lane SBX-P1B (the sandboxed-terminal settings, sandbox plan v2
		// section 10.1), joining the still-unreleased generation 5.
		"terminal.sandbox.backends":                 5,
		"terminal.sandbox.remote_allowed_hosts":     5,
		"terminal.sandbox.mask_paths":               5,
		"terminal.sandbox.workspace_retention_days": 5,
		"terminal.sandbox.home_mode":                5,
		"terminal.sandbox.default_on":               5,
		"terminal.sandbox.allow_remote_clone":       5,
		"terminal.sandbox.allow_worktree_source":    5,
		"terminal.sandbox.allow_tool_config_writes": 5,
		"terminal.sandbox.egress_allow_cidrs":       5,
		"terminal.sandbox.egress_allow_hosts":       5,
		"terminal.sandbox.extra_ro_binds":           5,
		"terminal.sandbox.extra_rw_binds":           5,
		"terminal.sandbox.prep_timeout_seconds":     5,
		// lane SBX-P3D (vendor_forced_native).
		"terminal.sandbox.vendor_forced_native": 5,
		// lane SBX-UPD (live sandboxed runs across updates).
		"terminal.sandbox.live_run_update_policy": 5,
		// lane SBX-P3A (the container driver's settings).
		"terminal.sandbox.oci.allow_rootful":            5,
		"terminal.sandbox.oci.allow_devcontainer_image": 5,
		"terminal.sandbox.oci.podman_userns":            5,
		"terminal.sandbox.oci.stop_grace_seconds":       5,
		// lane SBX-P3B (the org image pins).
		"terminal.sandbox.oci.image": 5,
		// lane SBX-P3C (the first-start install cache).
		"terminal.sandbox.oci.install_cache": 5,
		// lane LEFT-SBX (the install-script allowance, ruling P-136).
		"terminal.sandbox.oci.install_scripts": 5,
		// lane SBX-P6 (the Windows driver's settings).
		"terminal.sandbox.mxc.stop_grace_seconds":    5,
		"terminal.sandbox.mxc.probe_timeout_seconds": 5,
		// lane SBX-P5 (the macOS drivers' settings).
		"terminal.sandbox.seatbelt.allow_keychain":    5,
		"terminal.sandbox.seatbelt.driver":            5,
		"terminal.sandbox.apple_container.memory_mib": 5,
		"terminal.sandbox.apple_container.cpus":       5,
		// lane SBX-P3B (the org image pins).
		"terminal.sandbox.apple_container.image": 5,
		// lane SBX-P3B (the Landlock-only row's floor).
		"terminal.sandbox.landlock.min_abi": 5,
		// lane SBX-P7 (the hosted rows' shared settings).
		"terminal.sandbox.hosted.min_session_minutes": 5,
		"terminal.sandbox.hosted.max_run_minutes":     5,
		"terminal.sandbox.hosted.daily_box_minutes":   5,
		"terminal.sandbox.hosted.checkpoint_minutes":  5,
		"terminal.sandbox.hosted.memory_images":       5,
		// the LEFT-SBX merge (the opt-in hosted database export, ruling
		// P-141).
		"terminal.sandbox.hosted.db_export": 5,
		// lane LEFT2-SBX (R-034: the re-adoption and MXC tier pins).
		"terminal.sandbox.readopt.bound_minutes":      5,
		"terminal.sandbox.readopt.checkpoint_cap_mib": 5,
		"terminal.sandbox.windows.mxc_tier":           5,
		// lane w6-governance (DEC-9, OBS-8a: the direct provider egress
		// posture), joining the still-unreleased generation 5.
		"terminal.sandbox.provider_direct": 5,
		// lane w6-governance (CLI-1b, D6: managed command wrapping).
		"shell_wrap.org_maintain": 5,
	}
	shareSince = map[string]int{
		"full_tool_bodies":            2, // v1.32.0
		"cache_detail":                2, // v1.32.0
		"routing_detail":              2, // v1.32.0
		"limit_gauge":                 2, // v1.32.0
		"codeintel_detail":            2, // v1.32.0
		"process_detail":              2, // v1.32.0
		"terminal_detail":             2, // v1.32.0
		"task_detail":                 3, // v1.33.0
		"tool_account_detail":         3, // v1.33.0
		"intelligence.org_enrichment": 3, // v1.33.0
		"obs.egress":                  3, // v1.33.0
		// lane w5-wire (per-session hook liveness, DEC-5).
		"hook_activity": 5,
	}
	featureSince = map[string]int{}
)

// PinnedKeySince returns the generation at which a pinnable key joined.
func PinnedKeySince(key string) int { return sinceIn(pinSince, key) }

// ShareKeySince returns the generation at which a share key joined.
func ShareKeySince(key string) int { return sinceIn(shareSince, key) }

// FeatureSince returns the generation at which a feature id joined: the later
// of its own row and the pinned key it expands to, because a build that does
// not know that key refuses the feature too.
func FeatureSince(id string) int {
	since := sinceIn(featureSince, id)
	if f, ok := LookupFeature(id); ok {
		if k := PinnedKeySince(f.Key); k > since {
			since = k
		}
	}
	return since
}

// CurrentTarget is what this build compiles.
func CurrentTarget() Target {
	return Target{Level: CurrentVocabLevel, MaxSchema: MaxSchema, KeyGen: CurrentKeyGen}
}

// MinTarget is the axis-by-axis lower of two targets: what a body must respect
// to compile on BOTH nodes (the inventory fallback takes it over a member's
// machines).
func MinTarget(a, b Target) Target {
	return Target{Level: min(a.Level, b.Level), MaxSchema: min(a.MaxSchema, b.MaxSchema), KeyGen: min(a.KeyGen, b.KeyGen)}
}

// ---------------------------------------------------------------------------
// What a node advertises.
// ---------------------------------------------------------------------------

const (
	schemaCapabilityPrefix = "nodegov-schema-"
	keysCapabilityPrefix   = "nodegov-keys-"
)

// SchemaCapabilityToken renders the policy_caps token that names the highest
// node.governance body schema a node decodes.
func SchemaCapabilityToken(schema int) string { return schemaCapabilityPrefix + strconv.Itoa(schema) }

// KeysCapabilityToken renders the policy_caps token that names the key
// vocabulary generation a node compiles.
func KeysCapabilityToken(gen int) string { return keysCapabilityPrefix + strconv.Itoa(gen) }

// CapabilityTokens is every node.governance token this build advertises on
// the policy GET: its vocabulary level, its body schema and its key
// generation. The server serves it exactly that (TargetForCapabilities).
func CapabilityTokens() []string {
	return []string{
		VocabCapabilityToken(CurrentVocabLevel),
		SchemaCapabilityToken(MaxSchema),
		KeysCapabilityToken(CurrentKeyGen),
	}
}

// capabilityEra is the schema and key generation of the builds that advertised
// a vocabulary level BEFORE the schema and keys tokens existed, by that level.
// Levels 4 to 6 were only ever advertised by builds descending from the
// vocabulary-level change (01efa140a), which already decoded schema 3
// (493685fd8) and knew org_client.push_interval_seconds (a2d41219e). Levels
// 1-3 are never advertised by a real build; they map to the oldest released
// build at that level, so a hand-written token is never served more than the
// matching release compiles. target_test.go pins one row per level.
var capabilityEra = map[int]struct{ MaxSchema, KeyGen int }{
	1: {2, 1},
	2: {2, 3},
	3: {2, 3},
	4: {3, 4},
	5: {3, 4},
	6: {3, 4},
	// Level 7 (the Plans & limits page) builds always advertise the schema
	// and keys tokens; this row is only the fallback for a hand-written one.
	7: {3, 4},
	// Level 8 (the Messages page, T-854): same as level 7.
	8: {3, 4},
	// Level 9 (the Tools page tabs, T-935): same as level 8.
	9: {3, 4},
	// Level 10 (the security pillar's Code security page): same as level 9.
	10: {3, 4},
}

// TargetForCapabilities resolves the Target a node advertises, and false when
// it advertises no vocabulary level (a build older than the capability: the
// caller falls back to TargetForAgentVersion). The schema and key axes come
// from their own tokens when present, else from the era of the advertised
// level. Every axis is clamped to this server's own (a newer node can only be
// served what this server knows).
func TargetForCapabilities(tokens []string) (Target, bool) {
	level, ok := ParseVocabCapability(tokens)
	if !ok {
		return Target{}, false
	}
	era, known := capabilityEra[level]
	if !known {
		era = capabilityEra[CurrentVocabLevel]
	}
	t := Target{Level: level, MaxSchema: era.MaxSchema, KeyGen: era.KeyGen}
	if s, ok := parseCapability(tokens, schemaCapabilityPrefix, 1, MaxSchema); ok {
		t.MaxSchema = s
	}
	if k, ok := parseCapability(tokens, keysCapabilityPrefix, FirstKeyGen, CurrentKeyGen); ok {
		t.KeyGen = k
	}
	return MinTarget(t, CurrentTarget()), true
}

// ---------------------------------------------------------------------------
// What a node that advertises nothing compiles, by its reported version.
// ---------------------------------------------------------------------------

// releasedTargets maps a released agent version onto what that build
// compiles, for a node too old to advertise CapabilityTokens. Ordered newest
// first; the first row whose MinVersion the node is at or above decides.
//
// Versions compare by full SemVer precedence (compareRelease): a PRE-RELEASE
// of X is OLDER than X, so a row can name exactly the first build that had
// something. Every row was checked against the tags: all eleven v1.34.0 rc
// tags and v1.34.0 itself have byte-identical vocabularies and MaxSchema 2,
// and v1.33.0 / v1.32.0 had no rc tags (any pre-release of them falls to the
// row below, the conservative side). Re-check against the tags whenever a row
// is added.
var releasedTargets = []struct {
	MinVersion string
	Target     Target
}{
	{"1.34.0-rc.1", Target{Level: 3, MaxSchema: 2, KeyGen: 3}},
	{"1.33.0", Target{Level: 2, MaxSchema: 2, KeyGen: 3}},
	{"1.32.0", Target{Level: 1, MaxSchema: 2, KeyGen: 2}},
}

// oldestTarget is v1.31.0, the first node.governance build. It is what an
// unparseable, empty or "dev" version resolves to: never an assumed-new build.
var oldestTarget = Target{Level: FirstVocabLevel, MaxSchema: 2, KeyGen: FirstKeyGen}

// LastUncappedTarget is the newest Target a build that does NOT advertise
// CapabilityTokens compiles (the v1.34.0 line). The server assumes it for a
// member that has never reported a version: an older node served something it
// lacks rejects the body before installing anything, so it heals on the next
// poll after its first push, whereas a v1.34 node served a stripped body would
// hold that body at that version until the next publish (a pre-capability
// build treats the full body at the same version as a replay).
func LastUncappedTarget() Target { return releasedTargets[0].Target }

// TargetForAgentVersion maps a reported agent version onto what that build
// compiles. An unparseable, empty or "dev" version is the oldest build.
func TargetForAgentVersion(version string) Target {
	for _, row := range releasedTargets {
		if cmp, ok := compareRelease(version, row.MinVersion); ok && cmp >= 0 {
			return row.Target
		}
	}
	return oldestTarget
}

// compareRelease orders two versions by SemVer 2.0 precedence: the X.Y.Z core
// numerically, then a version WITH a pre-release below the same core without
// one, pre-release identifiers compared one by one (numeric ones numerically
// and below alphanumeric ones, a shorter list below a longer one it
// prefixes). Build metadata ("+...") is ignored. ok is false when either side
// does not parse. It differs from update.CompareSemver ON PURPOSE: that one
// treats "1.34.0-rc.11" as "1.34.0" (the dashboard's update nag), which here
// would credit a release candidate with what only the release has.
func compareRelease(a, b string) (int, bool) {
	ca, pa, oka := parseRelease(a)
	cb, pb, okb := parseRelease(b)
	if !oka || !okb {
		return 0, false
	}
	for i := range ca {
		if c := cmpInt(ca[i], cb[i]); c != 0 {
			return c, true
		}
	}
	switch {
	case len(pa) == 0 && len(pb) == 0:
		return 0, true
	case len(pa) == 0:
		return 1, true
	case len(pb) == 0:
		return -1, true
	}
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if c := comparePreIdent(pa[i], pb[i]); c != 0 {
			return c, true
		}
	}
	return cmpInt(len(pa), len(pb)), true
}

// parseRelease splits "vX.Y.Z[-pre][+build]" into its numeric core and
// pre-release identifiers. Parts of the core beyond the third are ignored, as
// update.ParseSemver ignores them.
func parseRelease(v string) (core [3]int, pre []string, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	coreStr, preStr, hasPre := strings.Cut(v, "-")
	parts := strings.Split(coreStr, ".")
	if len(parts) < 3 {
		return core, nil, false
	}
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return core, nil, false
		}
		core[i] = n
	}
	if hasPre {
		pre = strings.Split(preStr, ".")
		for _, id := range pre {
			if id == "" {
				return core, nil, false
			}
		}
	}
	return core, pre, true
}

func comparePreIdent(a, b string) int {
	na, errA := strconv.Atoi(a)
	nb, errB := strconv.Atoi(b)
	switch {
	case errA == nil && errB == nil:
		return cmpInt(na, nb)
	case errA == nil:
		return -1
	case errB == nil:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// ---------------------------------------------------------------------------
// Projection.
// ---------------------------------------------------------------------------

// ErrNotExpressible is returned when a body cannot be expressed in a node's
// schema without dropping a directive that must never be dropped silently. The
// server answers 503 and the node keeps its last verified body.
var ErrNotExpressible = errors.New("nodegov: the body cannot be expressed in this node's schema without dropping a directive it must keep")

// schemaFields is the per-schema table of body fields: the schema each needs,
// how to see and drop it, and whether dropping it for a node that cannot
// decode it is SAFE. Walked top-down by ProjectToTarget (CLAUDE.md rule 5).
//
//   - The expose lists (schema 3) only ever LOOSEN a managed-node default. A
//     build that cannot decode schema 3 either has no managed defaults at all
//     (every released build up to v1.34.0, verified against the rc.11 code in
//     rc11compat) or keeps its own defaults, which is stricter, never looser.
//     Omitting them is safe.
//   - pinned / share / features (schema 2) are the org's enforcement and
//     sharing directives. Dropping them would quietly un-govern the node, so
//     they are never omitted for a schema reason: such a body is refused as
//     not expressible. No node.governance build decodes less than schema 2,
//     so this row is a guard, not a path any fleet takes today.
var schemaFields = []struct {
	name      string
	schema    int
	omittable bool
	present   func(Body) bool
	drop      func(*Body)
}{
	{
		name: "sections.visible", schema: 3, omittable: true,
		present: func(b Body) bool { return len(b.Sections.Visible) > 0 },
		drop:    func(b *Body) { b.Sections.Visible = nil },
	},
	{
		name: "sections.settings_visible", schema: 3, omittable: true,
		present: func(b Body) bool { return len(b.Sections.SettingsVisible) > 0 },
		drop:    func(b *Body) { b.Sections.SettingsVisible = nil },
	},
	{
		name: "pinned", schema: 2,
		present: func(b Body) bool { return len(b.Pinned) > 0 },
	},
	{
		name: "share", schema: 2,
		present: func(b Body) bool { return len(b.Share) > 0 },
	},
	{
		name: "features", schema: 2,
		present: func(b Body) bool { return len(b.Features) > 0 },
	},
}

// keyRefs addresses the three keyed directive classes with their since tables,
// so the key projection walks one table.
func keyRefs(b *Body) []struct {
	name  string
	keys  func() []string
	since func(string) int
	drop  func(string)
} {
	return []struct {
		name  string
		keys  func() []string
		since func(string) int
		drop  func(string)
	}{
		{"pinned", func() []string { return sortedKeys(b.Pinned) }, PinnedKeySince, func(k string) { delete(b.Pinned, k) }},
		{"share", func() []string { return sortedKeys(b.Share) }, ShareKeySince, func(k string) { delete(b.Share, k) }},
		{"features", func() []string { return sortedKeys(b.Features) }, FeatureSince, func(k string) { delete(b.Features, k) }},
	}
}

// ProjectToTarget returns b with everything a node at Target t does not
// compile removed, and what was removed as "<list>:<id>" (plus
// "schema:<from>-><to>" when the declared schema is lowered). In order:
//
//  1. section and tab ids above t.Level;
//  2. pinned / share / feature keys above t.KeyGen (a build that does not
//     know a key cannot apply it, projected or refused);
//  3. schemaFields above t.MaxSchema, when omittable; a non-omittable one is
//     ErrNotExpressible;
//  4. the schema is lowered to what the projected body still needs
//     (SchemaFor) whenever something was removed or it exceeds t.MaxSchema.
//
// b is not modified. A body that needs nothing removed comes back equal to b
// with no entries, which callers use to serve the stored envelope unchanged.
func ProjectToTarget(b Body, t Target) (Body, []string, error) {
	out := b
	out.Sections = cloneSections(b.Sections)
	out.Pinned = cloneAnyMap(b.Pinned)
	out.Share = cloneAnyMap(b.Share)
	out.Features = cloneBoolMap(b.Features)
	var removed []string
	for _, ref := range sectionListRefs(&out.Sections) {
		kept := (*ref.ids)[:0:0]
		for _, id := range *ref.ids {
			if ref.since(strings.TrimSpace(id)) > t.Level {
				removed = append(removed, ref.name+":"+id)
				continue
			}
			kept = append(kept, id)
		}
		if len(kept) == 0 {
			kept = nil
		}
		*ref.ids = kept
	}
	for _, ref := range keyRefs(&out) {
		for _, k := range ref.keys() {
			if ref.since(k) > t.KeyGen {
				ref.drop(k)
				removed = append(removed, ref.name+":"+k)
			}
		}
	}
	for _, f := range schemaFields {
		if f.schema <= t.MaxSchema || !f.present(out) {
			continue
		}
		if !f.omittable {
			return Body{}, nil, fmt.Errorf("%w: %s needs schema %d and the node decodes up to %d", ErrNotExpressible, f.name, f.schema, t.MaxSchema)
		}
		f.drop(&out)
		removed = append(removed, f.name+":*")
	}
	if len(out.Pinned) == 0 {
		out.Pinned = nil
	}
	if len(out.Share) == 0 {
		out.Share = nil
	}
	if len(out.Features) == 0 {
		out.Features = nil
	}
	if len(removed) > 0 || out.Schema > t.MaxSchema {
		if s := SchemaFor(out); s < out.Schema {
			removed = append(removed, fmt.Sprintf("schema:%d->%d", out.Schema, s))
			out.Schema = s
		}
	}
	return out, removed, nil
}

// ProjectServedBody is the serve-time projection of a stored node.governance
// body for one node: decode, ProjectToTarget, canonicalize. projected is nil
// (and removed empty) when the node compiles the body as stored, so the caller
// serves the stored envelope byte for byte; otherwise projected is the
// canonical body to sign.
func ProjectServedBody(raw []byte, maxBytes int64, t Target) (projected []byte, removed []string, err error) {
	body, err := DecodeBody(raw, maxBytes)
	if err != nil {
		return nil, nil, err
	}
	out, removed, err := ProjectToTarget(body, t)
	if err != nil || len(removed) == 0 {
		return nil, nil, err
	}
	canon, err := CanonicalJSON(out)
	if err != nil {
		return nil, nil, err
	}
	return canon, removed, nil
}

// ServedProjectionHashes returns the body hash (hex sha256 of the canonical
// bytes, exactly what the org server stamps on the re-signed envelope when it
// projects a body at serve time) of every distinct projection of a stored
// node.governance body that a node target older than this build is served.
// The stored body's own hash is not in the set: a node that compiles the body
// as stored is served it byte for byte. A body no target needs to strip, or
// one that does not decode, yields nil, and the caller still has the stored
// hash.
//
// Fleet-state reconciliation uses it so a node that was served the published
// version in the shape it speaks reads as running that version, not as
// drifted from it (T-347).
func ServedProjectionHashes(raw []byte, maxBytes int64) map[string]bool {
	var out map[string]bool
	current := CurrentTarget()
	for level := FirstVocabLevel; level <= CurrentVocabLevel; level++ {
		for schema := 1; schema <= MaxSchema; schema++ {
			for keys := FirstKeyGen; keys <= CurrentKeyGen; keys++ {
				t := Target{Level: level, MaxSchema: schema, KeyGen: keys}
				if t == current {
					continue
				}
				canon, _, err := ProjectServedBody(raw, maxBytes, t)
				if err != nil || canon == nil {
					continue
				}
				sum := sha256.Sum256(canon)
				if out == nil {
					out = map[string]bool{}
				}
				out[hex.EncodeToString(sum[:])] = true
			}
		}
	}
	return out
}

func cloneAnyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneBoolMap(in map[string]bool) map[string]bool {
	if in == nil {
		return nil
	}
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
