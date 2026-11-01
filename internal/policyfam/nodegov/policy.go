package nodegov

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/postureop"
)

// maxNoticeFieldBytes bounds every free-text notice field. The node renders
// these VERBATIM in its own UI (§4.2), so they are bounded and
// control-character-free by compile time rather than by whatever the SPA
// happens to do with them.
const maxNoticeFieldBytes = 200

// PolicySpec is the compiled, ready-to-apply node.governance policy: four
// deduplicated, sorted section lists plus the notice copy the node renders
// when it tells the developer their machine is managed.
//
// Hash is the content address of the compiled policy (audit provenance;
// mirrors policyfam/providers.PolicySpec.Hash). It is an INTERNAL cache
// key: the org-rail wire identity for this family is the signed BodyHash,
// exactly as for admission/egress/gateway.
type PolicySpec struct {
	HiddenSections   []string
	ReadOnlySections []string
	HiddenSettings   []string
	ReadOnlySettings []string
	// VisibleSections / VisibleSettings are the schema-3 EXPOSE lists (see
	// SectionsV1.Visible): ids shown on a managed node despite the default.
	VisibleSections []string
	VisibleSettings []string
	// Pinned is the settings.pin directive class after compilation: dotted
	// config path → NORMALIZED Go value (bool / string / int64 / []string).
	// It carries the `pinned` block ONLY — the feature block's expansion
	// lives in FeaturePinned so the resolver can gate the two on their own
	// authority tokens (settings.pin vs feature.lock) without re-parsing.
	Pinned map[string]any
	// Share is the capture.pin directive class: share key → normalized
	// value. Applied LOWERING-ONLY by internal/govern (§2.1).
	Share map[string]any
	// Features is the feature.lock directive class as published: feature id
	// → bool. Kept for display ("your organization requires the guard to be
	// on") — it is NOT a second enforcement path.
	Features map[string]bool
	// FeaturePinned is the Features block EXPANDED into pinned entries. A
	// feature is a compile-time alias over a pin, so the node has exactly
	// one enforcement path and a feature lock can never drift from the pin
	// that implements it.
	FeaturePinned map[string]any
	Notice        Notice
	Hash          string
	// IgnoredIDs lists the section ids CompileBodyLenient dropped because
	// this build's vocabulary does not know them, as "<list>:<id>". Always
	// empty from the strict Compile. Not part of Hash: the spec this node
	// applies is exactly the one without them.
	IgnoredIDs []string
}

// Notice is the honesty copy an org publishes alongside its directives so a
// governed developer can see WHO manages the machine and how to reach them
// (§4.2). Every field is optional; the node falls back to the org name it
// recorded at enrolment.
type Notice struct {
	OrgDisplayName string
	Contact        string
	PolicyURL      string
}

// PolicyInput is the plain, pre-compile policy. It mirrors BodyV1 field for
// field; the only difference is BodyV1 carries JSON tags.
type PolicyInput struct {
	HiddenSections   []string
	ReadOnlySections []string
	HiddenSettings   []string
	ReadOnlySettings []string
	VisibleSections  []string
	VisibleSettings  []string
	// Pinned / Share / Features are the schema-2 directive classes, still in
	// their raw decoded (any-valued) shape — Compile is what type-checks and
	// normalizes them.
	Pinned   map[string]any
	Share    map[string]any
	Features map[string]bool
	Notice   Notice
}

// sectionList is one row of the compile table: which input list it is, the
// vocabulary it must be drawn from, and the T8 floor it must not breach.
// Table-driven (CLAUDE.md #5) so the four lists can never drift apart in
// which checks they get.
type sectionList struct {
	name        string
	values      func(PolicyInput) []string
	known       func(string) bool
	unhideable  func(string) bool
	vocabLabel  string
	assignSpec  func(*PolicySpec, []string)
	conflictKey string // lists sharing a key may not name the same id twice
}

func sectionLists() []sectionList {
	return []sectionList{
		{
			// The one list a page TAB ("<page>/<tab>", vocab.go) may appear in.
			name: "sections.hidden", values: func(in PolicyInput) []string { return in.HiddenSections },
			known: IsNavSectionOrTab, unhideable: isUnhideableNavID, vocabLabel: "nav section or page tab",
			assignSpec: func(s *PolicySpec, v []string) { s.HiddenSections = v }, conflictKey: "nav",
		},
		{
			name: "sections.read_only", values: func(in PolicyInput) []string { return in.ReadOnlySections },
			known: IsNavSection, unhideable: IsUnhideableNavSection, vocabLabel: "nav section",
			assignSpec: func(s *PolicySpec, v []string) { s.ReadOnlySections = v }, conflictKey: "nav",
		},
		{
			name: "sections.settings_hidden", values: func(in PolicyInput) []string { return in.HiddenSettings },
			known: IsSettingsSection, unhideable: IsUnhideableSettingsSection, vocabLabel: "settings section",
			assignSpec: func(s *PolicySpec, v []string) { s.HiddenSettings = v }, conflictKey: "settings",
		},
		{
			name: "sections.settings_read_only", values: func(in PolicyInput) []string { return in.ReadOnlySettings },
			known: IsSettingsSection, unhideable: IsUnhideableSettingsSection, vocabLabel: "settings section",
			assignSpec: func(s *PolicySpec, v []string) { s.ReadOnlySettings = v }, conflictKey: "settings",
		},
		{
			name: "sections.visible", values: func(in PolicyInput) []string { return in.VisibleSections },
			known: IsNavSection, unhideable: IsUnhideableNavSection, vocabLabel: "nav section",
			assignSpec: func(s *PolicySpec, v []string) { s.VisibleSections = v }, conflictKey: "nav",
		},
		{
			name: "sections.settings_visible", values: func(in PolicyInput) []string { return in.VisibleSettings },
			known: IsSettingsSection, unhideable: IsUnhideableSettingsSection, vocabLabel: "settings section",
			assignSpec: func(s *PolicySpec, v []string) { s.VisibleSettings = v }, conflictKey: "settings",
		},
	}
}

// Compile validates a PolicyInput and produces a ready PolicySpec. It
// enforces the schema-1 grammar frozen by the spec:
//
//   - every id must be in its closed vocabulary (an unknown id is a HARD
//     error, never a silent skip: an admin must never believe a page is
//     hidden when it is not). This is the publish lint's rule; the agent
//     accept path compiles through CompileBodyLenient instead, which drops
//     an id its build does not have (a page it cannot show, hide or lock)
//     rather than lose the whole body (vocablevel.go);
//   - no id may appear twice within one list, nor in both the hidden and
//     the read_only list of the same vocabulary (hide-and-lock is
//     ambiguous about which the node applied);
//   - no id from the T8 unhideable floor may appear anywhere;
//   - notice fields are bounded, control-character-free, and policy_url,
//     when set, is an absolute http/https URL.
//
// An empty policy (no ids at all) is VALID: it is how an org publishes "you
// are managed, here is who manages you" with no restriction, and how it
// lifts every restriction without un-publishing.
func Compile(in PolicyInput) (PolicySpec, error) {
	spec := PolicySpec{}
	claimed := map[string]string{} // conflictKey+"\x00"+id -> list name
	for _, l := range sectionLists() {
		clean, err := compileSectionList(l, in, claimed)
		if err != nil {
			return PolicySpec{}, err
		}
		l.assignSpec(&spec, clean)
	}
	pinned, err := compilePinned(in.Pinned)
	if err != nil {
		return PolicySpec{}, err
	}
	spec.Pinned = pinned
	share, err := compileShare(in.Share)
	if err != nil {
		return PolicySpec{}, err
	}
	spec.Share = share
	features, featurePins, err := compileFeatures(in.Features, pinned)
	if err != nil {
		return PolicySpec{}, err
	}
	spec.Features, spec.FeaturePinned = features, featurePins
	notice, err := compileNotice(in.Notice)
	if err != nil {
		return PolicySpec{}, err
	}
	spec.Notice = notice
	spec.Hash = hashSpec(spec)
	return spec, nil
}

// compilePinned type-checks and normalizes the `pinned` block against
// PinnableKeys. The grammar (§1.9), enforced identically by the publish lint
// and the agent accept path because both call this function:
//
//   - the key must be in the table (an unknown key is a HARD error, never a
//     silent skip — an admin must never believe a key is pinned when the
//     node dropped it);
//   - the value must type-check against the row's Kind;
//   - when the row carries an Enum, the value must be in it (so a value
//     config.Validate would reject is refused HERE, not at config.Load,
//     where it would break every hook invocation on every node — review B4);
//   - the row's direction is checked by walking the postureop direction
//     table (postureop.CheckPin): a DirRestrictiveOnly key must carry exactly
//     its Safe value, a numeric direction refuses a negative value, a list
//     direction that would allow nothing refuses an empty list, and a
//     direction that does not apply to the row's kind (or is unknown) is a
//     hard error. This is the per-key and impossible-combination half; the
//     result half (does the merged posture loosen this node) is the accept
//     path's CheckPosture gate, which knows the node's local values.
func compilePinned(raw map[string]any) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(raw))
	for key, val := range raw {
		row, ok := LookupPinnableKey(key)
		if !ok {
			return nil, fmt.Errorf("nodegov.Compile: pinned names %q, which is not a settable key (it is either unknown or structurally excluded from remote control)", key)
		}
		norm, err := normalizeValue("pinned."+key, row.Kind, val)
		if err != nil {
			return nil, err
		}
		if len(row.Enum) > 0 && !valueInSet(norm, row.Enum) {
			return nil, fmt.Errorf("nodegov.Compile: pinned.%s = %v is not one of %v", key, norm, row.Enum)
		}
		if err := postureop.CheckFormat(row.Format, norm); err != nil {
			return nil, fmt.Errorf("nodegov.Compile: pinned.%s: %w", key, err)
		}
		if row.Direction == DirRestrictiveOnly && !valuesEqual(norm, row.Safe) {
			return nil, fmt.Errorf("nodegov.Compile: pinned.%s may only be set to %v (this key is restrictive-only: the organization may force the safer value, never the riskier one)", key, row.Safe)
		}
		if err := postureop.CheckPin(row.Direction, row.Kind, norm, row.Safe); err != nil {
			return nil, fmt.Errorf("nodegov.Compile: pinned.%s: %w", key, err)
		}
		if n, isInt := norm.(int64); isInt && (row.Min != 0 || row.Max != 0) && (n < row.Min || n > row.Max) {
			return nil, fmt.Errorf("nodegov.Compile: pinned.%s = %d is outside the permitted range %d..%d", key, n, row.Min, row.Max)
		}
		out[key] = norm
	}
	return out, nil
}

// compileShare type-checks and normalizes the `share` block against
// ShareKeys. There is no direction check here: the share algebra is
// LOWERING-ONLY at RESOLVE time (internal/govern intersects the org
// directive with the node's own local value), so a directive of `true`
// against a local `false` is a legal body that resolves to a no-op rather
// than a publish error. Rejecting it at publish would be worse: an admin
// pinning a fleet at its current level publishes exactly that body.
func compileShare(raw map[string]any) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(raw))
	for key, val := range raw {
		row, ok := LookupShareKey(key)
		if !ok {
			return nil, fmt.Errorf("nodegov.Compile: share names %q, which is not an organization-directable sharing key", key)
		}
		norm, err := normalizeValue("share."+key, row.Kind, val)
		if err != nil {
			return nil, err
		}
		out[key] = norm
	}
	return out, nil
}

// compileFeatures expands the `features` block into pinned entries (§3).
// A feature is an ALIAS, so its direction bound is the direction of the
// pinnable key it expands to — one definition, checked at publish and at
// accept. A feature that disagrees with an explicit pin on the same key is a
// hard error: two directives commanding one key with two values is
// ambiguous about which the node applied.
func compileFeatures(raw map[string]bool, pinned map[string]any) (map[string]bool, map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	feats := make(map[string]bool, len(raw))
	pins := make(map[string]any, len(raw))
	for id, on := range raw {
		f, ok := LookupFeature(id)
		if !ok {
			return nil, nil, fmt.Errorf("nodegov.Compile: features names %q, which is not a known feature", id)
		}
		row, ok := LookupPinnableKey(f.Key)
		if !ok {
			// Structurally impossible — TestEveryFeatureExpandsToAPinnableKey
			// pins it — but a compiler that trusts its own table silently is
			// how a drift becomes a false compliance claim.
			return nil, nil, fmt.Errorf("nodegov.Compile: feature %q expands to %q, which is not a pinnable key", id, f.Key)
		}
		if row.Kind != "bool" {
			return nil, nil, fmt.Errorf("nodegov.Compile: feature %q expands to non-boolean key %q", id, f.Key)
		}
		if row.Direction == DirRestrictiveOnly && !valuesEqual(on, row.Safe) {
			return nil, nil, fmt.Errorf("nodegov.Compile: feature %q may only be set to %v (the key it locks, %s, is restrictive-only)", id, row.Safe, f.Key)
		}
		if prior, dup := pinned[f.Key]; dup && !valuesEqual(prior, on) {
			return nil, nil, fmt.Errorf("nodegov.Compile: feature %q and pinned.%s disagree (%v vs %v) — one key, one value", id, f.Key, on, prior)
		}
		feats[id] = on
		pins[f.Key] = on
	}
	return feats, pins, nil
}

// normalizeValue coerces a JSON-decoded value onto the declared Kind,
// returning the canonical Go type the sidecar and the config overlay both
// expect (bool / string / int64 / []string).
func normalizeValue(label, kind string, val any) (any, error) {
	switch kind {
	case "bool":
		b, ok := val.(bool)
		if !ok {
			return nil, fmt.Errorf("nodegov.Compile: %s must be a boolean, got %T", label, val)
		}
		return b, nil
	case "string":
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("nodegov.Compile: %s must be a string, got %T", label, val)
		}
		return strings.TrimSpace(s), nil
	case "int":
		switch n := val.(type) {
		case float64:
			if n != math.Trunc(n) {
				return nil, fmt.Errorf("nodegov.Compile: %s must be a whole number, got %v", label, n)
			}
			return int64(n), nil
		case int64:
			return n, nil
		default:
			return nil, fmt.Errorf("nodegov.Compile: %s must be a number, got %T", label, val)
		}
	case "string_list":
		items, ok := val.([]any)
		if !ok {
			if already, isStrings := val.([]string); isStrings {
				return append([]string{}, already...), nil
			}
			return nil, fmt.Errorf("nodegov.Compile: %s must be a list of strings, got %T", label, val)
		}
		out := make([]string, 0, len(items))
		seen := map[string]bool{}
		for _, it := range items {
			s, isStr := it.(string)
			if !isStr {
				return nil, fmt.Errorf("nodegov.Compile: %s must be a list of strings, got a %T element", label, it)
			}
			s = strings.TrimSpace(s)
			if s == "" {
				return nil, fmt.Errorf("nodegov.Compile: %s contains an empty entry", label)
			}
			if seen[s] {
				return nil, fmt.Errorf("nodegov.Compile: %s names %q twice", label, s)
			}
			seen[s] = true
			out = append(out, s)
		}
		sort.Strings(out)
		return out, nil
	default:
		return nil, fmt.Errorf("nodegov.Compile: %s declares unsupported kind %q", label, kind)
	}
}

func valueInSet(v any, set []any) bool {
	for _, cand := range set {
		if valuesEqual(v, cand) {
			return true
		}
	}
	return false
}

// valuesEqual compares two normalized values without reflect.DeepEqual's
// type strictness across the int widths a hand-written table might use.
func valuesEqual(a, b any) bool {
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
		return false
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

// formatValue renders a normalized value deterministically for the content
// hash. It must never depend on map iteration order or on %v's formatting of
// a slice, which is why lists are joined explicitly.
func formatValue(v any) string {
	switch tv := v.(type) {
	case bool:
		return strconv.FormatBool(tv)
	case string:
		return tv
	case int64:
		return strconv.FormatInt(tv, 10)
	case []string:
		return strings.Join(tv, "\x1f")
	default:
		return fmt.Sprintf("%v", v)
	}
}

// sortedKeys returns a map's keys in a stable order, so every hash and every
// rendered list is deterministic.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// compileSectionList runs one row of the compile table against the input it
// names, returning the sorted+deduplicated ids.
func compileSectionList(l sectionList, in PolicyInput, claimed map[string]string) ([]string, error) {
	raw := l.values(in)
	out := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, id := range raw {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, fmt.Errorf("nodegov.Compile: %s contains an empty id", l.name)
		}
		if !l.known(id) {
			if IsNavTab(id) {
				return nil, fmt.Errorf("nodegov.Compile: %s names page tab %q: a tab can only be hidden (sections.hidden); lock or expose its page instead", l.name, id)
			}
			return nil, fmt.Errorf("nodegov.Compile: %s names %q, which is not a known %s", l.name, id, l.vocabLabel)
		}
		if l.unhideable(id) {
			return nil, fmt.Errorf("nodegov.Compile: %s names %q, which can never be hidden or locked — it is how a developer sees what their organization configured and receives", l.name, id)
		}
		if seen[id] {
			return nil, fmt.Errorf("nodegov.Compile: %s names %q twice", l.name, id)
		}
		key := l.conflictKey + "\x00" + id
		if other, dup := claimed[key]; dup {
			return nil, fmt.Errorf("nodegov.Compile: %s names %q, which %s already names — an id takes exactly one of hidden, read-only or visible", l.name, id, other)
		}
		claimed[key] = l.name
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

func compileNotice(n Notice) (Notice, error) {
	fields := []struct {
		name string
		val  *string
	}{
		{"notice.org_display_name", &n.OrgDisplayName},
		{"notice.contact", &n.Contact},
		{"notice.policy_url", &n.PolicyURL},
	}
	for _, f := range fields {
		v := strings.TrimSpace(*f.val)
		if len(v) > maxNoticeFieldBytes {
			return Notice{}, fmt.Errorf("nodegov.Compile: %s is %d bytes, exceeds the %d-byte cap", f.name, len(v), maxNoticeFieldBytes)
		}
		for _, r := range v {
			if unicode.IsControl(r) {
				return Notice{}, fmt.Errorf("nodegov.Compile: %s contains a control character", f.name)
			}
		}
		*f.val = v
	}
	if n.PolicyURL != "" {
		u, err := url.Parse(n.PolicyURL)
		if err != nil {
			return Notice{}, fmt.Errorf("nodegov.Compile: notice.policy_url %q: %w", n.PolicyURL, err)
		}
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return Notice{}, fmt.Errorf("nodegov.Compile: notice.policy_url %q must be an absolute http or https URL", n.PolicyURL)
		}
	}
	return n, nil
}

// hashSpec computes a stable content hash over the semantic policy fields so
// the same policy always yields the same Hash. Field order is fixed and the
// lists are already sorted, so the hash never depends on submission order.
func hashSpec(s PolicySpec) string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			_, _ = h.Write([]byte(p))
			_, _ = h.Write([]byte{0x1e})
		}
	}
	for _, pair := range []struct {
		label string
		ids   []string
	}{
		{"hidden", s.HiddenSections},
		{"read_only", s.ReadOnlySections},
		{"settings_hidden", s.HiddenSettings},
		{"settings_read_only", s.ReadOnlySettings},
		{"visible", s.VisibleSections},
		{"settings_visible", s.VisibleSettings},
	} {
		for _, id := range pair.ids {
			write(pair.label, id)
		}
	}
	for _, key := range sortedKeys(s.Pinned) {
		write("pinned", key, formatValue(s.Pinned[key]))
	}
	for _, key := range sortedKeys(s.Share) {
		write("share", key, formatValue(s.Share[key]))
	}
	for _, id := range sortedKeys(s.Features) {
		write("feature", id, strconv.FormatBool(s.Features[id]))
	}
	write("notice", s.Notice.OrgDisplayName, s.Notice.Contact, s.Notice.PolicyURL)
	return hex.EncodeToString(h.Sum(nil))
}
