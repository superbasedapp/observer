package configschema

import (
	"regexp"
	"strings"
)

// The config.toml sanity check shared by every write door (adapter-config
// plan section 5.5, backlog item 7 for Observer's own file): the dashboard's
// PUT /api/config/keys and `observer config set` both classify a key here
// before anything is parsed or written, so the CLI is not a bypass of the
// dashboard's tier and governance gates. Pure: the governance posture and
// the credential detector are passed in.

// KeyGovernance is the managed-node posture a config write is checked
// against. A caller on an ungoverned node passes nil. Sections that can never
// be hidden (nodegov.IsUnhideableSettingsSection) are the caller's to exempt,
// since this package may not import the governance vocabulary.
type KeyGovernance interface {
	IsSettingsSectionHidden(section string) bool
	IsSettingsSectionReadOnly(section string) bool
}

// KeyVerdict is the closed set of outcomes for one key.
type KeyVerdict string

// The KeyVerdict vocabulary, in the order a batch reports them.
const (
	KeyOK                 KeyVerdict = "ok"
	KeyUnknown            KeyVerdict = "unknown_key"
	KeySecret             KeyVerdict = "secret_write_refused"
	KeyOwnerElsewhere     KeyVerdict = "owner_elsewhere"
	KeyGovernanceHidden   KeyVerdict = "governance_hidden"
	KeyGovernanceReadOnly KeyVerdict = "governance_read_only"
	KeyGovernanceUnmapped KeyVerdict = "governance_unmappable"
)

// KeyCheck is one key's classification.
type KeyCheck struct {
	Key string
	// Leaf is the schema leaf that governs the key: the exact leaf, or for a
	// map-entry key ("profiles.by_tool.cline") its string_map ancestor.
	Leaf  Leaf
	Found bool
	// Verdict is KeyOK or the first refusal that applies.
	Verdict KeyVerdict
	Message string
	// NeedsConfirm is true for a sensitive-tier key: the write needs an
	// explicit confirm (the dashboard's confirm token, the CLI's --yes).
	NeedsConfirm bool
}

// ResolveKey returns the leaf that governs a dotted key: the exact leaf, or
// the nearest string_map / table ancestor for a key that names an entry
// inside a map.
func ResolveKey(dotted string) (Leaf, bool) {
	if l, ok := Lookup(dotted); ok {
		return l, true
	}
	segs := strings.Split(dotted, ".")
	for i := len(segs) - 1; i > 0; i-- {
		if l, ok := Lookup(strings.Join(segs[:i], ".")); ok && (l.Kind == KindStringMap || l.Kind == KindTable) {
			return l, true
		}
	}
	return Leaf{}, false
}

// keyRules is the ordered refusal table: the first rule that matches wins.
var keyRules = []struct {
	verdict KeyVerdict
	match   func(l Leaf, gov KeyGovernance) bool
	message func(l Leaf) string
}{
	{
		KeySecret, func(l Leaf, _ KeyGovernance) bool { return l.Tier == TierSecret || l.Secret },
		func(Leaf) string {
			return "this is a credential; it is never written from here. Edit config.toml directly."
		},
	},
	{
		KeyOwnerElsewhere, func(l Leaf, _ KeyGovernance) bool { return l.Tier == TierOwnerElsewhere || l.Deprecated != "" },
		func(l Leaf) string {
			if l.Deprecated != "" {
				return "deprecated key: " + l.Deprecated
			}
			return "read-only here, owned by " + l.OwnedBy
		},
	},
	{
		KeyGovernanceUnmapped, func(l Leaf, gov KeyGovernance) bool { return gov != nil && l.Section == "" },
		func(Leaf) string {
			return "this key could not be mapped to a governed settings section on a managed node"
		},
	},
	{
		KeyGovernanceHidden, func(l Leaf, gov KeyGovernance) bool { return gov != nil && gov.IsSettingsSectionHidden(l.Section) },
		func(Leaf) string {
			return "this setting is managed by your organization and is not available on this machine"
		},
	},
	{KeyGovernanceReadOnly, func(l Leaf, gov KeyGovernance) bool {
		return gov != nil && gov.IsSettingsSectionReadOnly(l.Section)
	}, func(Leaf) string { return "this setting is pinned by your organization and cannot be changed here" }},
}

// CheckKey classifies one dotted key for a write: unknown, a credential,
// owned elsewhere, hidden or read-only under governance, or OK (with
// NeedsConfirm for a sensitive key).
func CheckKey(dotted string, gov KeyGovernance) KeyCheck {
	c := KeyCheck{Key: dotted, Verdict: KeyOK}
	l, ok := ResolveKey(dotted)
	if !ok {
		c.Verdict, c.Message = KeyUnknown, "unknown config key"
		if gov != nil {
			// A governed node never writes a key the guard cannot classify.
			c.Verdict, c.Message = KeyGovernanceUnmapped, "unknown config key; a managed node refuses keys it cannot classify"
		}
		return c
	}
	c.Leaf, c.Found = l, true
	if l.Kind == KindTable && l.Path == dotted && l.Tier != TierSecret {
		c.Verdict, c.Message = KeyOwnerElsewhere, "a whole table is not writable through a single key"
		return c
	}
	for _, r := range keyRules {
		if r.match(l, gov) {
			c.Verdict, c.Message = r.verdict, r.message(l)
			return c
		}
	}
	c.NeedsConfirm = l.Tier == TierSensitive
	return c
}

// SecretShaped reports whether a value about to be written holds a string
// that looks like a credential (the injected detector) or a string under a
// credential-named map key. The posture (warn / refuse) is the caller's.
func SecretShaped(v any, detect func(string) bool) bool {
	return secretShaped(v, detect, true)
}

// SecretShapedLeaf is SecretShaped for a value of leaf l: a map whose keys
// are ids (Leaf.KeysAreIDs) is judged by its values alone.
func SecretShapedLeaf(l Leaf, v any, detect func(string) bool) bool {
	return secretShaped(v, detect, !l.KeysAreIDs)
}

func secretShaped(v any, detect func(string) bool, keyNames bool) bool {
	switch x := v.(type) {
	case string:
		return detect != nil && x != "" && detect(x)
	case []string:
		for _, e := range x {
			if secretShaped(e, detect, keyNames) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if secretShaped(e, detect, keyNames) {
				return true
			}
		}
	case map[string]string:
		for k, e := range x {
			if (keyNames && credentialKeyName(k) && e != "") || secretShaped(e, detect, keyNames) {
				return true
			}
		}
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok && keyNames && credentialKeyName(k) && s != "" {
				return true
			}
			if secretShaped(e, detect, keyNames) {
				return true
			}
		}
	}
	return false
}

var credentialKeyRe = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|passwd|credential|authorization|bearer)`)

// credentialKeyNameExempt are names that contain a credential word but name
// a count or a reference (max_tokens, token_env).
var credentialKeyNameExempt = regexp.MustCompile(`(?i)(tokens|token_?(limit|count|budget|env|file|path)|_env$|_file$|_path$)`)

func credentialKeyName(k string) bool {
	return credentialKeyRe.MatchString(k) && !credentialKeyNameExempt.MatchString(k)
}

// SecretPlaceholder replaces a hidden value in a masked rendering of
// config.toml (the dry-run diff).
const SecretPlaceholder = `"__observer_hidden_secret__"` //nolint:gosec // a placeholder marker, never a credential

var (
	tomlHeaderRe = regexp.MustCompile(`^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(#.*)?$`)
	tomlAssignRe = regexp.MustCompile(`^(\s*)((?:"[^"]*"|'[^']*'|[A-Za-z0-9_\-]+)(?:\s*\.\s*(?:"[^"]*"|'[^']*'|[A-Za-z0-9_\-]+))*)(\s*=\s*)(.*)$`)
)

// MaskTOMLSecrets renders config.toml text with every credential value
// replaced by SecretPlaceholder, so a diff of two renderings never shows
// one: a secret-tier leaf, a credential-named key, or a value the detector
// recognizes. A multi-line array value of a secret key is collapsed onto
// the key's line. Both sides of a diff go through the same function, so an
// unchanged secret stays unchanged in the diff.
func MaskTOMLSecrets(text string, detect func(string) bool) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	table := ""
	skipDepth := 0
	for _, line := range lines {
		if skipDepth > 0 {
			skipDepth += bracketDelta(line)
			continue
		}
		if m := tomlHeaderRe.FindStringSubmatch(line); m != nil && !strings.Contains(line, "=") {
			table = normalizeDotted(m[1])
			out = append(out, line)
			continue
		}
		m := tomlAssignRe.FindStringSubmatch(line)
		if m == nil {
			out = append(out, line)
			continue
		}
		key := normalizeDotted(m[2])
		dotted := key
		if table != "" {
			dotted = table + "." + key
		}
		rhs := m[4]
		if !secretAssignment(dotted, key, rhs, detect) {
			out = append(out, line)
			continue
		}
		out = append(out, m[1]+m[2]+m[3]+SecretPlaceholder)
		if d := bracketDelta(rhs); strings.HasPrefix(strings.TrimSpace(rhs), "[") && d > 0 {
			skipDepth = d
		}
	}
	return strings.Join(out, "\n")
}

func secretAssignment(dotted, key, rhs string, detect func(string) bool) bool {
	l, ok := ResolveKey(dotted)
	if ok && (l.Tier == TierSecret || l.Secret) {
		return true
	}
	segs := strings.Split(key, ".")
	val := strings.TrimSpace(rhs)
	if !(ok && l.KeysAreIDs) && credentialKeyName(segs[len(segs)-1]) && strings.HasPrefix(val, `"`) && val != `""` {
		return true
	}
	if detect == nil {
		return false
	}
	for _, q := range quotedStrings(val) {
		if q != "" && detect(q) {
			return true
		}
	}
	return false
}

var quotedRe = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"|'([^']*)'`)

func quotedStrings(s string) []string {
	var out []string
	for _, m := range quotedRe.FindAllStringSubmatch(s, -1) {
		if m[1] != "" {
			out = append(out, m[1])
		} else {
			out = append(out, m[2])
		}
	}
	return out
}

func normalizeDotted(s string) string {
	parts := strings.Split(s, ".")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"'`)
		parts[i] = p
	}
	return strings.Join(parts, ".")
}

// bracketDelta counts [ minus ] outside quoted strings on one line.
func bracketDelta(s string) int {
	d := 0
	inQuote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote != 0:
			if c == '\\' && inQuote == '"' {
				i++
			} else if c == inQuote {
				inQuote = 0
			}
		case c == '"' || c == '\'':
			inQuote = c
		case c == '#':
			return d
		case c == '[':
			d++
		case c == ']':
			d--
		}
	}
	return d
}
