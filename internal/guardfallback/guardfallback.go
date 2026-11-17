package guardfallback

import (
	"bufio"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Table is the bundle's TOML table name: `[fallbacks]`.
const Table = "fallbacks"

// Setting keys inside `[fallbacks]`.
const (
	// KeyUserPolicyInvalid chooses what a managed node does while the
	// developer's own guard-policy.toml does not load (T-327).
	KeyUserPolicyInvalid = "user_policy_invalid"
	// KeySandboxUnavailable chooses what a proxied, launchable tool degrades
	// to when its sandbox lever cannot be built on the machine (D-178).
	KeySandboxUnavailable = "sandbox_unavailable"
)

// Values. The first value of each Setting row is its default.
const (
	// UserPolicyLoud keeps the built-in rules and the org bundle in force
	// and only makes the failure loud (doctor, guard event, Security banner).
	UserPolicyLoud = "loud"
	// UserPolicyFailClosed additionally closes every enforced gate hook,
	// with a reason naming the file and line, until the file loads.
	UserPolicyFailClosed = "fail_closed"
	// SandboxRecordedAcceptance launches the tool unsandboxed and records
	// the accepted risk (today's behaviour). The spelling is
	// integration.EnforceRecordedAcceptance's.
	SandboxRecordedAcceptance = "recorded_acceptance"
	// SandboxOrgDisallow refuses to launch the tool while no sandbox is
	// available. The spelling is integration.EnforceOrgDisallow's.
	SandboxOrgDisallow = "org_disallow"
)

// Setting is one row of the closed vocabulary: the key and its values in
// ASCENDING strictness. Values[0] is the default and the value every
// individual node runs; folding several bundles keeps the strictest.
type Setting struct {
	Key    string
	Values []string
	// Label and Help are the admin-console copy, kept beside the values so
	// the dashboard and the assistant describe the same choice. Label is a
	// short sentence-case name; Help is ONE plain sentence saying when the
	// setting matters. The consequence of each value is the dashboard's
	// per-value copy (web2 lib/guardFallbacks.ts), and the technical detail
	// (file path, wire values) is Technical, shown only behind an info icon.
	Label string
	Help  string
	// Technical names the file and the wire values for the technical
	// reader. Never shown inline: the dashboard puts it in a tooltip.
	Technical string
}

// Settings is the whole vocabulary, in display and render order.
var Settings = []Setting{
	{
		Key:       KeyUserPolicyInvalid,
		Values:    []string{UserPolicyLoud, UserPolicyFailClosed},
		Label:     "Developer's own guard file is broken",
		Help:      "The developer's local guard settings file can't be read.",
		Technical: "File: ~/.observer/guard-policy.toml. Values: loud, fail_closed.",
	},
	{
		Key:       KeySandboxUnavailable,
		Values:    []string{SandboxRecordedAcceptance, SandboxOrgDisallow},
		Label:     "No sandbox available",
		Help:      "A tool needs a filesystem sandbox, but this machine can't build one (macOS, Windows, or sandboxing off).",
		Technical: "Applies to proxied tools while the guard enforces. Values: recorded_acceptance, org_disallow.",
	},
}

// Fallbacks is one set of choices. An empty field means the default, so the
// zero value is the all-defaults set an individual node always runs.
type Fallbacks struct {
	UserPolicyInvalid  string
	SandboxUnavailable string
}

// field is the table of key -> field accessor, so every per-key operation
// below walks Settings instead of switching on a key name.
var field = map[string]func(*Fallbacks) *string{
	KeyUserPolicyInvalid:  func(f *Fallbacks) *string { return &f.UserPolicyInvalid },
	KeySandboxUnavailable: func(f *Fallbacks) *string { return &f.SandboxUnavailable },
}

// Lookup returns the Setting row for key.
func Lookup(key string) (Setting, bool) {
	for _, s := range Settings {
		if s.Key == key {
			return s, true
		}
	}
	return Setting{}, false
}

// rank is v's position in s.Values, or -1 when v is not a value of s.
func (s Setting) rank(v string) int {
	for i, x := range s.Values {
		if x == v {
			return i
		}
	}
	return -1
}

// Default is the row's default value.
func (s Setting) Default() string { return s.Values[0] }

// Get returns the effective value of key: the set value when it is one of
// the row's values, else the default. An unknown key returns "".
func (f Fallbacks) Get(key string) string {
	s, ok := Lookup(key)
	if !ok {
		return ""
	}
	v := *field[key](&f)
	if s.rank(v) < 0 {
		return s.Default()
	}
	return v
}

// Normalize returns f with every field spelled out (defaults filled in).
func (f Fallbacks) Normalize() Fallbacks {
	out := Fallbacks{}
	for _, s := range Settings {
		*field[s.Key](&out) = f.Get(s.Key)
	}
	return out
}

// IsDefault reports whether every choice is its default.
func (f Fallbacks) IsDefault() bool {
	for _, s := range Settings {
		if f.Get(s.Key) != s.Default() {
			return false
		}
	}
	return true
}

// FailClosedOnInvalidUserPolicy reports the T-327 choice.
func (f Fallbacks) FailClosedOnInvalidUserPolicy() bool {
	return f.Get(KeyUserPolicyInvalid) == UserPolicyFailClosed
}

// DisallowWithoutSandbox reports the D-178 choice.
func (f Fallbacks) DisallowWithoutSandbox() bool {
	return f.Get(KeySandboxUnavailable) == SandboxOrgDisallow
}

// Validate reports whether value is a legal value for key.
func Validate(key, value string) error {
	s, ok := Lookup(key)
	if !ok {
		return fmt.Errorf("%s.%s is not a fallback setting (known: %s)", Table, key, strings.Join(keys(), ", "))
	}
	if s.rank(value) < 0 {
		return fmt.Errorf("%s.%s = %q is not one of %s", Table, key, value, strings.Join(s.Values, ", "))
	}
	return nil
}

// Set validates and assigns one choice.
func (f *Fallbacks) Set(key, value string) error {
	if err := Validate(key, value); err != nil {
		return err
	}
	*field[key](f) = value
	return nil
}

func keys() []string {
	out := make([]string, 0, len(Settings))
	for _, s := range Settings {
		out = append(out, s.Key)
	}
	return out
}

// Decode reads a decoded `[fallbacks]` table. Every legal entry is applied;
// each unknown key, non-string value or unknown value is returned as a
// problem and IGNORED (its key keeps the default). The caller decides what a
// problem means: the authoring gate refuses the bundle, a node accepts it and
// notes the problem, because a newer server may know a value this agent does
// not (the GUARD-FWD-1 consumer rule).
func Decode(raw map[string]any) (Fallbacks, []string) {
	var f Fallbacks
	var problems []string
	names := make([]string, 0, len(raw))
	for k := range raw {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		s, isStr := raw[k].(string)
		if !isStr {
			if _, known := Lookup(k); !known {
				problems = append(problems, fmt.Sprintf("%s.%s is not a fallback setting", Table, k))
				continue
			}
			problems = append(problems, fmt.Sprintf("%s.%s must be a string", Table, k))
			continue
		}
		if err := f.Set(k, strings.TrimSpace(s)); err != nil {
			problems = append(problems, err.Error())
		}
	}
	return f, problems
}

// Strictest folds several sets into one: per key, the strictest value any of
// them chose (the same strictest-wins rule the bundle composition applies to
// every rule decision).
func Strictest(sets ...Fallbacks) Fallbacks {
	out := Fallbacks{}
	for _, s := range Settings {
		best := 0
		for _, f := range sets {
			if r := s.rank(f.Get(s.Key)); r > best {
				best = r
			}
		}
		*field[s.Key](&out) = s.Values[best]
	}
	return out
}

// Effective is the one tenancy gate: the org's choices apply on a MANAGED
// node; an individual node always runs the defaults (operator ruling:
// individual nodes keep today's behaviour).
func Effective(org Fallbacks, managed bool) Fallbacks {
	if !managed {
		return Fallbacks{}.Normalize()
	}
	return org.Normalize()
}

// --- TOML text ----------------------------------------------------------------

// renderComment is written as the table's first line, INSIDE the table, so
// Strip removes it together with the table.
const renderComment = "# Organization guard fallbacks (Policies > Guard > When a safeguard can't run in the admin dashboard)."

// Render emits the `[fallbacks]` table for f: only the non-default keys, in
// Settings order. Empty when f is all defaults, so an org that never changes
// a fallback ships byte-for-byte the bundle it shipped before the table
// existed.
func Render(f Fallbacks) string {
	var b strings.Builder
	for _, s := range Settings {
		if v := f.Get(s.Key); v != s.Default() {
			fmt.Fprintf(&b, "%s = %q\n", s.Key, v)
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return "[" + Table + "]\n" + renderComment + "\n" + b.String()
}

// headerRE matches the `[fallbacks]` header line (whitespace and a trailing
// comment allowed, as TOML allows them).
var headerRE = regexp.MustCompile(`^\s*\[\s*` + Table + `\s*\]\s*(#.*)?$`)

// anyHeaderRE matches any table or array-of-tables header line.
var anyHeaderRE = regexp.MustCompile(`^\s*\[`)

// Present reports whether body carries a `[fallbacks]` table header.
func Present(body string) bool {
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if headerRE.MatchString(sc.Text()) {
			return true
		}
	}
	return false
}

// Strip removes every `[fallbacks]` table (header through the line before
// the next header) from body, leaving everything else byte for byte.
func Strip(body string) string {
	lines := strings.SplitAfter(body, "\n")
	var b strings.Builder
	in := false
	for _, l := range lines {
		trimmed := strings.TrimRight(l, "\r\n")
		switch {
		case headerRE.MatchString(trimmed):
			in = true
			continue
		case in && anyHeaderRE.MatchString(trimmed):
			in = false
		case in:
			continue
		}
		b.WriteString(l)
	}
	return b.String()
}

// FromTOML decodes just the `[fallbacks]` table of a bundle body. present
// reports whether the table exists; problems are Decode's; err is a TOML
// syntax error (the whole body did not parse).
func FromTOML(body string) (f Fallbacks, present bool, problems []string, err error) {
	var doc struct {
		Fallbacks map[string]any `toml:"fallbacks"`
	}
	meta, derr := toml.Decode(body, &doc)
	if derr != nil {
		return Fallbacks{}, false, nil, fmt.Errorf("guardfallback.FromTOML: %w", derr)
	}
	if !meta.IsDefined(Table) {
		return Fallbacks{}, false, nil, nil
	}
	f, problems = Decode(doc.Fallbacks)
	return f, true, problems, nil
}

// EmptyBundle is the body Splice produces when nothing but default fallbacks
// is left: a comment, which lints as an org bundle that raises nothing.
const EmptyBundle = "# Org-wide guard bundle: no rule overrides.\n"

// Splice rewrites body so its `[fallbacks]` table says exactly f: every
// existing table is stripped and, unless f is all defaults, one table is
// appended at the end. The admin's rules, overrides and comments are left as
// written. The result is re-decoded and must say f exactly; a body that
// expresses fallbacks some other way (a dotted key, an inline table) is
// refused rather than rewritten wrongly.
func Splice(body string, f Fallbacks) (string, error) {
	out := strings.TrimRight(Strip(body), " \t\r\n")
	if t := Render(f); t != "" {
		if out != "" {
			out += "\n\n"
		}
		out += t
	} else if out != "" {
		out += "\n"
	} else {
		// A bundle must say something: an org-wide bundle whose only content
		// was the table becomes an explicit "nothing to raise" body.
		out = EmptyBundle
	}
	got, _, problems, err := FromTOML(out)
	if err != nil {
		return "", err
	}
	if len(problems) > 0 || got.Normalize() != f.Normalize() {
		return "", fmt.Errorf("guardfallback.Splice: the bundle sets %s outside a [%s] table; edit it in the raw TOML editor", Table, Table)
	}
	return out, nil
}
