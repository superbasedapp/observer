package guardrecipe

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Kind is a recipe's axis.
type Kind string

// Recipe kinds.
const (
	// KindLevel is a strictness level: one per scope, carries the mode.
	KindLevel Kind = "level"
	// KindPack is a function pack: any number per scope, rows only.
	KindPack Kind = "pack"
)

// Source says where a catalog recipe came from.
type Source string

// Recipe sources.
const (
	// SourceBuiltin is a recipe embedded in this binary (catalog/*.toml).
	SourceBuiltin Source = "builtin"
	// SourceUser is a recipe file in the user's guard-recipes directory.
	SourceUser Source = "user"
)

// NameRx is the shape of a recipe name: it is the file name (<name>.toml)
// and the [guard] level value, so it is filesystem-safe and lowercase.
// internal/config's guard.level validation carries the same pattern.
var NameRx = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// MaxRecipeBytes bounds one recipe file. A reader stats a file and reads at
// most this many bytes (plus one, to see that it is larger) before Parse.
const MaxRecipeBytes = 128 << 10

// maxNestingDepth bounds how deeply a recipe file nests arrays, inline
// tables and table headers. The decoder's cost grows faster than linearly
// with nesting (sweep finding RC-10), so a deeper file is refused before it
// is decoded. A recipe needs three levels at most ([[rule]] plus an array
// in [rule.match]).
const maxNestingDepth = 8

// Modes a level may carry ([guard] mode).
var validModes = map[string]bool{"off": true, "observe": true, "enforce": true}

// PromptModes a level may carry ([guard.prompt] mode).
var validPromptModes = map[string]bool{"off": true, "warn": true, "ask-once": true, "block": true, "redact": true}

// validDecisions is the [[override]] decision vocabulary ("" keeps the
// rule's catalog decision).
var validDecisions = map[string]bool{"": true, "allow": true, "flag": true, "ask": true, "deny": true}

// OverrideRow is one [[override]] row of a recipe, in the guard policy-file
// vocabulary plus a recipe-only note rendered as a comment.
type OverrideRow struct {
	// Rule is the rule ID the row tunes.
	Rule string `toml:"rule"`
	// Decision replaces the rule's observe and enforce decisions ("" keeps
	// them).
	Decision string `toml:"decision"`
	// Enforce is true (the decision holds in observe mode), false (cap the
	// rule at flag) or unset.
	Enforce *bool `toml:"enforce"`
	// Note is a one-line reason, rendered as a comment above the row.
	Note string `toml:"note"`
}

// Recipe is one parsed catalog entry.
type Recipe struct {
	// Name is the recipe's name (its file name without .toml).
	Name string
	// Kind is level or pack.
	Kind Kind
	// Title and Summary are the human labels.
	Title   string
	Summary string
	// Version is the recipe's revision; an applied file records it, so a
	// newer catalog revision shows as an update.
	Version int
	// Order sorts levels on the strictness slider (levels only).
	Order int
	// Mode and PromptMode are the [guard] mode and [guard.prompt] mode a
	// level sets at global scope (levels only).
	Mode       string
	PromptMode string
	// Extends names a recipe of the same kind whose rows come first.
	Extends string
	// Advice lists things the recipe recommends that are not rules
	// (a sandboxed terminal, a config key to fill in).
	Advice []string
	// Inputs lists the config keys the recipe's rules read
	// ("guard.network.allow_hosts"), so a surface can link them.
	Inputs []string
	// Overrides are the recipe's own [[override]] rows, in file order.
	Overrides []OverrideRow
	// Rules are the recipe's own [[rule]] rows, decoded as TOML tables.
	Rules []map[string]any
	// Source says where the recipe came from.
	Source Source
	// Raw is the file as read.
	Raw []byte
}

// RuleID returns a [[rule]] row's id ("" when missing).
func RuleID(row map[string]any) string {
	s, _ := row["id"].(string)
	return s
}

// fileShape is the on-disk recipe shape. Unknown keys are an error (a typo
// in a hand-written recipe must fail loudly, as a policy file does).
type fileShape struct {
	Name       string           `toml:"name"`
	Kind       string           `toml:"kind"`
	Title      string           `toml:"title"`
	Summary    string           `toml:"summary"`
	Version    int              `toml:"version"`
	Order      int              `toml:"order"`
	Mode       string           `toml:"mode"`
	PromptMode string           `toml:"prompt_mode"`
	Extends    string           `toml:"extends"`
	Advice     []string         `toml:"advice"`
	Inputs     []string         `toml:"inputs"`
	Override   []OverrideRow    `toml:"override"`
	Rule       []map[string]any `toml:"rule"`
}

// Parse decodes and checks one recipe file. name is the file name without
// .toml; the file's own `name` key must equal it.
func Parse(name string, raw []byte, src Source) (*Recipe, error) {
	if len(raw) > MaxRecipeBytes {
		return nil, fmt.Errorf("guardrecipe.Parse %s: file is larger than %d bytes", name, MaxRecipeBytes)
	}
	// The file itself is printed too (`recipe show --toml`, the dashboard's
	// raw view), comments included: no raw control character but the tab
	// and the line breaks TOML uses (RC-9).
	if c, ok := controlChar(strings.NewReplacer("\t", "", "\r\n", "\n").Replace(string(raw)), true); ok {
		return nil, fmt.Errorf("guardrecipe.Parse %s: the file holds control character U+%04X (terminal control sequences are refused)", name, c)
	}
	if d := nestingDepth(raw); d > maxNestingDepth {
		return nil, fmt.Errorf("guardrecipe.Parse %s: arrays and tables are nested deeper than %d levels", name, maxNestingDepth)
	}
	var f fileShape
	meta, err := toml.Decode(string(raw), &f)
	if err != nil {
		return nil, fmt.Errorf("guardrecipe.Parse %s: %w", name, err)
	}
	var unknown []string
	for _, k := range meta.Undecoded() {
		// [[rule]] tables decode into maps, which the decoder still lists
		// as undecoded below the first level; the guard's lint checks their
		// vocabulary when the compiled file is applied. Anything else is a
		// typo.
		if len(k) > 0 && k[0] == "rule" {
			continue
		}
		unknown = append(unknown, k.String())
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("guardrecipe.Parse %s: unknown keys: %s", name, strings.Join(unknown, ", "))
	}
	r := &Recipe{
		Name: f.Name, Kind: Kind(f.Kind), Title: f.Title, Summary: f.Summary,
		Version: f.Version, Order: f.Order, Mode: f.Mode, PromptMode: f.PromptMode,
		Extends: f.Extends, Advice: f.Advice, Inputs: f.Inputs,
		Overrides: f.Override, Rules: f.Rule, Source: src, Raw: raw,
	}
	if err := r.check(name); err != nil {
		return nil, fmt.Errorf("guardrecipe.Parse %s: %w", name, err)
	}
	return r, nil
}

// check validates a parsed recipe's own fields (cross-recipe checks such as
// a missing extends target run when the catalog is assembled).
func (r *Recipe) check(fileName string) error {
	if !NameRx.MatchString(r.Name) {
		return fmt.Errorf("name %q is not a recipe name (lowercase letters, digits and dashes)", r.Name)
	}
	if fileName != "" && r.Name != fileName {
		return fmt.Errorf("name %q does not match the file name %q", r.Name, fileName)
	}
	if strings.TrimSpace(r.Title) == "" {
		return errors.New("missing title")
	}
	if err := r.checkText(); err != nil {
		return err
	}
	if r.Version < 1 {
		return errors.New("version must be 1 or more")
	}
	switch r.Kind {
	case KindLevel:
		if !validModes[r.Mode] {
			return fmt.Errorf("level mode %q not in {off, observe, enforce}", r.Mode)
		}
		if !validPromptModes[r.PromptMode] {
			return fmt.Errorf("level prompt_mode %q not in {off, warn, ask-once, block, redact}", r.PromptMode)
		}
	case KindPack:
		if r.Mode != "" || r.PromptMode != "" || r.Order != 0 {
			return errors.New("a pack carries rows only: mode, prompt_mode and order are level keys")
		}
	default:
		return fmt.Errorf("kind %q not in {level, pack}", r.Kind)
	}
	if r.Extends != "" && !NameRx.MatchString(r.Extends) {
		return fmt.Errorf("extends %q is not a recipe name", r.Extends)
	}
	if r.Extends == r.Name && r.Name != "" {
		return errors.New("a recipe cannot extend itself")
	}
	for i, ov := range r.Overrides {
		if strings.TrimSpace(ov.Rule) == "" {
			return fmt.Errorf("override %d: missing rule id", i+1)
		}
		if !validDecisions[ov.Decision] {
			return fmt.Errorf("override %d (%s): decision %q not in {allow, flag, ask, deny}", i+1, ov.Rule, ov.Decision)
		}
		if ov.Decision == "" && ov.Enforce == nil {
			return fmt.Errorf("override %d (%s): sets neither decision nor enforce", i+1, ov.Rule)
		}
		if strings.ContainsAny(ov.Note, "\r\n") {
			return fmt.Errorf("override %d (%s): note must be one line", i+1, ov.Rule)
		}
	}
	seen := map[string]bool{}
	for i, row := range r.Rules {
		id := RuleID(row)
		if id == "" {
			return fmt.Errorf("rule %d: missing id", i+1)
		}
		if seen[id] {
			return fmt.Errorf("rule %d: duplicate id %q", i+1, id)
		}
		seen[id] = true
	}
	return nil
}

// textField is one recipe text a surface prints: a terminal, the
// dashboard, a verdict reason. lineBreaks allows a line feed (alone or after
// a carriage return) in prose fields; no other control character is
// allowed anywhere (sweep finding RC-9: an escape sequence in a recipe a
// person was handed must not reach their terminal).
type textField struct {
	name       string
	value      string
	lineBreaks bool
}

// textFields lists every printed text of a recipe, in file order.
func (r *Recipe) textFields() []textField {
	out := []textField{{"title", r.Title, false}, {"summary", r.Summary, true}}
	for i, a := range r.Advice {
		out = append(out, textField{fmt.Sprintf("advice %d", i+1), a, true})
	}
	for i, in := range r.Inputs {
		out = append(out, textField{fmt.Sprintf("inputs %d", i+1), in, false})
	}
	for i, ov := range r.Overrides {
		out = append(out,
			textField{fmt.Sprintf("override %d rule", i+1), ov.Rule, false},
			textField{fmt.Sprintf("override %d note", i+1), ov.Note, false})
	}
	for i, row := range r.Rules {
		keys := make([]string, 0, len(row))
		for k := range row {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			prose := k == "doc" || k == "advice"
			switch v := row[k].(type) {
			case string:
				out = append(out, textField{fmt.Sprintf("rule %d %s", i+1, k), v, prose})
			case []any:
				for j, e := range v {
					if s, ok := e.(string); ok {
						out = append(out, textField{fmt.Sprintf("rule %d %s %d", i+1, k, j+1), s, false})
					}
				}
			}
		}
	}
	return out
}

// checkText refuses a control character in any printed text.
func (r *Recipe) checkText() error {
	for _, f := range r.textFields() {
		if c, ok := controlChar(f.value, f.lineBreaks); ok {
			return fmt.Errorf("%s: control character U+%04X is not allowed (terminal control sequences are refused)", f.name, c)
		}
	}
	return nil
}

// controlChar returns the first C0 or C1 control character of s (and DEL),
// skipping a line feed, and a carriage return right before one, when
// lineBreaks allows them.
func controlChar(s string, lineBreaks bool) (rune, bool) {
	rs := []rune(s)
	for i, c := range rs {
		switch {
		case lineBreaks && c == '\n':
			continue
		case lineBreaks && c == '\r' && i+1 < len(rs) && rs[i+1] == '\n':
			continue
		case c < 0x20, c == 0x7f, c >= 0x80 && c <= 0x9f:
			return c, true
		}
	}
	return 0, false
}

// nestingDepth returns the deepest nesting of [ and { in a TOML text,
// outside strings and comments. It is a lexical pre-scan, linear in the
// input, that runs before the decoder; a malformed file it misreads is the
// decoder's to refuse.
func nestingDepth(raw []byte) int {
	depth, deepest := 0, 0
	n := len(raw)
	for i := 0; i < n; i++ {
		switch c := raw[i]; c {
		case '#':
			for i < n && raw[i] != '\n' {
				i++
			}
		case '"', '\'':
			i = skipString(raw, i, c)
		case '[', '{':
			depth++
			if depth > deepest {
				deepest = depth
			}
		case ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return deepest
}

// skipString returns the index of the last byte of the string that opens at
// raw[i] (quote q): a basic or literal string, one-line or multi-line. A
// basic string honours backslash escapes; a one-line string also ends at a
// newline (the decoder refuses it).
func skipString(raw []byte, i int, q byte) int {
	const backslash = 0x5c
	n := len(raw)
	multi := i+2 < n && raw[i+1] == q && raw[i+2] == q
	if multi {
		for j := i + 3; j < n; j++ {
			if q == '"' && raw[j] == backslash {
				j++
				continue
			}
			if raw[j] == q && j+2 < n && raw[j+1] == q && raw[j+2] == q {
				return j + 2
			}
		}
		return n
	}
	for j := i + 1; j < n; j++ {
		switch {
		case q == '"' && raw[j] == backslash:
			j++
		case raw[j] == q, raw[j] == '\n':
			return j
		}
	}
	return n
}
