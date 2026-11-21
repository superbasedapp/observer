package guardrecipe

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// render writes the compiled recipe file: the header, the top-level disable
// list (it must precede every table in TOML), the [[override]] rows grouped
// by origin, then the [[rule]] definitions.
func render(c *Compiled, level *Recipe, packs []*Recipe, ruleRows []map[string]any) []byte {
	var b strings.Builder
	b.WriteString("# Observer guard recipe - a managed file.\n")
	b.WriteString("# Written by `observer guard recipe apply` (or the Security page's Recipes card)\n")
	b.WriteString("# and removed by `observer guard recipe remove`. Do not edit it: the next apply\n")
	b.WriteString("# rewrites it. Put your own rules in the policy file beside it, which loads\n")
	b.WriteString("# after this one and wins.\n")
	b.WriteString(c.Meta.headerLine())
	b.WriteString("\n")
	if level != nil {
		fmt.Fprintf(&b, "# level: %s v%d (%s)\n", level.Name, level.Version, oneLine(level.Title))
	}
	for _, p := range packs {
		fmt.Fprintf(&b, "# pack:  %s v%d (%s)\n", p.Name, p.Version, oneLine(p.Title))
	}
	if len(c.Disable) > 0 {
		b.WriteString("\n# The level's mode is off: these rules are off in this project.\n")
		b.WriteString("disable = [\n")
		for _, id := range c.Disable {
			fmt.Fprintf(&b, "  %s,\n", tomlString(id))
		}
		b.WriteString("]\n")
	}
	last := ""
	for _, ov := range c.Overrides {
		group := string(ov.Origin) + ":" + ov.Recipe
		if group != last {
			last = group
			b.WriteString("\n")
			switch ov.Origin {
			case OriginMode:
				b.WriteString("# The level's mode, held in this project whatever the machine-wide mode is.\n")
			default:
				fmt.Fprintf(&b, "# --- %s %s\n", ov.Origin, ov.Recipe)
			}
		}
		if ov.Kept != "" {
			fmt.Fprintf(&b, "# %s\n", oneLine(ov.Kept))
		}
		if ov.Decision == "" && ov.Enforce == nil {
			// A pack row a stricter recipe row kept, or one that could only
			// lower the rule (a compile problem): nothing to write.
			continue
		}
		if ov.Note != "" {
			fmt.Fprintf(&b, "# %s\n", oneLine(ov.Note))
		}
		b.WriteString("[[override]]\n")
		fmt.Fprintf(&b, "rule = %s\n", tomlString(ov.Rule))
		if ov.Decision != "" {
			fmt.Fprintf(&b, "decision = %s\n", tomlString(ov.Decision))
		}
		if ov.Enforce != nil {
			fmt.Fprintf(&b, "enforce = %v\n", *ov.Enforce)
		}
	}
	if len(ruleRows) > 0 {
		b.WriteString("\n# --- rules the selected recipes define\n")
		for _, rr := range ruleRows {
			renderRule(&b, rr)
		}
	}
	return []byte(b.String())
}

// renderRule writes one [[rule]] table: id first, the other scalar keys in
// name order, then each sub-table ([rule.match]).
func renderRule(b *strings.Builder, row map[string]any) {
	b.WriteString("\n[[rule]]\n")
	fmt.Fprintf(b, "id = %s\n", tomlString(RuleID(row)))
	keys := make([]string, 0, len(row))
	for k := range row {
		if k != "id" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var tables []string
	for _, k := range keys {
		if _, isTable := row[k].(map[string]any); isTable {
			tables = append(tables, k)
			continue
		}
		fmt.Fprintf(b, "%s = %s\n", tomlKey(k), tomlValue(row[k]))
	}
	for _, k := range tables {
		sub := row[k].(map[string]any)
		fmt.Fprintf(b, "[rule.%s]\n", tomlKey(k))
		subKeys := make([]string, 0, len(sub))
		for sk := range sub {
			subKeys = append(subKeys, sk)
		}
		sort.Strings(subKeys)
		for _, sk := range subKeys {
			fmt.Fprintf(b, "%s = %s\n", tomlKey(sk), tomlValue(sub[sk]))
		}
	}
}

// tomlKey renders a bare key when it can, a quoted one otherwise.
func tomlKey(k string) string {
	if k == "" {
		return `""`
	}
	for _, r := range k {
		if !(r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return tomlString(k)
		}
	}
	return k
}

// tomlValue renders a decoded TOML value back to TOML. The decoder only
// produces these shapes; anything else renders as an empty string so the
// guard's lint (which every apply runs) refuses the file loudly.
func tomlValue(v any) string {
	switch x := v.(type) {
	case string:
		return tomlString(x)
	case bool:
		return strconv.FormatBool(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	case float64:
		if math.IsInf(x, 0) || math.IsNaN(x) {
			return `""`
		}
		s := strconv.FormatFloat(x, 'f', -1, 64)
		if !strings.ContainsAny(s, ".e") {
			s += ".0"
		}
		return s
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			parts = append(parts, tomlValue(e))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []string:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			parts = append(parts, tomlString(e))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return `""`
	}
}

// tomlString renders a TOML basic string with every character TOML requires
// escaped (quote, backslash, control characters).
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// oneLine flattens text for a comment line.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
