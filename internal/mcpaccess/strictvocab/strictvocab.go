package strictvocab

import (
	"sort"
	"strings"
)

// The accepted classes. Naming a class makes every call it matches
// audit-before-act SYNCHRONOUSLY instead of the durable-async default. The
// default set is NONE.
const (
	// Governed is the GOVERNED decision class (doc3 §9.1 method partition,
	// mcp_decision.decision_class): tools/call, resources/read, prompts/get,
	// completion/complete, tasks/*, subscriptions/listen and
	// resources/(un)subscribe.
	Governed = "governed"
	// Catalogue is the CATALOGUE decision class: tools/list, resources/list,
	// resources/templates/list, prompts/list, server/discover, ping and the
	// handshake / notification methods.
	Catalogue = "catalogue"
	// Destructive is a tools/call whose tool the server's approved snapshot
	// marks destructive (an explicit annotations.destructiveHint: true), or
	// whose approved descriptor cannot be read at decision time: an
	// unclassifiable tool call is treated as destructive, the stricter
	// reading for an audit setting.
	Destructive = "destructive"
	// Write is every call whose grant ACTION carries the write effect class
	// (the call action, i.e. tools/call), whatever the matched grant's
	// effect (an ask grant included).
	Write = "write"
)

// Classes is the accepted audit_strict_classes vocabulary, in the order the
// settings form lists it.
var Classes = []string{Governed, Catalogue, Destructive, Write}

// Retirement is one RETIRED audit_strict_classes value: accepted by an
// earlier build, matched by nothing in the shipped model, and converted on
// read to the set Into, which matches a superset of every call the retired
// value could reasonably have meant (a retirement never weakens auditing).
type Retirement struct {
	Value  string
	Into   []string
	Reason string
}

// retired is the retirement table. "egress" (an early config vocabulary
// entry with no definition in doc3; egress is a deployment ROUTING setting,
// egress_mode, not a call class) is converted to every decision class,
// governed + catalogue: every call that can reach an upstream server is then
// audited before it runs, whichever meaning was intended.
var retired = []Retirement{
	{
		Value: "egress", Into: []string{Catalogue, Governed},
		Reason: "egress has no call-class meaning in the shipped model (egress is the egress_mode routing setting); converted to every decision class, governed + catalogue (AA-69)",
	},
}

// Retired returns a copy of the retirement table.
func Retired() []Retirement {
	out := make([]Retirement, len(retired))
	for i, r := range retired {
		r.Into = append([]string(nil), r.Into...)
		out[i] = r
	}
	return out
}

// RetiredValue reports the retirement row for value, if value is retired.
func RetiredValue(value string) (Retirement, bool) {
	for _, r := range retired {
		if r.Value == value {
			return r, true
		}
	}
	return Retirement{}, false
}

// Normalized is Normalize's result.
type Normalized struct {
	// Classes is the canonical set: trimmed, de-duplicated, sorted, every
	// retired value replaced by its Into set. An UNKNOWN value is kept as is
	// (a validator refuses it; the PDP reads it as strict-everything), never
	// silently dropped.
	Classes []string
	// Retired lists the retired values that were converted, sorted.
	Retired []string
	// Unknown lists the values that are neither accepted nor retired, sorted.
	Unknown []string
}

// Changed reports whether normalization converted a retired value.
func (n Normalized) Changed() bool { return len(n.Retired) > 0 }

// CSV renders Classes in the column's comma-separated form.
func (n Normalized) CSV() string { return strings.Join(n.Classes, ",") }

// Normalize canonicalizes an audit_strict_classes list (see Normalized). It
// is the one conversion every reader applies: the org server's settings
// load, its boot migration of the stored row, the TOML seed and the PDP's
// policy compile.
func Normalize(in []string) Normalized {
	set := map[string]bool{}
	retiredSeen := map[string]bool{}
	unknown := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if r, ok := RetiredValue(v); ok {
			retiredSeen[v] = true
			for _, c := range r.Into {
				set[c] = true
			}
			continue
		}
		if !isClass(v) {
			unknown[v] = true
		}
		set[v] = true
	}
	return Normalized{Classes: sortedKeys(set), Retired: sortedKeys(retiredSeen), Unknown: sortedKeys(unknown)}
}

func isClass(v string) bool {
	for _, c := range Classes {
		if c == v {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
