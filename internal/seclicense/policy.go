package seclicense

import (
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// The engine and rule pack identity of every licence finding.
const (
	// Driver is the engine driver id (the DRIVER_LABEL row "license").
	Driver = "license"
	// Version is the driver, rule and pack version.
	Version = "1"
)

// The rule ids, one per policy table row.
const (
	RuleDenied     = "license.denied"
	RuleNotAllowed = "license.not_allowed"
	RuleUnknown    = "license.unknown"
)

// The Policy.Unknown values.
const (
	UnknownIgnore = "ignore"
	UnknownFlag   = "flag"
)

// Policy is a project's licence policy ([security.licenses]). Deny and
// Allow hold SPDX ids or Class names; an empty Allow allows everything
// not denied. Unknown is UnknownIgnore (the default) or UnknownFlag.
type Policy struct {
	Deny    []string
	Allow   []string
	Unknown string
}

// Active reports whether the policy can produce a finding: a deny or allow
// entry, or unknown licences flagged. The default policy is inactive and
// records nothing.
func (p Policy) Active() bool {
	return len(p.Deny) > 0 || len(p.Allow) > 0 || p.Unknown == UnknownFlag
}

// Verdict is one policy table row's outcome for an entry. Message and
// FixHint are the table's own text, never repository text.
type Verdict struct {
	RuleID   string
	Severity policy.FindingSeverity
	Message  string
	FixHint  string
}

// matcher is a compiled deny or allow list: ids lower-cased, class names
// as classes.
type matcher struct {
	ids     map[string]bool
	classes map[Class]bool
}

func compile(list []string) matcher {
	m := matcher{ids: map[string]bool{}, classes: map[Class]bool{}}
	for _, raw := range list {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if c, ok := classByName(s); ok {
			m.classes[c] = true
			continue
		}
		m.ids[strings.ToLower(normalizeID(s))] = true
	}
	return m
}

// classByName resolves a class name, case-insensitively.
func classByName(s string) (Class, bool) {
	for _, c := range Classes() {
		if strings.EqualFold(string(c), s) {
			return c, true
		}
	}
	return "", false
}

func (m matcher) empty() bool { return len(m.ids) == 0 && len(m.classes) == 0 }

// hits reports whether one licence (an id with its class) is on the list.
func (m matcher) hits(id string, c Class) bool {
	return m.ids[strings.ToLower(id)] || m.classes[c]
}

// leafPass is a predicate over one licence choice (an id and its class).
type leafPass func(id string, c Class) bool

// satisfiable reports whether some choice of the expression's OR
// alternatives passes pass on every part it needs. A WITH node is judged
// on its base id with the class the exception leaves it.
func satisfiable(n *node, pass leafPass) bool {
	switch n.op {
	case tokID:
		return pass(n.id, ClassOf(n.id))
	case tokWith:
		c := classOfNode(n)
		base := n.children[0]
		if base.op != tokID {
			return satisfiable(base, pass)
		}
		return pass(base.id, c)
	case tokOr:
		return satisfiable(n.children[0], pass) || satisfiable(n.children[1], pass)
	case tokAnd:
		return satisfiable(n.children[0], pass) && satisfiable(n.children[1], pass)
	}
	return false
}

// evalInput is what the policy rows decide on.
type evalInput struct {
	deny, allow matcher
	unknown     string
	tree        *node // nil when the licence is empty or malformed
	class       Class
}

// policyRow is one row of the policy table.
type policyRow struct {
	Verdict Verdict
	Match   func(in evalInput) bool
}

// policyTable is the licence policy table, walked top-down; the first
// matching row is the verdict. Severity is capped at medium on every row
// (plan section 12, finding 5).
var policyTable = []policyRow{
	{
		Verdict: Verdict{
			RuleID:   RuleDenied,
			Severity: policy.FindingSeverityMedium,
			Message:  "A dependency's licence is denied by the project's licence policy.",
			FixHint:  "Replace the dependency, or record an exception if its use is cleared.",
		},
		Match: func(in evalInput) bool {
			if in.deny.empty() {
				return false
			}
			if in.tree == nil {
				return in.deny.hits("", ClassUnknown)
			}
			return !satisfiable(in.tree, func(id string, c Class) bool { return !in.deny.hits(id, c) })
		},
	},
	{
		Verdict: Verdict{
			RuleID:   RuleNotAllowed,
			Severity: policy.FindingSeverityMedium,
			Message:  "A dependency's licence is not on the project's licence allow list.",
			FixHint:  "Replace the dependency, add its licence to the allow list, or record an exception.",
		},
		Match: func(in evalInput) bool {
			if in.allow.empty() {
				return false
			}
			if in.tree == nil {
				return !in.allow.hits("", ClassUnknown)
			}
			return !satisfiable(in.tree, func(id string, c Class) bool { return in.allow.hits(id, c) && !in.deny.hits(id, c) })
		},
	},
	{
		Verdict: Verdict{
			RuleID:   RuleUnknown,
			Severity: policy.FindingSeverityLow,
			Message:  "A dependency declares no licence Observer recognizes.",
			FixHint:  "Check the dependency's licence by hand, then allow it or record an exception.",
		},
		Match: func(in evalInput) bool {
			return in.unknown == UnknownFlag && in.class == ClassUnknown
		},
	},
}

// Evaluate walks the policy table top-down for one entry: denied (by id or
// class, with no OR alternative that avoids the deny list), then not
// allowed (Allow non-empty and no OR alternative is allowed), then unknown
// (class unknown and Unknown is UnknownFlag). ok is false when no row
// matches.
func Evaluate(p Policy, e Entry) (Verdict, bool) {
	in := evalInput{deny: compile(p.Deny), allow: compile(p.Allow), unknown: p.Unknown}
	if t, ok := parse(Normalize(e.License)); ok {
		in.tree = t
		in.class = classOfNode(t)
	} else {
		in.class = ClassUnknown
	}
	for _, r := range policyTable {
		if r.Match(in) {
			return r.Verdict, true
		}
	}
	return Verdict{}, false
}

// Findings evaluates every entry and builds the shared finding shape for
// each verdict, unscoped to a project (ProjectFindings scopes the key).
func Findings(p Policy, entries []Entry, now time.Time) []secfinding.Finding {
	return ProjectFindings("", p, entries, now)
}

// ProjectFindings is Findings with the local key scoped to the project
// root hash, so the same dependency in two projects keys differently.
// Every finding is category license, scope manual, baseline unknown (never
// new: it stays out of the commit gate's blocking set) and status open,
// located on the dependency file. The evidence is "<ecosystem>
// <name>@<version>: <normalized licence>" and never the licence text.
func ProjectFindings(rootHash string, p Policy, entries []Entry, now time.Time) []secfinding.Finding {
	if !p.Active() {
		return nil
	}
	var out []secfinding.Finding
	for _, e := range entries {
		v, ok := Evaluate(p, e)
		if !ok {
			continue
		}
		lic := Normalize(e.License)
		if lic == "" {
			lic = "(none declared)"
		}
		ev := secfinding.Clip(e.Ecosystem+" "+e.Name+"@"+e.Version+": "+lic, secfinding.MaxEvidence)
		conf := e.Confidence
		if conf == "" {
			conf = policy.FindingConfidenceMedium
		}
		id := secfinding.TextIdentity(e.Ecosystem + "\x00" + e.Name + "\x00" + e.Version + "\x00" + e.Path)
		out = append(out, secfinding.Normalize(secfinding.Finding{
			LocalKey:         secfinding.LocalKey(rootHash, v.RuleID, id),
			Location:         secfinding.Location{RelPath: e.Path},
			Rule:             secfinding.Rule{ID: v.RuleID, Version: Version, Pack: Driver, PackVersion: Version},
			Engine:           secfinding.Engine{Driver: Driver, DriverVersion: Version},
			Category:         policy.FindingLicense,
			Severity:         v.Severity,
			Confidence:       conf,
			Scope:            policy.FindingScopeManual,
			EvidenceRedacted: ev,
			EvidenceHash:     secfinding.EvidenceHash(ev),
			Message:          v.Message,
			FixHint:          v.FixHint,
			Baseline:         policy.FindingBaselineUnknown,
			Status:           policy.FindingStatusOpen,
			FirstSeen:        now.UTC(),
			LastSeen:         now.UTC(),
		}))
	}
	return out
}
