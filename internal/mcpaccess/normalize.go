package mcpaccess

import "sort"

// Normalized is a Spec that passed Lint with no error, with disabled and
// expired grants removed and the rest in canonical order: hierarchy level
// ascending (org 0 > team 1 > project 2 - the org floor is walked first),
// then ord, then id. Every compiler takes a Normalized.
type Normalized struct {
	Registry Registry
	Grants   []Grant
	Problems []Problem
}

// Normalize lints spec and, when no error-severity problem is present,
// returns the canonical grant order. Warnings are carried in
// Normalized.Problems. An error-severity finding is returned as *LintError.
//
// Hierarchy merge (R8.23.e "org > team > project floor"): the effect
// precedence deny > ask > allow is GLOBAL, so a deeper level can only
// narrow what a shallower one allows, never relax an org-level deny or ask;
// when two grants of the same effect match, the shallowest level (then the
// lowest ord) is the one reported as matched.
func Normalize(spec Spec, now int64) (Normalized, error) {
	ps := Lint(spec, now)
	if HasErrors(ps) {
		return Normalized{Problems: ps}, &LintError{Problems: ps}
	}
	out := Normalized{Registry: spec.Registry, Problems: ps}
	for _, g := range spec.Grants {
		if !g.Enabled {
			continue
		}
		if now > 0 && g.Conditions.ExpiresAt > 0 && g.Conditions.ExpiresAt <= now {
			continue
		}
		if g.AuditClass == "" {
			g.AuditClass = "normal"
		}
		if g.Subject.Kind == "" {
			g.Subject.Kind = SubjectAny
		}
		if g.Resource.Name == "*" {
			g.Resource.Name = ""
		}
		out.Grants = append(out.Grants, g)
	}
	sort.SliceStable(out.Grants, func(i, j int) bool {
		a, b := out.Grants[i], out.Grants[j]
		if a.HierarchyLevel != b.HierarchyLevel {
			return a.HierarchyLevel < b.HierarchyLevel
		}
		if a.Ord != b.Ord {
			return a.Ord < b.Ord
		}
		return a.ID < b.ID
	})
	return out, nil
}

// precedenceLess orders grants for resolution: effect precedence first
// (deny > ask > allow), then the canonical hierarchy/ord/id order.
func precedenceLess(a, b Grant) bool {
	if effectPrecedence[a.Effect] != effectPrecedence[b.Effect] {
		return effectPrecedence[a.Effect] < effectPrecedence[b.Effect]
	}
	if a.HierarchyLevel != b.HierarchyLevel {
		return a.HierarchyLevel < b.HierarchyLevel
	}
	if a.Ord != b.Ord {
		return a.Ord < b.Ord
	}
	return a.ID < b.ID
}
