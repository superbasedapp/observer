package orgcontract

import (
	"fmt"
	"sort"
)

// The org's project_unknown decision (security plan section 7.11 "Offline
// launch" and the hard-cases table, PR14; lane sec-p2a). It rides the
// org-wide signed guard bundle as one table:
//
//	[project_audience]
//	unknown = "ask"
//
// and says what the guard does where a project bundle reaches the member but
// the project layer is unknown: the mapping is past its offline lifetime, the
// resolve call failed above the mapping cap, or a matched project's envelope
// is missing. "none" (the default) keeps today's behaviour (the org, team and
// member layers apply, the load issue is recorded); "ask" adds a floor that
// asks on an individual node and denies on a managed node, never weaker than
// the rule verdict (PR14; a host that cannot ask denies, Q27).
//
// This file is the ONE owner of the vocabulary: the guard (node side, every
// layer's parse and the floor) and internal/orgserver/guardbundle (publish
// validation and strictest-wins composition) both call it.

// ProjectAudienceTable is the bundle's TOML table name.
const ProjectAudienceTable = "project_audience"

// ProjectUnknownKey is the key inside ProjectAudienceTable.
const ProjectUnknownKey = "unknown"

// project_unknown values, in ascending strictness. The first is the default.
const (
	ProjectUnknownNone = "none"
	ProjectUnknownAsk  = "ask"
)

var projectUnknownValues = []string{ProjectUnknownNone, ProjectUnknownAsk}

func projectUnknownRank(v string) int {
	for i, x := range projectUnknownValues {
		if x == v {
			return i
		}
	}
	return -1
}

// DecodeProjectAudienceTable reads a decoded `[project_audience]` table. It
// returns the effective project_unknown value and the problems found (an
// unknown key, a non-string value, an unknown value). The caller decides what
// a problem means: the authoring gate refuses the bundle, a node accepts it
// and notes the problem. A value this binary does not know (a newer server's)
// reads as the strictest value it knows, never as the default: unknown never
// relaxes (PR14).
func DecodeProjectAudienceTable(raw map[string]any) (string, []string) {
	value := ProjectUnknownNone
	var problems []string
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k != ProjectUnknownKey {
			problems = append(problems, fmt.Sprintf("%s.%s is not a setting (known: %s)", ProjectAudienceTable, k, ProjectUnknownKey))
			continue
		}
		s, ok := raw[k].(string)
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s.%s must be a string", ProjectAudienceTable, k))
			value = projectUnknownValues[len(projectUnknownValues)-1]
		case projectUnknownRank(s) < 0:
			problems = append(problems, fmt.Sprintf("%s.%s = %q is not one of %s, %s", ProjectAudienceTable, k, s, ProjectUnknownNone, ProjectUnknownAsk))
			value = projectUnknownValues[len(projectUnknownValues)-1]
		default:
			value = s
		}
	}
	return value, problems
}

// StrictestProjectUnknown folds several bundles' values (strictest wins; an
// empty value is the default).
func StrictestProjectUnknown(values ...string) string {
	best := ProjectUnknownNone
	for _, v := range values {
		if projectUnknownRank(v) > projectUnknownRank(best) {
			best = v
		}
	}
	return best
}
