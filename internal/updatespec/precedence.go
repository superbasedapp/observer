package updatespec

import (
	"strconv"
	"strings"
)

// ComparePrecedence orders two versions by SemVer 2.0 precedence and returns
// -1 / 0 / +1 for a < b / a == b / a > b, with ok=false when either side does
// not parse. The X.Y.Z core compares numerically; a version WITH a pre-release
// is LOWER than the same core without one ("1.35.0-rc.1" < "1.35.0");
// pre-release identifiers compare one by one (numeric ones numerically and
// below alphanumeric ones, a shorter list below a longer one it prefixes);
// build metadata ("+...") is ignored.
//
// It differs from update.CompareSemver ON PURPOSE. CompareSemver strips the
// pre-release because it mirrors the dashboard's update nag. A WIRE GATE ("does
// this agent understand field X, which first shipped in release R?") must not:
// a release candidate of R may predate the decoder, and crediting it with R's
// fields makes it fail the signature check of the document that carries them
// (the D-264 / D-265 class). Use this one for every field gate.
//
// It is the one owner: internal/update re-exports it as
// update.ComparePrecedence, and the node.governance compiler
// (internal/policyfam/nodegov) orders its released-target table with it.
func ComparePrecedence(a, b string) (int, bool) {
	ca, pa, oka := parsePrecedence(a)
	cb, pb, okb := parsePrecedence(b)
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

// parsePrecedence splits "vX.Y.Z[-pre][+build]" into its numeric core and its
// pre-release identifiers. Parts of the core beyond the third are ignored, as
// update.ParseSemver ignores them; an empty pre-release identifier does not
// parse.
func parsePrecedence(v string) (core [3]int, pre []string, ok bool) {
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

// comparePreIdent compares two pre-release identifiers by SemVer 2.0 rules.
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
