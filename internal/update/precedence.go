package update

import "github.com/marmutapp/superbased-observer/internal/updatespec"

// ComparePrecedence orders two versions by SemVer 2.0 precedence and returns
// -1 / 0 / +1 for a < b / a == b / a > b, with ok=false when either side does
// not parse. A version WITH a pre-release is LOWER than the same core without
// one ("1.35.0-rc.1" < "1.35.0"), and build metadata is ignored.
//
// It differs from CompareSemver ON PURPOSE: use this one for every wire field
// gate (the D-264 / D-265 class). The rules and their owner live in
// updatespec.ComparePrecedence; this re-export keeps update's callers
// unchanged.
func ComparePrecedence(a, b string) (int, bool) {
	return updatespec.ComparePrecedence(a, b)
}
