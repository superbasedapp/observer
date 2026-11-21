package secdepdetail

import "sort"

// MaxFixedVersions caps the fixed versions listed.
const MaxFixedVersions = 20

// Fix is the upgrade the advisories support: every fixed version their
// ranges name, and the one suggested upgrade when a single clear answer
// exists ("" otherwise).
type Fix struct {
	FixedVersions []string
	Suggested     string
}

// interval is one parsed affected range.
type interval struct {
	lo, hi string // lo "" = from the start
	hiIncl bool   // hi is last_affected (inclusive)
	open   bool   // no upper bound
}

// SuggestFix collects the fixed versions of the advisories' ranges and
// picks the smallest one above the current version that no listed range
// marks affected, compared with the ecosystem's comparator
// (ComparatorFor). It suggests nothing when any version involved does not
// parse, when the current version sits in no listed range (the comparator
// and the scanner disagree, so the answer is not clear), when a range
// holding the current version has no fix, or when no fixed version clears
// every range. It never invents a version.
func SuggestFix(eco, current string, advs []Advisory) Fix {
	cmp := ComparatorFor(eco)
	var fix Fix
	seen := map[string]bool{}
	var ivs []interval
	parsed := true
	for _, a := range advs {
		for _, r := range a.Ranges {
			if r.Fixed != "" && !seen[r.Fixed] {
				seen[r.Fixed] = true
				fix.FixedVersions = append(fix.FixedVersions, r.Fixed)
			}
			iv := interval{lo: r.Introduced}
			switch {
			case r.Fixed != "":
				iv.hi = r.Fixed
			case r.LastAffected != "":
				iv.hi, iv.hiIncl = r.LastAffected, true
			default:
				iv.open = true
			}
			ivs = append(ivs, iv)
		}
	}
	sortVersions(fix.FixedVersions, cmp)
	if len(fix.FixedVersions) > MaxFixedVersions {
		fix.FixedVersions = fix.FixedVersions[:MaxFixedVersions]
	}
	contained := 0
	for _, iv := range ivs {
		hit, ok := iv.contains(cmp, current)
		if !ok {
			parsed = false
			break
		}
		if hit {
			contained++
			if iv.open || iv.hiIncl {
				// The current version's range has no fix.
				return fix
			}
		}
	}
	if !parsed || contained == 0 {
		return fix
	}
	for _, f := range fix.FixedVersions {
		c, ok := cmp(f, current)
		if !ok {
			return fix
		}
		if c <= 0 {
			continue
		}
		unaffected := true
		for _, iv := range ivs {
			hit, ok := iv.contains(cmp, f)
			if !ok {
				return fix
			}
			if hit {
				unaffected = false
				break
			}
		}
		if unaffected {
			fix.Suggested = f
			return fix
		}
	}
	return fix
}

// contains reports whether v is inside the interval; ok false when a bound
// or v does not parse.
func (iv interval) contains(cmp Comparator, v string) (in, ok bool) {
	if iv.lo != "" && iv.lo != "0" {
		c, ok := cmp(v, iv.lo)
		if !ok {
			return false, false
		}
		if c < 0 {
			return false, true
		}
	}
	if iv.open {
		return true, true
	}
	c, ok := cmp(v, iv.hi)
	if !ok {
		return false, false
	}
	if iv.hiIncl {
		return c <= 0, true
	}
	return c < 0, true
}

// sortVersions sorts ascending by cmp when every pair parses, else
// lexically (an order for display only; nothing is suggested from it).
func sortVersions(vs []string, cmp Comparator) {
	ok := true
	sort.SliceStable(vs, func(i, j int) bool {
		c, good := cmp(vs[i], vs[j])
		if !good {
			ok = false
			return vs[i] < vs[j]
		}
		return c < 0
	})
	if !ok {
		sort.Strings(vs)
	}
}
