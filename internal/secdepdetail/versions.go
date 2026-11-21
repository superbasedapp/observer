package secdepdetail

import (
	"regexp"
	"strings"
)

// Comparator orders two versions of one ecosystem: it returns -1, 0 or 1
// and ok false when either version is not one it can parse (then nothing
// is suggested; a version is never compared by guesswork).
type Comparator func(a, b string) (int, bool)

// comparatorRows is the per-ecosystem comparator table, walked top-down;
// an ecosystem with no row uses compareDotted (semver-like dotted numeric
// with a pre-release tail).
var comparatorRows = []struct {
	ecosystem string
	compare   Comparator
}{
	{"Go", compareGo},
	{"PyPI", comparePEP440},
	{"Packagist", compareVPrefixed},
}

// ComparatorFor returns the ecosystem's comparator (comparatorRows, else
// the dotted default).
func ComparatorFor(eco string) Comparator {
	for _, r := range comparatorRows {
		if r.ecosystem == eco {
			return r.compare
		}
	}
	return compareDotted
}

// dotted is a parsed semver-like version: numeric release segments and
// pre-release identifiers.
type dotted struct {
	release []string
	pre     []string
}

// parseDotted parses "1.2.3", "1.2", "1.2.3-rc.1" or "1.2.3+build" (build
// metadata is ignored). Every release segment must be all digits.
func parseDotted(s string) (dotted, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	rel, pre, hasPre := strings.Cut(s, "-")
	if rel == "" {
		return dotted{}, false
	}
	var d dotted
	for _, seg := range strings.Split(rel, ".") {
		if !allDigits(seg) {
			return dotted{}, false
		}
		d.release = append(d.release, seg)
	}
	if hasPre {
		if pre == "" {
			return dotted{}, false
		}
		for _, id := range strings.Split(pre, ".") {
			if id == "" {
				return dotted{}, false
			}
			for i := 0; i < len(id); i++ {
				c := id[i]
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
					return dotted{}, false
				}
			}
			d.pre = append(d.pre, id)
		}
	}
	return d, true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// compareDigits orders two digit strings numerically, of any length.
func compareDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	switch {
	case len(a) != len(b):
		return sign(len(a) - len(b))
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// compareRelease orders numeric segment lists, a missing segment reading
// as 0 ("1.0" == "1.0.0").
func compareRelease(a, b []string) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := compareDigits(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// compareDotted is the default comparator: release segments numerically,
// then a version with no pre-release above one with, pre-release
// identifiers compared as semver does (numeric below alphanumeric).
func compareDotted(a, b string) (int, bool) {
	x, ok1 := parseDotted(a)
	y, ok2 := parseDotted(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	if c := compareRelease(x.release, y.release); c != 0 {
		return c, true
	}
	switch {
	case len(x.pre) == 0 && len(y.pre) == 0:
		return 0, true
	case len(x.pre) == 0:
		return 1, true
	case len(y.pre) == 0:
		return -1, true
	}
	for i := 0; i < len(x.pre) && i < len(y.pre); i++ {
		p, q := x.pre[i], y.pre[i]
		pn, qn := allDigits(p), allDigits(q)
		switch {
		case pn && qn:
			if c := compareDigits(p, q); c != 0 {
				return c, true
			}
		case pn:
			return -1, true
		case qn:
			return 1, true
		case p != q:
			if p < q {
				return -1, true
			}
			return 1, true
		}
	}
	return sign(len(x.pre) - len(y.pre)), true
}

// compareGo is Go module versions: the leading "v" stripped, then the
// dotted comparator (a pseudo-version is a pre-release; "+incompatible"
// is build metadata).
func compareGo(a, b string) (int, bool) {
	return compareDotted(strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v"))
}

// compareVPrefixed is the dotted comparator with an optional leading "v"
// (Packagist versions are often tagged "v4.0.0").
func compareVPrefixed(a, b string) (int, bool) {
	return compareDotted(strings.TrimPrefix(strings.TrimPrefix(a, "v"), "V"), strings.TrimPrefix(strings.TrimPrefix(b, "v"), "V"))
}

// pep440Pattern is PEP 440's public version (normalised lower case): epoch,
// release, pre, post, dev and a local label (ignored for ordering).
var pep440Pattern = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?` +
	`(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d+)?)?` +
	`(?:[-_.]?(dev)[-_.]?(\d+)?)?` +
	`(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

// pep440 is the ordering key of one PEP 440 version.
type pep440 struct {
	epoch   string
	release []string
	// preRank: -2 a dev-only release (sorts before every pre-release), 0
	// alpha, 1 beta, 2 rc, 3 no pre-release.
	preRank int
	preNum  string
	hasPost bool
	postNum string
	hasDev  bool
	devNum  string
}

func parsePEP440(s string) (pep440, bool) {
	m := pep440Pattern.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return pep440{}, false
	}
	v := pep440{epoch: orZero(m[1]), release: strings.Split(m[2], "."), preRank: 3}
	switch m[3] {
	case "a", "alpha":
		v.preRank = 0
	case "b", "beta":
		v.preRank = 1
	case "c", "rc", "pre", "preview":
		v.preRank = 2
	}
	if m[3] != "" {
		v.preNum = orZero(m[4])
	}
	if m[5] != "" || m[6] != "" {
		v.hasPost = true
		v.postNum = orZero(m[5] + m[7])
	}
	if m[8] != "" {
		v.hasDev, v.devNum = true, orZero(m[9])
	}
	if v.preRank == 3 && !v.hasPost && v.hasDev {
		v.preRank = -2
	}
	return v, true
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// comparePEP440 orders PyPI versions as packaging does for public
// versions: epoch, release (zero padded), then dev-only below a
// pre-release below the final release, post-releases above it, and a dev
// release below the same version without one.
func comparePEP440(a, b string) (int, bool) {
	x, ok1 := parsePEP440(a)
	y, ok2 := parsePEP440(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	if c := compareDigits(x.epoch, y.epoch); c != 0 {
		return c, true
	}
	if c := compareRelease(x.release, y.release); c != 0 {
		return c, true
	}
	if x.preRank != y.preRank {
		return sign(x.preRank - y.preRank), true
	}
	if x.preRank >= 0 && x.preRank < 3 {
		if c := compareDigits(x.preNum, y.preNum); c != 0 {
			return c, true
		}
	}
	if x.hasPost != y.hasPost {
		if x.hasPost {
			return 1, true
		}
		return -1, true
	}
	if c := compareDigits(x.postNum, y.postNum); x.hasPost && c != 0 {
		return c, true
	}
	if x.hasDev != y.hasDev {
		if x.hasDev {
			return -1, true
		}
		return 1, true
	}
	if x.hasDev {
		return compareDigits(x.devNum, y.devNum), true
	}
	return 0, true
}

// nameNormalizers is the per-ecosystem package-name normalisation table
// (how an OSV record's affected[].package.name is matched to the finding's
// package); an ecosystem with no row compares names exactly.
var nameNormalizers = []struct {
	ecosystem string
	normalize func(string) string
}{
	{"PyPI", normalizePEP503},
	{"NuGet", strings.ToLower},
	{"Packagist", strings.ToLower},
}

var pep503Run = regexp.MustCompile(`[-_.]+`)

// normalizePEP503 is PEP 503's name normalisation: lower case, every run
// of '-', '_' and '.' a single '-'.
func normalizePEP503(name string) string {
	return pep503Run.ReplaceAllString(strings.ToLower(name), "-")
}

// NormalizeName is the ecosystem's comparable form of a package name.
func NormalizeName(eco, name string) string {
	for _, r := range nameNormalizers {
		if r.ecosystem == eco {
			return r.normalize(name)
		}
	}
	return name
}

// sameVersion reports whether a version written in a lockfile is the
// finding's version (a leading "v" ignored on either side: go.mod and
// composer.lock write it, the evidence may not).
func sameVersion(written, version string) bool {
	if written == version {
		return true
	}
	trim := func(s string) string { return strings.TrimPrefix(s, "v") }
	return trim(written) != "" && trim(written) == trim(version)
}
