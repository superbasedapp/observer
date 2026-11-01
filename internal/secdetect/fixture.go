package secdetect

import (
	"path"
	"strings"
)

// fixturePathClass is one row of the closed fixture and test-data path
// table (security plan section 5.3): a typed-secret finding in such a path
// is lowered from deny to ask under enforce, never ignored.
type fixturePathClass struct {
	// dir is a directory name that marks the class anywhere in the path.
	dir string
	// suffix is a file-name suffix that marks the class.
	suffix string
}

// fixturePathClasses is THE fixture path table, one test case per row.
var fixturePathClasses = []fixturePathClass{
	{dir: "testdata"},
	{dir: "fixtures"},
	{dir: "__fixtures__"},
	{dir: "__tests__"},
	{dir: "__mocks__"},
	{dir: "mocks"},
	{dir: "test"},
	{dir: "tests"},
	{dir: "spec"},
	{dir: "examples"},
	{suffix: "_test.go"},
	{suffix: ".test.ts"},
	{suffix: ".test.js"},
	{suffix: ".spec.ts"},
	{suffix: ".spec.js"},
	{suffix: "_test.py"},
	{suffix: ".example"},
	{suffix: ".sample"},
}

// IsFixturePath reports whether p (slash or backslash separated, relative
// or absolute) is in a fixture or test-data class. Case is folded.
func IsFixturePath(p string) bool {
	if p == "" {
		return false
	}
	p = strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	base := path.Base(p)
	dirs := strings.Split(path.Dir(p), "/")
	for _, c := range fixturePathClasses {
		if c.suffix != "" && strings.HasSuffix(base, c.suffix) {
			return true
		}
		if c.dir == "" {
			continue
		}
		for _, d := range dirs {
			if d == c.dir {
				return true
			}
		}
	}
	return false
}
