package sectestpath

import (
	"path"
	"strings"
)

// sectestpath.go is THE closed test-path class table (lane SEC-G5, moved
// here from internal/secrulepack in lane SEC-P4 decision 13 so the code
// rules' per-rule test exclusion and the diff observations read one table
// without the diff observations linking the rule pack): a rule whose
// pack.json row sets exclude_tests drops its results in a path of one of
// these classes, and secdiffobs.IsTestPath names a test file by it. The table is walked
// top-down; the first class that matches names the path. Matching is on
// the lowercased, slash-separated project-relative path, except the JVM and
// C# rows, which match the original-case file stem ending in "Test" or
// "Tests" (FooTest.java, FooTests.cs), so Latest.java or Contest.cs is not a
// test (audit finding 2).

// testPathRow is one class.
type testPathRow struct {
	class string
	// match reads the lowercased directory names, the lowercased base name
	// and the original-case base name.
	match func(dirs []string, base, orig string) bool
}

// testDirs are directory names that hold tests or test data.
var testDirs = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "spec": true, "specs": true,
	"testdata": true, "test-data": true, "test_data": true, "fixtures": true, "__fixtures__": true,
	"e2e": true, "mocks": true, "__mocks__": true, "testing": true, "integration-tests": true,
}

// jsTestExt are the extensions a .test. or .spec. file may carry.
var jsTestExt = map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true, ".mts": true, ".cts": true}

var testPathTable = []testPathRow{
	{"test_dir", func(dirs []string, _, _ string) bool {
		for _, d := range dirs {
			if testDirs[d] {
				return true
			}
		}
		return false
	}},
	{"go_test", func(_ []string, b, _ string) bool { return strings.HasSuffix(b, "_test.go") }},
	{"python_test", func(_ []string, b, _ string) bool {
		return path.Ext(b) == ".py" && (strings.HasPrefix(b, "test_") || strings.HasSuffix(b, "_test.py") || b == "conftest.py")
	}},
	{"js_test", func(_ []string, b, _ string) bool {
		stem := strings.TrimSuffix(b, path.Ext(b))
		return jsTestExt[path.Ext(b)] && (strings.HasSuffix(stem, ".test") || strings.HasSuffix(stem, ".spec"))
	}},
	{"jvm_test", func(_ []string, b, orig string) bool {
		return (path.Ext(b) == ".java" || path.Ext(b) == ".kt") && testStem(orig)
	}},
	{"csharp_test", func(_ []string, b, orig string) bool {
		return path.Ext(b) == ".cs" && testStem(orig)
	}},
	// The RSpec convention outside a spec directory (lane SEC-P4: the
	// diff observations' test-path check reads this table since then, and
	// it knew *_spec.rb).
	{"ruby_test", func(_ []string, b, _ string) bool { return strings.HasSuffix(b, "_spec.rb") }},
}

// testStem reports whether an original-case base name's stem (the name
// without its extension) ends in "Test" or "Tests", the JVM and .NET test
// class convention. The case is the signal: "Latest", "Contest", "Attest"
// and "Protest" end in lowercase "test" and are not tests.
func testStem(orig string) bool {
	stem := strings.TrimSuffix(orig, path.Ext(orig))
	return strings.HasSuffix(stem, "Test") || strings.HasSuffix(stem, "Tests")
}

// Class returns the class of a test path and true, or "" and false.
func Class(rel string) (string, bool) {
	slashed := strings.ReplaceAll(rel, `\`, "/")
	p := strings.ToLower(slashed)
	dir, base := path.Split(p)
	_, orig := path.Split(slashed)
	dirs := strings.Split(strings.Trim(dir, "/"), "/")
	for _, row := range testPathTable {
		if row.match(dirs, base, orig) {
			return row.class, true
		}
	}
	return "", false
}

// Classes returns the class names, in table order.
func Classes() []string {
	out := make([]string, 0, len(testPathTable))
	for _, r := range testPathTable {
		out = append(out, r.class)
	}
	return out
}
