package secdiffobs

import "testing"

// TestIsTestPathReadsTheOneTable (lane SEC-P4 decision 13): the diff
// observations' test-path check is the code rules' original-case class
// table, so the JVM and C# near misses are not tests where the old
// lowercase suffix read them as tests.
func TestIsTestPathReadsTheOneTable(t *testing.T) {
	for p, want := range map[string]bool{
		"src/main/java/FooTest.java":    true,
		"src/FooTests.cs":               true,
		"Api/UserTest.kt":               true,
		"pkg/thing_test.go":             true,
		"app/models/user_spec.rb":       true,
		"web/a.test.ts":                 true,
		"tests/helpers.py":              true,
		"src/main/java/Latest.java":     false,
		"src/Contest.cs":                false,
		"src/Protest.java":              false,
		"src/Attest.kt":                 false,
		"src/latesttest.java":           false,
		"README.md":                     false,
		`src\main\java\WidgetTest.java`: true,
	} {
		if got := IsTestPath(p); got != want {
			t.Errorf("%s: %v, want %v", p, got, want)
		}
	}
}
