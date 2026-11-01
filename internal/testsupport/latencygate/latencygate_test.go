package latencygate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListed(t *testing.T) {
	list := filepath.Join(t.TempDir(), "latency-tests.txt")
	body := "# comment\n\ninternal/guard\tTestA\ninternal/scrub\tTestB\nbad line\n"
	if err := os.WriteFile(list, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		pkg, test string
		want      bool
	}{
		{"internal/guard", "TestA", true},
		{"internal/scrub", "TestB", true},
		{"internal/guard", "TestB", false},
		{"internal/routing", "TestA", false},
		{"# comment", "", false},
	}
	for _, c := range cases {
		got, err := Listed(list, c.pkg, c.test)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("Listed(%q, %q) = %v, want %v", c.pkg, c.test, got, c.want)
		}
	}
	if _, err := Listed(filepath.Join(t.TempDir(), "missing"), "p", "T"); err == nil {
		t.Error("a missing list must be an error")
	}
}

// TestCheckedInListNamesRealTests keeps the list honest in the other
// direction: every listed test is declared in its package.
func TestCheckedInListNamesRealTests(t *testing.T) {
	root, ok := moduleRoot()
	if !ok {
		t.Skip("module root not found (a -trimpath build)")
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ListFile)))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range splitLines(string(data)) {
		pkg, test := line[0], line[1]
		n++
		files, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pkg), "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range files {
			b, err := os.ReadFile(f) //nolint:gosec // G304: a test file of this module
			if err != nil {
				t.Fatal(err)
			}
			if containsFunc(string(b), test) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s lists %s in %s, which declares no such test", ListFile, test, pkg)
		}
	}
	if n == 0 {
		t.Fatalf("%s lists no test: the latency step would be vacuous", ListFile)
	}
}
