package update

import "testing"

// TestComparePrecedenceContrast pins the re-export against the contrast that
// makes it necessary: CompareSemver strips the pre-release, ComparePrecedence
// orders a release candidate below its release. The full precedence table
// lives with the owner, updatespec.TestComparePrecedence.
func TestComparePrecedenceContrast(t *testing.T) {
	if c, ok := ComparePrecedence("1.35.0-rc.1", "1.35.0"); c != -1 || !ok {
		t.Fatalf("ComparePrecedence(1.35.0-rc.1, 1.35.0) = %d, %v; want -1, true", c, ok)
	}
	if c, _ := CompareSemver("1.35.0-rc.1", "1.35.0"); c != 0 {
		t.Fatalf("CompareSemver strips the pre-release; this test documents that, got %d", c)
	}
}
