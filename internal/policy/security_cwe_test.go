package policy

import (
	"reflect"
	"testing"
)

func TestSafeCWEs(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{"CWE-79": true, "CWE-1333": true, "CWE-": false, "CWE-123456": false, "cwe-79": false, "CWE-7a": false, "IGNORE": false} {
		if got := ValidCWE(in); got != want {
			t.Errorf("ValidCWE(%q) = %v", in, got)
		}
	}
	got := SafeCWEs([]string{"CWE-1", "bad", "CWE-2", "CWE-3", "CWE-4", "CWE-5"})
	if !reflect.DeepEqual(got, []string{"CWE-1", "CWE-2", "CWE-3", "CWE-4"}) {
		t.Errorf("SafeCWEs = %v", got)
	}
}
