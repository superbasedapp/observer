package secfinding

import (
	"strings"
	"testing"
)

// TestOrgKeyLifecycle (lane LEFT-SHARED): one secret on two nodes holding
// the org's key gives one org_key; the stored value ships only under the
// version it was made with; nothing ships without a key.
func TestOrgKeyLifecycle(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	a := OrgSecretKey(key, "aws_access_key", " AKIAIOSFODNN7EXAMPLE ")
	b := OrgSecretKey(key, "aws_access_key", "AKIAIOSFODNN7EXAMPLE")
	if a == "" || a != b {
		t.Fatalf("one secret on two nodes: %q vs %q", a, b)
	}
	if OrgSecretKey([]byte(strings.Repeat("x", 32)), "aws_access_key", "AKIAIOSFODNN7EXAMPLE") == a {
		t.Fatal("another org's key must give another org_key")
	}
	stored := StoredOrgKey(3, a)
	cases := []struct {
		name   string
		stored string
		held   int64
		want   string
	}{
		{"held version", stored, 3, a},
		{"rotated since", stored, 4, ""},
		{"no key held", stored, 0, ""},
		{"untagged legacy value", a, 3, ""},
		{"malformed digest", "v3:" + strings.Repeat("Z", 64), 3, ""},
		{"empty", "", 3, ""},
	}
	for _, c := range cases {
		if got := WireOrgKey(c.stored, c.held); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if StoredOrgKey(0, a) != "" || StoredOrgKey(1, "nothex") != "" {
		t.Error("StoredOrgKey must refuse a bad version or digest")
	}
}
