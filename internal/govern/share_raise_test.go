package govern

import (
	"reflect"
	"testing"
)

// TestRaiseList pins RaiseList's UNION semantics and its Managed gating,
// which must mirror RaiseBool's exactly: inert everywhere except the
// managed-tenancy plane, and a no-op for any directive shape other than a
// non-empty []string.
func TestRaiseList(t *testing.T) {
	const key = "target_action_allowlist"
	cases := []struct {
		name    string
		managed bool
		share   map[string]any
		current []string
		want    []string
	}{
		{
			name:    "unmanaged node: org's list is inert",
			managed: false,
			share:   map[string]any{key: []string{"exec", "write"}},
			current: []string{"read"},
			want:    []string{"read"},
		},
		{
			name:    "org published nothing",
			managed: true,
			current: []string{"read"},
			want:    []string{"read"},
		},
		{
			name:    "malformed directive (wrong type) leaves current unchanged",
			managed: true,
			share:   map[string]any{key: "exec"},
			current: []string{"read"},
			want:    []string{"read"},
		},
		{
			name:    "empty org list leaves current unchanged",
			managed: true,
			share:   map[string]any{key: []string{}},
			current: []string{"read"},
			want:    []string{"read"},
		},
		{
			name:    "managed node: union of disjoint entries, sorted",
			managed: true,
			share:   map[string]any{key: []string{"exec", "write"}},
			current: []string{"read"},
			want:    []string{"exec", "read", "write"},
		},
		{
			name:    "overlapping entries are deduplicated",
			managed: true,
			share:   map[string]any{key: []string{"read", "write"}},
			current: []string{"read", "exec"},
			want:    []string{"exec", "read", "write"},
		},
		{
			name:    "nil current: org's list becomes the whole result",
			managed: true,
			share:   map[string]any{key: []string{"write", "exec"}},
			current: nil,
			want:    []string{"exec", "write"},
		},
		{
			name:    "current already a superset: result unchanged in content",
			managed: true,
			share:   map[string]any{key: []string{"read"}},
			current: []string{"read", "exec"},
			want:    []string{"exec", "read"},
		},
		{
			name:    "a directive on a DIFFERENT key does not raise this one",
			managed: true,
			share:   map[string]any{"other_allowlist": []string{"exec"}},
			current: []string{"read"},
			want:    []string{"read"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Effective{Managed: tc.managed, Share: tc.share}
			got := e.RaiseList(key, tc.current)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("RaiseList(%q, %v) = %v, want %v", key, tc.current, got, tc.want)
			}
		})
	}
}

// TestRaiseScopeUnrestricted pins the sentinel-shaped scope-allowlist raise:
// only the literal bool `true` clears the node's allowlist to nil (the top
// of the scope lattice, "observe everything"). Any other directive shape —
// notably a []string, which is what a naive RaiseList-style union would
// expect — must NOT be treated as a partial widen; it is left inert, because
// unioning a restriction list is never a valid "raise" for an allowlist (see
// package doc above RaiseList).
func TestRaiseScopeUnrestricted(t *testing.T) {
	const key = "project_allowlist"
	cases := []struct {
		name    string
		managed bool
		share   map[string]any
		current []string
		want    []string
	}{
		{
			name:    "unmanaged node: sentinel is inert",
			managed: false,
			share:   map[string]any{key: true},
			current: []string{"proj-a"},
			want:    []string{"proj-a"},
		},
		{
			name:    "org published nothing",
			managed: true,
			current: []string{"proj-a"},
			want:    []string{"proj-a"},
		},
		{
			name:    "managed node: sentinel clears the allowlist to nil",
			managed: true,
			share:   map[string]any{key: true},
			current: []string{"proj-a", "proj-b"},
			want:    nil,
		},
		{
			name:    "sentinel false does not clear anything",
			managed: true,
			share:   map[string]any{key: false},
			current: []string{"proj-a"},
			want:    []string{"proj-a"},
		},
		{
			name:    "a []string directive is the WRONG shape for this op and is inert, not unioned",
			managed: true,
			share:   map[string]any{key: []string{"proj-c"}},
			current: []string{"proj-a"},
			want:    []string{"proj-a"},
		},
		{
			name:    "already-nil current stays nil under the sentinel",
			managed: true,
			share:   map[string]any{key: true},
			current: nil,
			want:    nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Effective{Managed: tc.managed, Share: tc.share}
			got := e.RaiseScopeUnrestricted(key, tc.current)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("RaiseScopeUnrestricted(%q, %v) = %v, want %v", key, tc.current, got, tc.want)
			}
		})
	}
}

// TestRaiseScopeDenylistRemoval pins the denylist-shaped scope raise:
// raising a denylist REMOVES org-named entries, the exact opposite of
// RaiseList's union. This is the case the design calls out explicitly as
// "union would be wrong" — unioning a denylist can only ever ADD
// restrictions, which is a lower, not a raise.
func TestRaiseScopeDenylistRemoval(t *testing.T) {
	const key = "path_denylist"
	cases := []struct {
		name    string
		managed bool
		share   map[string]any
		current []string
		want    []string
	}{
		{
			name:    "unmanaged node: removal directive is inert",
			managed: false,
			share:   map[string]any{key: []string{"secrets/"}},
			current: []string{"secrets/", "vendor/"},
			want:    []string{"secrets/", "vendor/"},
		},
		{
			name:    "org published nothing",
			managed: true,
			current: []string{"secrets/", "vendor/"},
			want:    []string{"secrets/", "vendor/"},
		},
		{
			name:    "malformed directive (wrong type) leaves current unchanged",
			managed: true,
			share:   map[string]any{key: true},
			current: []string{"secrets/"},
			want:    []string{"secrets/"},
		},
		{
			name:    "empty removal list leaves current unchanged",
			managed: true,
			share:   map[string]any{key: []string{}},
			current: []string{"secrets/"},
			want:    []string{"secrets/"},
		},
		{
			name:    "managed node: named entries are REMOVED, not added — union would grow this instead",
			managed: true,
			share:   map[string]any{key: []string{"vendor/"}},
			current: []string{"secrets/", "vendor/", "node_modules/"},
			want:    []string{"node_modules/", "secrets/"},
		},
		{
			name:    "removal entries absent from current are simply ignored",
			managed: true,
			share:   map[string]any{key: []string{"nonexistent/"}},
			current: []string{"secrets/", "vendor/"},
			want:    []string{"secrets/", "vendor/"},
		},
		{
			name:    "nil current stays nil (nothing to remove from)",
			managed: true,
			share:   map[string]any{key: []string{"vendor/"}},
			current: nil,
			want:    nil,
		},
		{
			name:    "removing every entry leaves an empty non-nil slice, distinct from starting nil",
			managed: true,
			share:   map[string]any{key: []string{"vendor/"}},
			current: []string{"vendor/"},
			want:    []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Effective{Managed: tc.managed, Share: tc.share}
			got := e.RaiseScopeDenylistRemoval(key, tc.current)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("RaiseScopeDenylistRemoval(%q, %v) = %#v, want %#v", key, tc.current, got, tc.want)
			}
			if tc.name == "removing every entry leaves an empty non-nil slice, distinct from starting nil" && got == nil {
				t.Error("expected a non-nil empty slice (current was non-nil), got nil — the nil-vs-empty distinction was lost")
			}
		})
	}
}
