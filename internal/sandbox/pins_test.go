package sandbox

import "testing"

// TestPinWritable: a pin is writable only when its nearest enclosing mount
// is a read-write bind (lane SHR-FOLLOWUPS audit finding 1), one case per
// row.
func TestPinWritable(t *testing.T) {
	org := PinMount{Target: "/srv/org", Writable: true}
	roRepo := PinMount{Target: "/srv/org/vendor/lib"}
	rwInRO := PinMount{Target: "/srv/org/vendor/lib/work", Writable: true}
	hidden := PinMount{Target: "/srv/org/secret"}
	for _, tc := range []struct {
		name   string
		pin    string
		mounts []PinMount
		want   bool
	}{
		{"inside a write bind", "/srv/org/a/repo/.git", []PinMount{org}, true},
		{"outside every mount", "/srv/other/.git", []PinMount{org}, false},
		{"no mounts", "/srv/org/.git", nil, false},
		{"the bind itself", "/srv/org", []PinMount{org}, false},
		{"read-only bind nested in a write bind", "/srv/org/vendor/lib/.git", []PinMount{org, roRepo}, false},
		{"read-only bind nested in a write bind, any order", "/srv/org/vendor/lib/.git", []PinMount{roRepo, org}, false},
		{"write bind nested in that read-only bind", "/srv/org/vendor/lib/work/.git", []PinMount{org, roRepo, rwInRO}, true},
		{"beside the nested read-only bind", "/srv/org/vendor/other/.git", []PinMount{org, roRepo}, true},
		{"prefix is not a parent", "/srv/org/vendor/library/.git", []PinMount{org, roRepo}, true},
		{"under a hidden dir or tmpfs", "/srv/org/secret/repo/.git", []PinMount{org, hidden}, false},
		{"two mounts at the nearest target, one read-only", "/srv/org/x/.git", []PinMount{org, {Target: "/srv/org"}}, false},
		{"unclean spelling", "/srv/org/vendor/lib/../lib/.git", []PinMount{org, roRepo}, false},
	} {
		if got := PinWritable(tc.pin, tc.mounts); got != tc.want {
			t.Errorf("%s: PinWritable(%s) = %v, want %v", tc.name, tc.pin, got, tc.want)
		}
	}
}
