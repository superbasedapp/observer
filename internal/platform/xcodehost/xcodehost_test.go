package xcodehost

import "testing"

func TestProjectRoot(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/Users/lume/Library/Autosave Information", ProjectUnknown},
		{"/Users/lume/Library/Autosave Information/", ProjectUnknown},
		{"/Users/u/library/autosave information", ProjectUnknown},
		{"/Users/lume/superbasedtest", "/Users/lume/superbasedtest"},
		{"/Users/lume/Library/Autosave Information/Sub", "/Users/lume/Library/Autosave Information/Sub"},
		{"/Library/Autosave Information", "/Library/Autosave Information"},
		{"Library/Autosave Information", "Library/Autosave Information"},
		{"", ""},
	} {
		if got := ProjectRoot(tc.in); got != tc.want {
			t.Errorf("ProjectRoot(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
