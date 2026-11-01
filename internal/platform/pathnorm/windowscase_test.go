package pathnorm

import "testing"

// TestWindowsPathCase pins the WINNODE2 item 11 helpers: the drive letter is
// upper-cased, a UNC or POSIX path is unchanged, and only Windows-shaped
// paths are case-insensitive.
func TestWindowsPathCase(t *testing.T) {
	cases := []struct {
		in, canon string
		windows   bool
	}{
		{`c:\Users\developer\projects\payments-api`, `C:\Users\developer\projects\payments-api`, true},
		{`C:\Users\developer\projects\payments-api`, `C:\Users\developer\projects\payments-api`, true},
		{`d:/work/x`, `D:/work/x`, true},
		{`\\fs\share\x`, `\\fs\share\x`, true},
		{`/home/dev/Project`, `/home/dev/Project`, false},
		{`/mnt/c/Users/dev`, `/mnt/c/Users/dev`, false},
		{`c:`, `c:`, false},
		{``, ``, false},
	}
	for _, tc := range cases {
		if got := CanonicalDriveLetter(tc.in); got != tc.canon {
			t.Errorf("CanonicalDriveLetter(%q) = %q, want %q", tc.in, got, tc.canon)
		}
		if got := IsWindowsShaped(tc.in); got != tc.windows {
			t.Errorf("IsWindowsShaped(%q) = %v, want %v", tc.in, got, tc.windows)
		}
	}
}
