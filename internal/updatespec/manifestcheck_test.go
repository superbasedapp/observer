package updatespec

import "testing"

// TestValidBaseName pins the plain-file-name check, one case per rule.
func TestValidBaseName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"observer_1.42.0_linux_amd64.tar.gz", true},
		{"a", true},
		{"", false},
		{"bin/observer", false},
		{`bin\observer.exe`, false},
		{".", false},
		{"..", false},
		{"-rf", false},
	}
	for _, tc := range cases {
		if err := ValidBaseName(tc.name); (err == nil) != tc.ok {
			t.Errorf("ValidBaseName(%q) = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// TestIsHexSHA256 pins the 64-hex-character check, either case.
func TestIsHexSHA256(t *testing.T) {
	sum := HashBytes([]byte("superbased"))
	cases := []struct {
		in string
		ok bool
	}{
		{sum, true},
		{"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", true},
		{sum[:63], false},
		{sum + "0", false},
		{"zz" + sum[2:], false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsHexSHA256(tc.in); got != tc.ok {
			t.Errorf("IsHexSHA256(%q) = %v, want %v", tc.in, got, tc.ok)
		}
	}
	if HashBytes(nil) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("HashBytes(nil) = %s, want the empty-input sha256", HashBytes(nil))
	}
}
