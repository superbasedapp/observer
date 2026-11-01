package crossmount

import "testing"

func TestWindowsPathFromMount(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"/mnt/c/Users/op/.codex/hooks.json", `C:\Users\op\.codex\hooks.json`, true},
		{"/mnt/D/x", `D:\x`, true},
		{"/mnt/c", `C:\`, true},
		{"/mnt/cfoo/x", "", false},
		{"/home/u/.codex/hooks.json", "", false},
		{"/mnt/", "", false},
		{"/mnt/1/x", "", false},
	}
	for _, c := range cases {
		got, ok := WindowsPathFromMount(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("WindowsPathFromMount(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
