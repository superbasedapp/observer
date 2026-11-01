//go:build linux

package host

import "testing"

func TestParseCgroup2Mount(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"pure v2", "30 24 0:26 / /sys/fs/cgroup rw,nosuid shared:4 - cgroup2 cgroup2 rw,nsdelegate\n", "/sys/fs/cgroup"},
		{
			"hybrid: the unified mount, after v1 controllers",
			"33 25 0:28 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n34 25 0:29 / /sys/fs/cgroup/unified rw shared:9 - cgroup2 cgroup2 rw\n",
			"/sys/fs/cgroup/unified",
		},
		{"an escaped space", `40 1 0:30 / /mnt/c\040g rw - cgroup2 none rw` + "\n", "/mnt/c g"},
		{"none", "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n", ""},
		{"a malformed line", "garbage\n", ""},
	}
	for _, tc := range cases {
		if got := parseCgroup2Mount([]byte(tc.in)); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestParseOwnCgroup(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-u7.scope\n": "/user.slice/user-1000.slice/user@1000.service/app.slice/run-u7.scope",
		"4:memory:/x\n1:name=systemd:/\n0::/\n":                                     "/",
		"4:memory:/x\n":                                                             "",
		"":                                                                          "",
	}
	for in, want := range cases {
		if got := parseOwnCgroup([]byte(in)); got != want {
			t.Errorf("parseOwnCgroup(%q) = %q, want %q", in, got, want)
		}
	}
}
