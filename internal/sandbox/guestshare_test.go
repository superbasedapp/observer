package sandbox

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

// TestGuestCheckSharedRows (the microVM row's first live run, D4): a
// host-pinned read-only path inside a share is judged by the write witness,
// not the mount table: EROFS passes with no guest mount point there, an
// accepted write or any other answer refuses naming the path, and the
// mount-table rows still run first.
func TestGuestCheckSharedRows(t *testing.T) {
	erofs := func(string) error { return syscall.EROFS }
	mounts := []string{"/home/u/proj"}
	shared := []string{"/home/u/proj/.git/config", "/home/u/proj/.git/hooks"}
	cases := []struct {
		name   string
		mounts []string
		probe  func(string) error
		says   string
	}{
		{"read-only through the share", mounts, erofs, ""},
		{"a write was accepted", mounts, func(p string) error {
			if strings.HasSuffix(p, "hooks") {
				return nil
			}
			return syscall.EROFS
		}, "/home/u/proj/.git/hooks is writable in the box through its share (a write was accepted)"},
		{"another answer", mounts, func(string) error { return syscall.EACCES }, "did not prove read-only through its share (write witness: permission denied)"},
		{"missing", mounts, func(string) error { return errors.New("no such file") }, "/home/u/proj/.git/config did not prove read-only"},
		{"the mount table first", []string{"/home/u/other"}, erofs, "/home/u/other is not mounted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GuestCheckShared([]byte(testMountInfo), tc.mounts, nil, shared, erofs, tc.probe)
			if tc.says == "" && got != "" || tc.says != "" && !strings.Contains(got, tc.says) {
				t.Fatalf("got %q, want %q", got, tc.says)
			}
		})
	}
	if bad := ShareReadOnlyWitness(shared, func(string) error { return nil }); len(bad) != 2 || !strings.HasPrefix(bad[0], "/home/u/proj/.git/config ") {
		t.Fatalf("sorted, every path: %v", bad)
	}
}
