package sandbox

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

const testMountInfo = `21 1 252:0 / / ro,relatime shared:1 - ext4 /dev/mapper/vroot ro
22 21 0:5 / /dev rw,nosuid - devtmpfs devtmpfs rw
23 21 0:20 / /home rw,nosuid,nodev - tmpfs tmpfs rw
24 23 0:30 / /home/u/proj rw,nosuid,nodev - virtiofs ws rw
25 24 0:30 /.git /home/u/proj/.git rw,nosuid,nodev - virtiofs ws rw
`

// TestGuestCheckRows is one case per rule of the shared in-guest check.
func TestGuestCheckRows(t *testing.T) {
	erofs := func(string) error { return syscall.EROFS }
	cases := []struct {
		name   string
		info   string
		mounts []string
		ro     []string
		access func(string) error
		says   string
	}{
		{"passes", testMountInfo, []string{"/home/u/proj", "/home/u/proj/.git"}, nil, erofs, ""},
		{"missing mount", testMountInfo, []string{"/home/u/other"}, nil, erofs, "/home/u/other is not mounted"},
		{"covered", testMountInfo + "26 23 0:41 / /home/u rw - tmpfs t rw\n", []string{"/home/u/proj"}, nil, erofs, "covered by a later mount on /home/u"},
		{"writable ro mount", testMountInfo, nil, []string{"/home/u/proj"}, erofs, "writable in the box, the plan made it read-only"},
		{"witness", testMountInfo, nil, []string{"/"}, func(string) error { return nil }, "/ is writable in the box (access: <nil>)"},
		{"witness other error", testMountInfo, nil, []string{"/"}, func(string) error { return errors.New("eperm") }, "access: eperm"},
		{"unreadable", "garbage\n", nil, nil, erofs, "could not read its own mount table"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GuestCheck([]byte(tc.info), tc.mounts, tc.ro, tc.access)
			if tc.says == "" && got != "" || tc.says != "" && !strings.Contains(got, tc.says) {
				t.Fatalf("got %q, want %q", got, tc.says)
			}
		})
	}
}

func TestParseGuestMountInfoEscapes(t *testing.T) {
	tab, err := ParseGuestMountInfo([]byte("36 35 98:0 / /a\\040b ro,relatime shared:1 - ext4 /dev/x rw\n"))
	if err != nil || len(tab) != 1 || tab[0].Point != "/a b" || !tab[0].ReadOnly {
		t.Fatalf("%+v %v", tab, err)
	}
	for _, bad := range []string{"36 35 98:0 / x ro - e d rw", "36 35 98:0 / /a\\04 ro - e d rw"} {
		if _, err := ParseGuestMountInfo([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
