//go:build windows

package fsatomic

import (
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

// TestWindowsOwnerOnlyNeedsTheOwner (WINFIX4 audit finding 5): a file whose
// DACL grants only this user and SYSTEM but whose owner is another account
// (an administrator planted it) is refused; before, only the DACL was read,
// by path.
func TestWindowsOwnerOnlyNeedsTheOwner(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := u.User.Sid.String()
	cases := []struct {
		name, sddl string
		want       bool
	}{
		{"mine", fmt.Sprintf("O:%sD:P(A;;FA;;;%s)(A;;FA;;;SY)", me, me), true},
		{"Administrators own it", fmt.Sprintf("O:BAD:P(A;;FA;;;%s)(A;;FA;;;SY)", me), false},
		{"SYSTEM owns it", fmt.Sprintf("O:SYD:P(A;;FA;;;%s)(A;;FA;;;SY)", me), false},
		{"not protected", fmt.Sprintf("O:%sD:(A;;FA;;;%s)", me, me), false},
		{"Everyone allowed", fmt.Sprintf("O:%sD:P(A;;FA;;;%s)(A;;FR;;;WD)", me, me), false},
	}
	for _, c := range cases {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := sdOwnerOnly(sd, u.User.Sid); err != nil || got != c.want {
			t.Errorf("%s: %v %v, want %v", c.name, got, err, c.want)
		}
	}
}
