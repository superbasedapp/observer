package govern

import "testing"

// TestShellWrapPosture: one case per row of shellWrapPostureRules (CLI-1b,
// D6), plus the refused grant and the non-bool pin.
func TestShellWrapPosture(t *testing.T) {
	pin := func(v any) map[string]any { return map[string]any{ShellWrapMaintainKey: v} }
	for _, tc := range []struct {
		name string
		e    Effective
		want ShellWrapPostureVerdict
	}{
		{"individual node, even with a pin", Effective{Pinned: pin(true)}, ShellWrapPostureVerdict{ShellWrapPostureNone, ShellWrapPostureSourceNotManaged}},
		{"managed, refused grant", Effective{Managed: true, State: StateGrantSignatureInvalid, Pinned: pin(true)}, ShellWrapPostureVerdict{ShellWrapPostureNone, ShellWrapPostureSourceNotManaged}},
		{"managed, admin on", Effective{Managed: true, Pinned: pin(true)}, ShellWrapPostureVerdict{ShellWrapPostureMaintain, ShellWrapPostureSourceAdminOn}},
		{"managed, admin off", Effective{Managed: true, Pinned: pin(false)}, ShellWrapPostureVerdict{ShellWrapPostureRelease, ShellWrapPostureSourceAdminOff}},
		{"managed, unset is never forced", Effective{Managed: true, Authority: []string{AuthorityEnforceBudget}}, ShellWrapPostureVerdict{ShellWrapPostureNone, ShellWrapPostureSourceUnset}},
		{"managed, a non-bool pin reads unset", Effective{Managed: true, Pinned: pin("on")}, ShellWrapPostureVerdict{ShellWrapPostureNone, ShellWrapPostureSourceUnset}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.e.ShellWrapPosture(); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
