package store

import "testing"

// TestShareOptions_ShipsRawContent pins the three-way disjunct (design
// docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §5.3
// item 4): raw content ships when FullContent (node opt-in) OR AdminManaged
// (native-console provisioning default-flip) OR EnterpriseGranted (the
// enterprise-managed-tenancy grant, govern.Effective.GrantsEnterpriseContent())
// is set — and ONLY then. EnterpriseGranted must behave exactly like its two
// siblings: additive, independent, and harmless when combined with either of
// the others.
func TestShareOptions_ShipsRawContent(t *testing.T) {
	cases := []struct {
		name string
		opts ShareOptions
		want bool
	}{
		{name: "zero value: no raw content", opts: ShareOptions{}, want: false},
		{name: "FullContent alone", opts: ShareOptions{FullContent: true}, want: true},
		{name: "AdminManaged alone", opts: ShareOptions{AdminManaged: true}, want: true},
		{name: "EnterpriseGranted alone", opts: ShareOptions{EnterpriseGranted: true}, want: true},
		{name: "EnterpriseGranted combined with FullContent", opts: ShareOptions{FullContent: true, EnterpriseGranted: true}, want: true},
		{name: "EnterpriseGranted combined with AdminManaged", opts: ShareOptions{AdminManaged: true, EnterpriseGranted: true}, want: true},
		{name: "an unrelated field set alone (e.g. RoutingSummary) does not ship raw content", opts: ShareOptions{RoutingSummary: true}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.opts.shipsRawContent(); got != tc.want {
				t.Errorf("shipsRawContent() = %v, want %v", got, tc.want)
			}
			// ShipsRawContent (exported) must delegate verbatim, never
			// re-derive — the two must never disagree.
			if got := tc.opts.ShipsRawContent(); got != tc.want {
				t.Errorf("ShipsRawContent() = %v, want %v (disagrees with shipsRawContent)", got, tc.want)
			}
		})
	}
}
