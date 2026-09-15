package govern

import "testing"

// TestGrantsEnterpriseContent pins the truth table for the enterpriseGranted
// disjunct (design §5.3 item 4): GrantsEnterpriseContent composes FOUR
// strict per-tier predicates (Managed, Codeintel, Process, Terminal — each
// gated via the STRICT grantsExtraction, no umbrella clause) plus e.Managed
// itself. It is deliberately a HIGH bar, narrower than any single
// extraction tier alone, before store.ShareOptions.shipsRawContent() honors
// it as the enterprise-managed-tenancy equivalent of a node operator's own
// full_content/admin_managed opt-in. Every one of the four tokens must be
// present; dropping any single one — or being unmanaged — must flip the
// result to false, and no OTHER extraction token (e.g. cache, routing) can
// substitute for a missing one.
func TestGrantsEnterpriseContent(t *testing.T) {
	all4 := []string{
		AuthorityExtractManaged,
		AuthorityExtractCodeintel,
		AuthorityExtractProcess,
		AuthorityExtractTerminal,
	}

	cases := []struct {
		name    string
		managed bool
		auth    []string
		want    bool
	}{
		{name: "all four tokens + managed: granted", managed: true, auth: all4, want: true},
		{name: "all four tokens but unmanaged: refused", managed: false, auth: all4, want: false},
		{name: "zero value: refused", managed: false, auth: nil, want: false},
		{name: "managed but no tokens at all: refused", managed: true, auth: nil, want: false},
		{
			name:    "missing 'managed' token alone: refused",
			managed: true,
			auth:    []string{AuthorityExtractCodeintel, AuthorityExtractProcess, AuthorityExtractTerminal},
			want:    false,
		},
		{
			name:    "missing 'codeintel' token alone: refused",
			managed: true,
			auth:    []string{AuthorityExtractManaged, AuthorityExtractProcess, AuthorityExtractTerminal},
			want:    false,
		},
		{
			name:    "missing 'process' token alone: refused",
			managed: true,
			auth:    []string{AuthorityExtractManaged, AuthorityExtractCodeintel, AuthorityExtractTerminal},
			want:    false,
		},
		{
			name:    "missing 'terminal' token alone: refused",
			managed: true,
			auth:    []string{AuthorityExtractManaged, AuthorityExtractCodeintel, AuthorityExtractProcess},
			want:    false,
		},
		{
			name:    "three of four plus an unrelated token: the unrelated token does not substitute for the missing one",
			managed: true,
			auth:    []string{AuthorityExtractManaged, AuthorityExtractCodeintel, AuthorityExtractProcess, AuthorityExtractCache},
			want:    false,
		},
		{
			name:    "all four plus extra unrelated tokens: still granted (extras are harmless)",
			managed: true,
			auth:    append(append([]string{}, all4...), AuthorityExtractCache, AuthorityExtractRouting),
			want:    true,
		},
		{
			name:    "all four tokens present but managed=false overrides everything",
			managed: false,
			auth:    []string{AuthorityExtractManaged, AuthorityExtractCodeintel, AuthorityExtractProcess, AuthorityExtractTerminal, AuthorityExtractObsEgress},
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Effective{Managed: tc.managed, Authority: tc.auth}
			if got := e.GrantsEnterpriseContent(); got != tc.want {
				t.Errorf("GrantsEnterpriseContent() = %v, want %v (managed=%v auth=%v)", got, tc.want, tc.managed, tc.auth)
			}
		})
	}
}
