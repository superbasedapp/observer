package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/attest"
)

func TestAttestTokenSourceFromEnv(t *testing.T) {
	cases := []struct {
		name        string
		armToken    string
		identityCID string
		wantStatic  bool
		wantValue   string
		wantCID     string
	}{
		{
			name:       "static_token_wins_when_set",
			armToken:   "fixed-dev-token",
			wantStatic: true,
			wantValue:  "fixed-dev-token",
		},
		{
			name:       "static_token_trims_whitespace",
			armToken:   "  fixed-dev-token  ",
			wantStatic: true,
			wantValue:  "fixed-dev-token",
		},
		{
			name:       "imds_when_arm_token_unset",
			armToken:   "",
			wantStatic: false,
		},
		{
			name:        "imds_carries_configured_client_id",
			armToken:    "",
			identityCID: "user-assigned-client-id",
			wantStatic:  false,
			wantCID:     "user-assigned-client-id",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("SBCI_ARM_TOKEN", c.armToken)
			t.Setenv("SBCI_ARM_IDENTITY_CLIENT_ID", c.identityCID)

			got := attestTokenSourceFromEnv()
			if c.wantStatic {
				static, ok := got.(attest.StaticTokenSource)
				if !ok {
					t.Fatalf("got %T, want attest.StaticTokenSource", got)
				}
				if static.Value != c.wantValue {
					t.Fatalf("static.Value = %q, want %q", static.Value, c.wantValue)
				}
				return
			}
			imds, ok := got.(*attest.ManagedIdentityTokenSource)
			if !ok {
				t.Fatalf("got %T, want *attest.ManagedIdentityTokenSource", got)
			}
			if imds.ClientID != c.wantCID {
				t.Fatalf("imds.ClientID = %q, want %q", imds.ClientID, c.wantCID)
			}
		})
	}
}
