package orgpricing

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

func TestModeTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name              string
		fromOrg           bool
		grant             bool
		wantFromOrg       bool
		wantAuthoritative bool
		why               string
	}{
		{
			name: "an individual node that never opted in applies nothing",
			why:  "ruling R2: pricing rides the budget opt-in, and there is no second switch",
		},
		{
			name: "a grant with no opt-in still applies nothing", grant: true,
			why: "a node that has not opted into the org's prices cannot be applying them authoritatively",
		},
		{
			name:    "an individual node that opted in applies them UNDER its own overrides",
			fromOrg: true, wantFromOrg: true,
			why: "ruling R3: a developer who typed a rate on an unmanaged machine meant it",
		},
		{
			name:    "a managed node holding enforce.budget applies them OVER its own overrides",
			fromOrg: true, grant: true, wantFromOrg: true, wantAuthoritative: true,
			why: "otherwise one TOML key would be enough to re-price out from under an org cap",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotFrom, gotAuth := Mode(config.GuardBudgetConfig{FromOrg: tc.fromOrg}, tc.grant)
			if gotFrom != tc.wantFromOrg || gotAuth != tc.wantAuthoritative {
				t.Errorf("Mode = (%v, %v), want (%v, %v) — %s",
					gotFrom, gotAuth, tc.wantFromOrg, tc.wantAuthoritative, tc.why)
			}
		})
	}
}
