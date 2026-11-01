package catalog

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

var extraForbiddenImports = []string{"github.com/marmutapp/superbased-observer/internal/integration"}

func mustLoad(t *testing.T) *Catalog {
	t.Helper()
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

// TestCatalogLoadsAndValidates is the F2 gate: every committed row decodes
// strictly and passes vendorsurface.ValidateCatalog.
func TestCatalogLoadsAndValidates(t *testing.T) {
	c := mustLoad(t)
	rows := c.Surfaces()
	// 1478 research rows (v5, 30 vendor groups) plus the section 4.3.3 review
	// additions; three research rows were renamed, none dropped.
	if len(rows) < 1478+20 {
		t.Fatalf("catalog has %d rows, want at least %d", len(rows), 1478+20)
	}
	// 30 research/v5 groups plus the three AP-135 groups (snowflake, ibm,
	// castai; docs/plans/native-console-wave-2026-10-21-phase0.md).
	if n := len(c.Groups()); n != 33 {
		t.Fatalf("catalog has %d vendor groups, want 33 (research/v5 + AP-135)", n)
	}
	for _, g := range c.Groups() {
		if len(c.GroupSurfaces(g)) == 0 {
			t.Errorf("vendor group %s has no rows", g)
		}
	}
}

// TestEveryRowIsSyntheticAwaitingLiveValidation: every vendor surface is
// labelled "synthetic, awaiting live validation" and no supply or control
// claims a live rung. Only a Built row (its driver passed the synthetic gate,
// lane F8 onward) may raise a supply above doc_only, and then only to
// assumption_tested or mock_verified; the driver table test checks the
// evidence ceiling against the fixture ledgers.
func TestEveryRowIsSyntheticAwaitingLiveValidation(t *testing.T) {
	for _, s := range mustLoad(t).Surfaces() {
		if s.Status != vendorsurface.StatusLabel {
			t.Errorf("%s: status %q", s.ID, s.Status)
		}
		for _, sp := range s.Supplies {
			if s.Build == vendorsurface.BuildBuilt && sp.Verification.Live == vendorsurface.LivePending &&
				(sp.Verification.Synthetic == vendorsurface.SynthMockVerified || sp.Verification.Synthetic == vendorsurface.SynthAssumptionTested) {
				continue
			}
			if sp.Verification != (vendorsurface.Verification{Synthetic: vendorsurface.SynthDocOnly, Live: vendorsurface.LivePending}) {
				t.Errorf("%s/%s: verification %+v", s.ID, sp.Class, sp.Verification)
			}
		}
		for _, ct := range s.Controls {
			if ct.Verification != (vendorsurface.Verification{Synthetic: vendorsurface.SynthDocOnly, Live: vendorsurface.LivePending}) {
				t.Errorf("%s/%s: verification %+v", s.ID, ct.Class, ct.Verification)
			}
		}
	}
}

// TestAwaitingReferenceSurfacesHaveNoDriver pins plan 4.5 Evidence honesty:
// AwaitingReference never counts as driverable. The rulings named in the plan
// are pinned by id.
func TestAwaitingReferenceSurfacesHaveNoDriver(t *testing.T) {
	c := mustLoad(t)
	for _, s := range c.Surfaces() {
		if s.Build != vendorsurface.BuildAwaitingReference {
			continue
		}
		for _, sp := range s.Supplies {
			if vendorsurface.Driverable(sp.Build) {
				t.Errorf("%s: AwaitingReference surface has a driverable supply %s", s.ID, sp.Class)
			}
		}
	}
	for _, id := range []vendorsurface.SurfaceID{
		"openai.chatgpt.codex_analytics_usage",        // R-D-06
		"mistral.admin.usage",                         // R-D-17
		"mistral.service_accounts",                    // R-D-17
		"aws.cloudtrail.kiro_event_mapping",           // R-D-11
		"openai.chatgpt.codex_analytics_code_reviews", // R-D-06
	} {
		s, ok := c.Surface(id)
		if !ok {
			t.Errorf("%s: missing", id)
			continue
		}
		if s.Build != vendorsurface.BuildAwaitingReference {
			t.Errorf("%s: build %s, want awaiting_reference", id, s.Build)
		}
	}
}

// TestReviewFoldRowsPresent pins the section 4.3.3 additions and splits.
func TestReviewFoldRowsPresent(t *testing.T) {
	c := mustLoad(t)
	for _, id := range []vendorsurface.SurfaceID{
		"anthropic.managed_agents.sessions", "anthropic.console.mcp_tunnels_legacy", "anthropic.workspace.mcp_tunnels",
		"anthropic.console.api_key_max_expiration", "openai.platform.tunnel_admin", "openai.tunnel_client.runtime",
		"microsoft.m365.copilot_policy_settings", "microsoft.m365.workiq_mcp_policy", "aws.cloudtrail.generic",
		"aws.cloudtrail.kiro_event_mapping", "factory.automations.webhook_trigger", "factory.automations.delivery_feed",
		"alibaba.modelstudio.budget_management", "alibaba.modelstudio.throughput_reservations",
		"pi.node.permission_system_extension",
	} {
		if !c.Has(id) {
			t.Errorf("review row %s missing", id)
		}
	}
	for _, old := range []vendorsurface.SurfaceID{"anthropic.console.mcp_tunnels", "openai.platform.tunnels", "aws.cloudtrail.kiro"} {
		if c.Has(old) {
			t.Errorf("split row %s still present under its old id", old)
		}
	}
	if s, _ := c.Surface("factory.automations.webhook_trigger"); s.Reach != vendorsurface.ReachInvokeAPI {
		t.Errorf("factory webhook trigger reach %s, want invoke_api (R-D-14)", s.Reach)
	}
	if s, _ := c.Surface("openai.tunnel_client.runtime"); s.Reach != vendorsurface.ReachRelay {
		t.Errorf("openai tunnel runtime reach %s, want relay (R-D-05)", s.Reach)
	}
	if s, _ := c.Surface("microsoft.m365.copilot_policy_settings"); s.Auth.Kind != vendorsurface.AuthOAuthUserToken {
		t.Errorf("m365 policy settings auth %s, want oauth_user_token (delegated only, R-D-08)", s.Auth.Kind)
	}
	if s, _ := c.Surface("anthropic.enterprise.inference_hooks"); s.Reach != vendorsurface.ReachSyncDecisionHook {
		t.Errorf("inference hooks reach %s, want sync_decision_hook (documented, not built, D-369)", s.Reach)
	}
}

// TestCredentialSurfacesAreSecretAware pins plan 4.5 R-E-06 at the catalog
// level: no row that supplies Credentials is classified never_returns_secret,
// so the runner (F7) cannot call it as an inventory read without review.
func TestCredentialSurfacesAreSecretAware(t *testing.T) {
	n := 0
	for _, s := range mustLoad(t).Surfaces() {
		for _, sp := range s.Supplies {
			if sp.Class == vendorsurface.ClassCredentials {
				n++
				if s.SecretClass == vendorsurface.SecretNever {
					t.Errorf("%s: credentials surface classified never_returns_secret", s.ID)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no Credentials supply in the catalog: the pin would be vacuous")
	}
}

// TestCompletenessDefaultsToSegment: no catalog row claims CompleteForTool
// before the arbitration lane (F11) proves it per supply.
func TestCompletenessDefaultsToSegment(t *testing.T) {
	for _, s := range mustLoad(t).Surfaces() {
		for _, sp := range s.Supplies {
			if sp.Coverage.Completeness == vendorsurface.CompleteForTool {
				t.Errorf("%s/%s claims complete_for_tool in the catalog", s.ID, sp.Class)
			}
		}
	}
}

func TestDecodeRejectsUnknownFieldsAndWrongGroup(t *testing.T) {
	cases := []struct {
		name, file, body, want string
	}{
		{"unknown field", "data/acme.json", `{"group":"acme","surfaces":[],"tools":["x"]}`, "unknown field"},
		{"group mismatch", "data/acme.json", `{"group":"other","surfaces":[]}`, "declares group"},
		{"row group mismatch", "data/acme.json", `{"group":"acme","surfaces":[{"id":"acme.x.y","vendor_group":"b"}]}`, "vendor_group"},
		{"invalid row", "data/acme.json", `{"group":"acme","surfaces":[{"id":"acme.x.y","vendor_group":"acme"}]}`, "invalid rows"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decode(fstest.MapFS{tc.file: {Data: []byte(tc.body)}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestDerivationRecordedForEveryRow(t *testing.T) {
	for _, s := range mustLoad(t).Surfaces() {
		if s.Derivation.BuildRule == "" {
			t.Errorf("%s: no build derivation", s.ID)
		}
		if s.Reach != vendorsurface.ReachUnclassified && s.Derivation.ReachRule == "" {
			t.Errorf("%s: reach %s without a recorded rule", s.ID, s.Reach)
		}
	}
}
