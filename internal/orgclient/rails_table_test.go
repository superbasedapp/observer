package orgclient

import (
	"sort"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestRailTablesKeepEveryMergedRail pins the shared rail tables that several
// branches edit (Integration 6, area-5 review): a conflict resolution that
// kept only one side would silently stop a rail from being fetched, probed or
// pinned. Each table is compared with its exact expected set, so a dropped
// row fails here by name.
//
//   - pushCycleRails: the version-vector rails the push cycle itself
//     refreshes (grants from request-grants, agent_config from adapter
//     config P6).
//   - railFetchers: one fetch row per version-vector rail key.
//   - railPinSources: every cached rail document whose org signing key takes
//     part in the cross-rail pin check (access grants, the AI tool policy and
//     the intel consent requirement included).
//
// The intel consent requirement and the intel result / tombstone rails are
// NOT version-vector rails: they ride the push cycle directly
// (runIntelConsentCycle, FetchIntelResults -> applyIntelTombstones), so they
// appear only in the pin table.
func TestRailTablesKeepEveryMergedRail(t *testing.T) {
	wantPushCycle := []string{
		orgcontract.RailAgentConfig, orgcontract.RailAnnouncement, orgcontract.RailBudget,
		orgcontract.RailDisplay, orgcontract.RailGrants, orgcontract.RailMessages, orgcontract.RailPricing, orgcontract.RailRouting,
	}
	var gotPushCycle []string
	for k := range pushCycleRails {
		gotPushCycle = append(gotPushCycle, k)
	}
	assertSameSet(t, "pushCycleRails", gotPushCycle, wantPushCycle)

	wantFetch := []string{
		orgcontract.RailAgentConfig, orgcontract.RailAnnouncement, orgcontract.RailBudget, orgcontract.RailBundle,
		orgcontract.RailDisplay, orgcontract.RailGrants, orgcontract.RailMessages, orgcontract.RailPricing, orgcontract.RailRouting,
	}
	var gotFetch []string
	for _, row := range railFetchers {
		gotFetch = append(gotFetch, row.keys...)
	}
	assertSameSet(t, "railFetchers", gotFetch, wantFetch)

	wantPins := []string{
		accessGrantRail, agentConfigPolicyRail, announcementRail, displayPolicyRail,
		intelRequirementRail, routingPolicyRail,
	}
	var gotPins []string
	for _, src := range railPinSources {
		gotPins = append(gotPins, src.rail)
	}
	assertSameSet(t, "railPinSources", gotPins, wantPins)
}

func assertSameSet(t *testing.T, name string, got, want []string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v", name, got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s = %v, want %v", name, got, want)
			return
		}
	}
}
