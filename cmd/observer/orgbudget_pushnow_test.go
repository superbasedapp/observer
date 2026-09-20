package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestGuardlessBudgetHandlePostureFollowsTheFetch is the cmd/observer half of
// the demo-estate posture finding (2026-09-20). A CLI one-shot (`observer org
// push-now`) composes through the SAME orgBudgetHandle the daemon runs, with
// no guard in-process: the posture it publishes must (a) follow the fetch
// outcome it was just handed - primed `unreachable` becomes `ok` the moment
// the fetch succeeds, never a cycle later - and (b) report the node's
// CONFIGURED guard mode rather than "off", because the node's guard is
// running in the daemon even though this process holds none.
//
// One row per (prime, fetch) transition the CLI can observe.
func TestGuardlessBudgetHandlePostureFollowsTheFetch(t *testing.T) {
	local := config.GuardBudgetConfig{FromOrg: true}
	body := orgcontract.BudgetPolicyBody{
		Version: 4, ResolvedScope: "team:eng", CapTokens: 1_000_000,
		Period: orgcontract.BudgetPolicyPeriodCalendarMonth, Timezone: "UTC",
		Enforcement: orgcontract.BudgetPolicyEnforcementHard,
		Caps: []orgcontract.BudgetPolicyCap{{
			Period: orgcontract.BudgetPolicyPeriodCalendarMonth, CapTokens: 1_000_000,
			Enforcement: orgcontract.BudgetPolicyEnforcementHard, ResolvedScope: "team:eng",
		}},
	}

	cases := []struct {
		name          string
		mode          string
		granted       bool
		fetch         *orgclient.BudgetFetchOutcome // nil = no fetch after Prime
		wantState     string
		wantMode      string
		wantCoverage  string
		wantLastFetch bool
		why           string
	}{
		{
			name: "primed only, managed + enforce.budget", mode: "enforce", granted: true,
			wantState: orgcontract.BudgetFetchUnreachable, wantMode: "enforce",
			wantCoverage: orgcontract.BudgetCoverageBudgetRequired,
			why:          "before any fetch the honest posture IS budget_required - this is the row the org saw",
		},
		{
			name: "successful fetch after prime, managed + enforce.budget", mode: "enforce", granted: true,
			fetch:     &orgclient.BudgetFetchOutcome{State: orgcontract.BudgetFetchOK, HaveBody: true, Body: body},
			wantState: orgcontract.BudgetFetchOK, wantMode: "enforce",
			wantCoverage: orgcontract.BudgetCoverageProxyOnly, wantLastFetch: true,
			why: "the posture must flip to ok / proxy_only on the SAME outcome, so push-now ships it at once",
		},
		{
			name: "successful fetch, individual node in observe mode", mode: "observe", granted: false,
			fetch:     &orgclient.BudgetFetchOutcome{State: orgcontract.BudgetFetchOK, HaveBody: true, Body: body},
			wantState: orgcontract.BudgetFetchOK, wantMode: "observe",
			wantCoverage: orgcontract.BudgetCoverageProxyOnly, wantLastFetch: true,
			why: "a guard-less process reports the CONFIGURED mode, not \"off\"",
		},
		{
			name: "failed fetch after prime, managed", mode: "enforce", granted: true,
			fetch:     &orgclient.BudgetFetchOutcome{State: orgcontract.BudgetFetchChannelOff},
			wantState: orgcontract.BudgetFetchChannelOff, wantMode: "enforce",
			wantCoverage: orgcontract.BudgetCoverageBudgetRequired,
			why:          "a 409 policy_channel_off is this fetch's truth and must ship as such",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			granted := tc.granted
			h := newOrgBudgetHandle(nil, local, func() bool { return granted }, nil,
				slog.New(slog.NewTextHandler(io.Discard, nil)))
			h.modeOverride = tc.mode
			h.Prime(orgclient.BudgetFetchOutcome{})
			if tc.fetch != nil {
				h.onBudgetFetch(*tc.fetch)
			}
			row, ok := h.postureProvider()()
			if !ok {
				t.Fatalf("no posture published after Prime")
			}
			if row.FetchState != tc.wantState {
				t.Errorf("fetch_state = %q, want %q - %s", row.FetchState, tc.wantState, tc.why)
			}
			if row.Mode != tc.wantMode {
				t.Errorf("mode = %q, want %q - %s", row.Mode, tc.wantMode, tc.why)
			}
			if row.Coverage != tc.wantCoverage {
				t.Errorf("coverage = %q, want %q - %s", row.Coverage, tc.wantCoverage, tc.why)
			}
			if row.LastFetchOK != tc.wantLastFetch {
				t.Errorf("last_fetch_ok = %v, want %v", row.LastFetchOK, tc.wantLastFetch)
			}
		})
	}
}

// TestGuardlessBudgetHandleModeDefaultsToOff keeps the pre-existing contract
// for every OTHER guard-less construction (a guard that failed to build in the
// daemon): with no override the honest answer is still "off".
func TestGuardlessBudgetHandleModeDefaultsToOff(t *testing.T) {
	h := newOrgBudgetHandle(nil, config.GuardBudgetConfig{}, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := h.guardMode(); got != "off" {
		t.Fatalf("guardMode() = %q, want off", got)
	}
}
