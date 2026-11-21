//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// fu8Timing is a fast watch timing for the tests.
var fu8Timing = openShellEffectiveTiming{firstPoll: time.Millisecond, wait: 200 * time.Millisecond, tick: time.Millisecond, missLimit: 3}

// fu8Compiled is one compiled internet-tier rule.
func fu8Compiled() []sandboxopenshell.NetRule {
	return []sandboxopenshell.NetRule{{
		Key: sandboxopenshell.NetRuleKey, Name: sandboxopenshell.NetRuleKey,
		Endpoints: []sandboxopenshell.NetEndpoint{{Host: "github.com", Ports: []int{80, 443}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1")}}},
		Binaries:  []string{"/usr/local/bin/observer"},
	}}
}

const (
	fu8Same  = `{"policy":{"version":1,"network_policies":{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","ports":[443],"enforcement":"enforce","allowed_ips":["0.0.0.0/1"]}],"binaries":[{"path":"/usr/local/bin/observer"}]}}}}`
	fu8Wider = `{"policy":{"version":1,"network_policies":{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","ports":[443],"enforcement":"enforce","allowed_ips":["0.0.0.0/1"]}],"binaries":[]},"approved":{"endpoints":[{"host":"pastebin.com","port":443}]}}}}`
)

// TestOpenShellEffectiveLoop pins the box watch (lane FU8, OSH-40), one
// case per way it ends.
func TestOpenShellEffectiveLoop(t *testing.T) {
	cases := []struct {
		name    string
		answers []string // "" is a failed read; the last answer repeats
		cancel  int      // cancel the context after this many reads (0: never)
		verdict sandboxopenshell.EffectiveVerdict
	}{
		{"matches until the run ends", []string{"", fu8Same}, 5, sandboxopenshell.EffectiveMatch},
		{"widened at first read", []string{"", "", fu8Wider}, 0, sandboxopenshell.EffectiveExtraRule},
		{"widened later (an approved proposal)", []string{fu8Same, fu8Same, fu8Wider}, 0, sandboxopenshell.EffectiveExtraRule},
		{"never readable", []string{""}, 0, sandboxopenshell.EffectiveUnreadable},
		{"not a policy document", []string{`{"error":"x"}`}, 0, sandboxopenshell.EffectiveUnreadable},
		{"stops answering after a read", []string{fu8Same, ""}, 0, sandboxopenshell.EffectiveUnreadable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var n atomic.Int32
			read := func(context.Context) ([]byte, bool) {
				i := int(n.Add(1)) - 1
				if c.cancel > 0 && i >= c.cancel {
					cancel()
				}
				a := c.answers[min(i, len(c.answers)-1)]
				return []byte(a), a != ""
			}
			v, d := openShellEffectiveLoop(ctx, fu8Compiled(), read, fu8Timing)
			if v != c.verdict {
				t.Fatalf("verdict %s (%s), want %s", v, d, c.verdict)
			}
		})
	}
}

// TestOpenShellPlanCarriesCompiledRules: the plan file round-trips the
// compiled rules and the check flag the host helper reads.
func TestOpenShellPlanCarriesCompiledRules(t *testing.T) {
	pf := openShellPlanFile{Version: openShellPlanVersion, RunID: "r", Network: fu8Compiled(), EffectiveCheck: true}
	b, err := json.Marshal(pf)
	if err != nil {
		t.Fatal(err)
	}
	var got openShellPlanFile
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !got.EffectiveCheck || len(got.Network) != 1 || got.Network[0].Endpoints[0].AllowedIPs[0] != netip.MustParsePrefix("0.0.0.0/1") {
		t.Fatalf("round trip: %+v", got)
	}
	if v, _ := sandboxopenshell.EffectiveVerdictOf(got.Network, []byte(fu8Same)); v != sandboxopenshell.EffectiveMatch {
		t.Fatalf("the round-tripped rules do not match their own read-back: %s", v)
	}
	// A plan without the flag (managed mode, or an older plan) starts no
	// watch.
	openShellWatchEffectivePolicy(openShellPlanFile{}, nil)()
}

// TestOpenShellManagedDBFoldsIntoDrift: a managed probe that read a
// changed database setting turns the posture to changed (OSH-40, managed
// half).
func TestOpenShellManagedDBFoldsIntoDrift(t *testing.T) {
	prev := openShellManagedDBDrift()
	t.Cleanup(func() { openShellRecordManagedDB(prev) })
	openShellRecordManagedDB(sandboxopenshell.GatewayDBChanged)
	if got := sandboxopenshell.FoldGatewayDrift(sandboxopenshell.GatewayDriftMatch, openShellManagedDBDrift()); got != sandboxopenshell.GatewayDriftChanged {
		t.Fatalf("fold = %s", got)
	}
	// The managed step records what it read: auto approval on the
	// private gateway is a change, an unreadable answer is unknown.
	for _, c := range []struct {
		settings string
		want     sandboxopenshell.GatewayDBDrift
	}{
		{`{"proposal_approval_mode":"auto","agent_policy_proposals_enabled":false}`, sandboxopenshell.GatewayDBChanged},
		{`{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false}`, sandboxopenshell.GatewayDBClean},
		{`garbage`, sandboxopenshell.GatewayDBUnknown},
	} {
		g := &openShellGathering{}
		g.out.facts.GatewayMode = sandboxopenshell.GatewayManaged
		g.out.pin.Target = sandboxopenshell.Target{Gateway: "observer-0123456789ab"}
		g.runAt = func(_ context.Context, _ sandboxopenshell.Target, _ integration.BinaryResolveSpec, args []string) extrun.Result {
			if slices.Contains(args, "settings") {
				return extrun.Result{Outcome: extrun.OutcomeOK, Stdout: []byte(c.settings)}
			}
			return extrun.Result{Outcome: extrun.OutcomeOK, Stdout: []byte("null")}
		}
		openShellGatewayPolicyStep(context.Background(), g)
		if got := openShellManagedDBDrift(); got != c.want {
			t.Errorf("settings %s: recorded %d, want %d", c.settings, got, c.want)
		}
	}
}

// TestOpenShellEnforceStop pins the enforced stop (fix round 1, FU8-A6),
// one case per way the delete answers.
func TestOpenShellEnforceStop(t *testing.T) {
	cases := []struct {
		name     string
		outcomes []sandboxopenshell.Outcome // the last repeats
		cancelAt int                        // cancel ctx after this many deletes (0: never)
		kills    int
		want     sandboxopenshell.Outcome
		said     int
	}{
		{"gone at once: no kill", []sandboxopenshell.Outcome{sandboxopenshell.OutcomeGone}, 0, 0, sandboxopenshell.OutcomeGone, 1},
		{"unknown then gone: one kill, retried", []sandboxopenshell.Outcome{sandboxopenshell.OutcomeUnknown, sandboxopenshell.OutcomeUnknown, sandboxopenshell.OutcomeGone}, 0, 1, sandboxopenshell.OutcomeGone, 3},
		{"present until the run ends: one kill", []sandboxopenshell.Outcome{sandboxopenshell.OutcomePresent}, 3, 1, sandboxopenshell.OutcomePresent, 3},
		{"unknown until the run ends: one kill", []sandboxopenshell.Outcome{sandboxopenshell.OutcomeUnknown}, 2, 1, sandboxopenshell.OutcomeUnknown, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var n, kills, said atomic.Int32
			del := func(context.Context) sandboxopenshell.Outcome {
				i := int(n.Add(1))
				if c.cancelAt > 0 && i >= c.cancelAt {
					cancel()
				}
				return c.outcomes[min(i-1, len(c.outcomes)-1)]
			}
			got := openShellEnforceStop(ctx, del, func() bool { kills.Add(1); return true }, func(string) { said.Add(1) }, time.Millisecond)
			if got != c.want || int(kills.Load()) != c.kills || int(said.Load()) != c.said {
				t.Fatalf("outcome %s kills %d said %d; want %s, %d, %d", got, kills.Load(), said.Load(), c.want, c.kills, c.said)
			}
		})
	}
}

// TestOpenShellEnforceStopRetriesTheKill (fix round 2, FU8-R3): a kill
// that found no child yet is retried on the next tick.
func TestOpenShellEnforceStopRetriesTheKill(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var n, tries atomic.Int32
	del := func(context.Context) sandboxopenshell.Outcome {
		if n.Add(1) >= 4 {
			cancel()
		}
		return sandboxopenshell.OutcomeUnknown
	}
	kill := func() bool { return tries.Add(1) >= 3 } // no child for two ticks
	openShellEnforceStop(ctx, del, kill, func(string) {}, time.Millisecond)
	if tries.Load() != 3 {
		t.Fatalf("kill tried %d times, want 3 (retried until a child was there, then not again)", tries.Load())
	}
}
