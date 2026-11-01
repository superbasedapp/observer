package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestConfigLayerSourceUserSetBobPolicy (FU-105): the managed-integrity
// settings-layer reading carries the closed ibm-bob/user_policy_override
// label exactly when IBM Bob's user preferences domain sets a policy key,
// whether or not the administrator also sets it, through the real
// effective-layer evaluator; no key name, value or path crosses. (An
// individual node never runs the collector at all:
// orgclient.TestReportManagedIntegrityIsManagedOnly and
// TestUserPolicyLabelNeverLeavesAnIndividualNode.)
func TestConfigLayerSourceUserSetBobPolicy(t *testing.T) {
	const label = "ibm-bob/user_policy_override"
	cases := []struct {
		name string
		dom  hook.IBMBobPolicyDomains
		want []string
	}{
		{name: "no user keys", dom: hook.IBMBobPolicyDomains{ManagedKeys: []string{"GatewayUrl"}}},
		{name: "a key the administrator also sets", dom: hook.IBMBobPolicyDomains{ManagedKeys: []string{"GatewayUrl"}, UserSource: "/u", UserKeys: []string{"GatewayUrl"}}, want: []string{label}},
		{name: "a key the administrator did not set", dom: hook.IBMBobPolicyDomains{ManagedKeys: []string{"GatewayUrl"}, UserSource: "/u", UserKeys: []string{"UpdateMode"}}, want: []string{label}},
		{name: "user keys with no managed domain", dom: hook.IBMBobPolicyDomains{UserSource: "/u", UserKeys: []string{"EnableTelemetry", "EnforcedHooks"}}, want: []string{label}},
		{name: "an unreadable user domain is not a finding", dom: hook.IBMBobPolicyDomains{UserSource: "/u", UserProblem: "/u is not a regular file"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := pinToolHomes(t)
			var sawHome string
			var sawSystem bool
			host := configLayerHost{
				Home: home, GOOS: "darwin", Getenv: func(string) string { return "" }, SystemRoot: filepath.Join(home, "no-system"),
				PolicyDomains: func(h string, system bool) []agentconfig.RuntimeTree {
					sawHome, sawSystem = h, system
					return tc.dom.LayerTrees()
				},
			}
			report := orgcontract.ManagedIntegrityReport{CaptureCheckVersion: orgcontract.ManagedCaptureCheckVersion}
			addConfigLayers(context.Background(), newConfigLayerSource(&fakeRootLister{}, host), &report)
			if sawHome != home || !sawSystem {
				t.Fatalf("policy domains read at %q system=%v, want the node home with managed domains", sawHome, sawSystem)
			}
			norm := report.NormalizeLabels()
			var bob []string
			for _, l := range norm.ConfigLayerRisks {
				if strings.HasPrefix(l, "ibm-bob/") {
					bob = append(bob, l)
				}
			}
			if !reflect.DeepEqual(bob, tc.want) {
				t.Fatalf("ibm-bob config_layer_risks = %v, want %v (all %v)", bob, tc.want, norm.ConfigLayerRisks)
			}
			wire, err := json.Marshal(norm)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"GatewayUrl", "UpdateMode", "EnforcedHooks", "EnableTelemetry", "com.ibm.bob", "user_prefs"} {
				if strings.Contains(string(wire), forbidden) {
					t.Fatalf("the wire carries %q: %s", forbidden, wire)
				}
			}
		})
	}
}
