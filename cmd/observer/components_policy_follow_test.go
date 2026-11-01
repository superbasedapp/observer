package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodecomponents"
)

// TestComponentPolicyFollowerTearsDownNewlyBlockedOnce is T-682's live
// follow: a component the org's policy newly blocks (with on_remove teardown
// auto) has its teardown run once, live; one inactive at daemon start, one
// the local selection removed, and an individual node are never touched.
func TestComponentPolicyFollowerTearsDownNewlyBlockedOnce(t *testing.T) {
	requireComponents(t, "codeintel", "terminals")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "none.db"))+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// "remote" was already inactive at start; "codeintel" and "terminals"
	// become policy-blocked later.
	start := componentstate.Resolve(config.ComponentsConfig{Remove: []string{"remote"}}, nil)
	f := newComponentPolicyFollower(cfgPath, nil, start, nil)
	managed := true
	auto := nodecomponents.TeardownAuto
	f.resolve = func(context.Context, config.Config) (componentstate.Snapshot, nodecomponents.Outcome) {
		deny := []string{"codeintel", "remote", "terminals"}
		var allow []string
		for _, id := range components.Compiled(components.BinaryNode) {
			if id != "codeintel" && id != "remote" && id != "terminals" {
				allow = append(allow, id)
			}
		}
		gov := &components.Governance{Policy: &components.PolicySets{Source: "policy", Allow: allow, Deny: deny}}
		g := componentstate.Governed{OrgManaged: managed, OrgName: "Acme", Source: "policy", Governance: gov}
		out := nodecomponents.Outcome{Source: nodecomponents.SourcePolicy, Spec: &nodecomponents.PolicySpec{OnRemove: nodecomponents.OnRemove{Teardown: auto, Data: nodecomponents.DataKeep}}}
		return componentstate.ResolveGoverned(config.ComponentsConfig{}, nil, g), out
	}
	var calls [][]string
	f.teardown = func(_ context.Context, ids []string) ([]componentsvc.StepOutcome, error) {
		calls = append(calls, ids)
		return nil, nil
	}
	f.pass(context.Background())
	f.pass(context.Background())
	if len(calls) != 1 || len(calls[0]) != 2 || calls[0][0] != "codeintel" || calls[0][1] != "terminals" {
		t.Fatalf("teardown calls = %v, want one call for [codeintel terminals]", calls)
	}
	// Manual teardown policy: nothing runs.
	calls, auto = nil, nodecomponents.TeardownManual
	f.tornDown = map[string]bool{}
	f.pass(context.Background())
	if len(calls) != 0 {
		t.Fatalf("manual teardown policy ran teardown: %v", calls)
	}
	// An individual node: nothing.
	auto, managed = nodecomponents.TeardownAuto, false
	f.pass(context.Background())
	if len(calls) != 0 {
		t.Fatalf("individual node ran teardown: %v", calls)
	}
}

// TestPurgePolicyOfAndVersion pins the purge authorisation rendering: only
// data "purge" with a positive delay authorises, and any policy change is a
// new version.
func TestPurgePolicyOfAndVersion(t *testing.T) {
	keep := nodecomponents.Outcome{Spec: &nodecomponents.PolicySpec{OnRemove: nodecomponents.OnRemove{Data: nodecomponents.DataKeep}}}
	if purgePolicyOf(keep) != nil || purgePolicyOf(nodecomponents.Outcome{}) != nil {
		t.Fatal("keep or no policy must not authorise a purge")
	}
	spec := &nodecomponents.PolicySpec{Distro: "managed", OnRemove: nodecomponents.OnRemove{Teardown: "auto", Data: nodecomponents.DataPurge, PurgeAfterDays: 30}}
	p := purgePolicyOf(nodecomponents.Outcome{Spec: spec})
	if p == nil || p.AfterDays != 30 || p.Version == "" {
		t.Fatalf("purge policy = %+v", p)
	}
	spec2 := *spec
	spec2.Distro = "developer"
	if purgePolicyOf(nodecomponents.Outcome{Spec: &spec2}).Version == p.Version {
		t.Fatal("a changed policy must be a new version")
	}
}
