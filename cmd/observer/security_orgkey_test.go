//go:build !sbo_omit_security

package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestSecurityOrgDedupeTwoNodesOneSecret (lane LEFT-SHARED): two managed
// nodes (two node keys, so two different local identities) holding the
// org's dedupe key give one secret the same org_key; the file is owner-only;
// a pull that stops carrying the key removes it and later sightings carry
// none; a stored value ships only under the version it was made with.
func TestSecurityOrgDedupeTwoNodesOneSecret(t *testing.T) {
	served := &orgcontract.SecurityOrgDedupe{Version: 2, Key: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("o", 32)))}
	inForce := securityManagedState{
		Outcome: orgclient.ManagedPullOutcome{InForce: true, Version: 9},
		Policy:  &orgcontract.SecurityManagedPolicyV1{Version: 1, FindingShare: "findings", OrgDedupe: served},
	}
	type node struct {
		cfg string
		dir string
	}
	var nodes []node
	for _, name := range []string{"a", "b"} {
		cfg := filepath.Join(t.TempDir(), name, "config.toml")
		dir := secposture.LayoutFor(cfg).Dir
		nodes = append(nodes, node{cfg: cfg, dir: dir})
	}
	saved := securityOrgDedupeDir
	defer func() { securityOrgDedupeDir = saved }()
	var stored []string
	var local []string
	for _, n := range nodes {
		securityOrgDedupeDir = func() string { return n.dir }
		followSecurityOrgDedupe(inForce)
		info, err := os.Stat(filepath.Join(n.dir, securityOrgDedupeKeyName))
		if err != nil {
			t.Fatalf("key file: %v", err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("key file mode %v, want 0600", info.Mode().Perm())
		}
		identify := securityIdentify(n.cfg)
		if identify == nil {
			t.Fatal("no identify")
		}
		id := identify("aws_access_key", "AKIAIOSFODNN7EXAMPLE")
		f, ok := securitySecretFinding(secdetect.FindingInput{
			ProjectRootHash: strings.Repeat("1", 64), Path: "a.env", Line: 1,
			Hit:   secdetect.Hit{Type: "aws_access_key", Line: 1, Confidence: secdetect.ConfidenceHigh, Identity: id},
			Scope: policy.FindingScopePostWrite,
		})
		if !ok {
			t.Fatal("no finding")
		}
		stored, local = append(stored, f.OrgKey), append(local, id)
	}
	if local[0] == local[1] {
		t.Fatal("two node keys must give two local identities")
	}
	if stored[0] == "" || stored[0] != stored[1] || !strings.HasPrefix(stored[0], "v2:") {
		t.Fatalf("one secret on two nodes: %q vs %q", stored[0], stored[1])
	}
	if secfinding.WireOrgKey(stored[0], 2) == "" || secfinding.WireOrgKey(stored[0], 3) != "" {
		t.Fatal("the stored org_key ships only under its own version")
	}
	// The pull stops carrying the key: the file goes and a new sighting
	// carries no org_key.
	n := nodes[0]
	securityOrgDedupeDir = func() string { return n.dir }
	followSecurityOrgDedupe(securityManagedState{Outcome: orgclient.ManagedPullOutcome{InForce: true}, Policy: &orgcontract.SecurityManagedPolicyV1{Version: 1}})
	if _, err := os.Stat(filepath.Join(n.dir, securityOrgDedupeKeyName)); !os.IsNotExist(err) {
		t.Fatalf("the key file must be removed: %v", err)
	}
	id := securityIdentify(n.cfg)("aws_access_key", "AKIAI44QH8DHBEXAMPLE")
	if got := securityOrgIdentityFor(id); got != "" {
		t.Fatalf("a sighting without a held key carries %q", got)
	}
	// A malformed key is refused and writes nothing.
	if err := writeSecurityOrgDedupe(n.dir, &orgcontract.SecurityOrgDedupe{Version: 1, Key: "short"}); err == nil {
		t.Fatal("a malformed key must be refused")
	}
}

// TestSecurityNotApplicableFrom (gen8, lane LEFT-SHARED): only not_applicable
// key states pass, with their closed reasons; applied and refused keys, a
// key twice, and a reason outside the wire vocabulary are left out.
func TestSecurityNotApplicableFrom(t *testing.T) {
	got := securityNotApplicableFrom([]securityscanning.KeyState{
		{Key: "require.finding_retention_days", State: securityscanning.StateApplied},
		{Key: "require.commit_gate", State: securityscanning.StateNotApplicable, Reason: securityscanning.ReasonIndividualNode},
		{Key: "require.commit_gate", State: securityscanning.StateNotApplicable, Reason: securityscanning.ReasonNotBuilt},
		{Key: "components:security.deps", State: securityscanning.StateNotApplicable, Reason: securityscanning.ReasonComponentAbsent},
		{Key: "require.x", State: securityscanning.StateNotApplicable, Reason: "made_up"},
	})
	want := []orgcontract.FamilyKeyNotApplicable{
		{Key: "require.commit_gate", Reason: "individual_node"},
		{Key: "components:security.deps", Reason: "component_absent"},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
