package agentconfig

import (
	"slices"
	"testing"
)

// TestDevcontainerFieldTable is the N2 ruling (lane SBX-P3D, proposed):
// initializeCommand is reported wherever the trust check runs; every other
// ignored field only where the container sandbox is active.
func TestDevcontainerFieldTable(t *testing.T) {
	cases := []struct {
		field string
		conds []TrustCondition
		want  bool
	}{
		{"initializeCommand", []TrustCondition{TrustCondDevcontainerHost}, true},
		{"postCreateCommand", []TrustCondition{TrustCondDevcontainerHost}, false},
		{"runArgs", []TrustCondition{TrustCondDevcontainerHost}, false},
		{"initializeCommand", []TrustCondition{TrustCondOCISandbox}, true},
		{"postCreateCommand", []TrustCondition{TrustCondOCISandbox}, true},
		{"initializeCommand", nil, false},
	}
	for _, c := range cases {
		if got := DevcontainerFieldReported(c.field, c.conds...); got != c.want {
			t.Errorf("%s under %v: %v", c.field, c.conds, got)
		}
	}
	if !DevcontainerConditionUsed(TrustCondDevcontainerHost) {
		t.Fatal("the host condition names no field")
	}
	paths := TrustPathsWith(TrustCondDevcontainerHost)
	i := slices.IndexFunc(paths, func(p TrustPath) bool { return p.Rel == ".devcontainer/devcontainer.json" })
	if i < 0 || paths[i].Class != TrustDevcontainer || len(paths[i].Sources) != 1 || paths[i].Sources[0] != "repo/devcontainer-host" {
		t.Fatalf("the host row: %+v", paths)
	}
	both := TrustPathsWith(TrustCondDevcontainerHost, TrustCondOCISandbox)
	i = slices.IndexFunc(both, func(p TrustPath) bool { return p.Rel == ".devcontainer/devcontainer.json" })
	if i < 0 || len(both[i].Sources) != 2 || len(both) != len(paths) {
		t.Fatalf("both conditions read the one file once: %+v", both[i])
	}
}

// TestDevcontainerRulingReversesByOneRow: giving the first field row the
// container condition (the orchestrator reversing the ruling) leaves the
// host condition with nothing to report, so nothing is read outside the
// container sandbox, and the container sandbox still reports every field.
func TestDevcontainerRulingReversesByOneRow(t *testing.T) {
	saved := append([]DevcontainerField(nil), devcontainerFields...)
	t.Cleanup(func() { devcontainerFields = saved })
	devcontainerFields[0].Condition = TrustCondOCISandbox
	if DevcontainerConditionUsed(TrustCondDevcontainerHost) {
		t.Fatal("the host condition still names a field")
	}
	if DevcontainerFieldReported("initializeCommand", TrustCondDevcontainerHost) {
		t.Fatal("initializeCommand still reported without the container sandbox")
	}
	if !DevcontainerFieldReported("initializeCommand", TrustCondOCISandbox) || !DevcontainerFieldReported("runArgs", TrustCondOCISandbox) {
		t.Fatal("the container sandbox lost a field")
	}
}
