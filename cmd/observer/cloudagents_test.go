package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
)

// TestCloudAgentsHelpNamesEveryConnector pins that the help of
// `observer cloud-agents` names every row of the connector table: the root
// Short by label, the root Long by id and label, `connect` by id with an
// example line, and `test` names every API connector. The help once named
// only the first five vendors after three more had landed.
func TestCloudAgentsHelpNamesEveryConnector(t *testing.T) {
	root := newCloudAgentsCmd()
	long := map[string]string{}
	for _, c := range root.Commands() {
		long[c.Name()] = c.Long
	}
	for _, c := range cloudagents.Connectors {
		if !strings.Contains(root.Short, c.Label) {
			t.Errorf("Short does not name %s (%q): %q", c.ID, c.Label, root.Short)
		}
		if !strings.Contains(root.Long, c.ID) || !strings.Contains(root.Long, c.Label) {
			t.Errorf("Long does not name %s (%q):\n%s", c.ID, c.Label, root.Long)
		}
		if !strings.Contains(long["connect"], "connect "+c.ID) {
			t.Errorf("connect help has no example for %s:\n%s", c.ID, long["connect"])
		}
		if c.Kind == cloudagents.SourceAPI && !strings.Contains(long["test"], c.ID) {
			t.Errorf("test help does not name API connector %s:\n%s", c.ID, long["test"])
		}
	}
}

func runCloudAgents(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newCloudAgentsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// TestCloudAgentsCLI_NothingLinked: with no account linked every verb
// works on the local database only and says nothing is pulled.
func TestCloudAgentsCLI_NothingLinked(t *testing.T) {
	cfg := plansTestConfig(t)
	t.Setenv("PATH", t.TempDir()) // no codex or gh: any call would fail loudly below
	out, err := runCloudAgents(t, "--config", cfg)
	if err != nil || !strings.Contains(out, "No cloud-agent account linked") {
		t.Fatalf("status: %v %s", err, out)
	}
	out, err = runCloudAgents(t, "status", "--json", "--config", cfg)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Connectors []struct{ ID string } `json:"connectors"`
		Accounts   []json.RawMessage     `json:"accounts"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil || len(v.Connectors) < 2 || v.Accounts == nil || len(v.Accounts) != 0 {
		t.Fatalf("status --json: %v %s", err, out)
	}
	out, err = runCloudAgents(t, "sync", "--config", cfg)
	if err != nil || !strings.Contains(out, "Nothing pulled") {
		t.Fatalf("sync: %v %s", err, out)
	}
	if _, err := runCloudAgents(t, "disconnect", "x", "--config", cfg); err == nil {
		t.Fatal("a non-numeric account id must fail")
	}
	if _, err := runCloudAgents(t, "disconnect", "7", "--config", cfg); err == nil {
		t.Fatal("an unknown account must fail")
	}
	if _, err := runCloudAgents(t, "connect", "made-up", "--config", cfg); err == nil {
		t.Fatal("an unknown connector must fail")
	}
}
