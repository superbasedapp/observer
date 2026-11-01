package jetbrainshost_test

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/jetbrainshost"
)

// TestCopilotCLIAliasResolves pins the S-1 alias: the registry's
// github-copilot-cli entry (@github/copilot, the package the 2026-09-03 run
// proved) stamps the copilot-cli session it points at, verbatim.
func TestCopilotCLIAliasResolves(t *testing.T) {
	got, ok := jetbrainshost.ParseAgentSession("acp.registry.github-copilot-cli:4c1d2e3f-aaaa-bbbb-cccc-0123456789ab\n")
	if !ok || got.Tool != models.ToolCopilotCLI || got.SessionID != "4c1d2e3f-aaaa-bbbb-cccc-0123456789ab" {
		t.Fatalf("ParseAgentSession = %+v, %v; want copilot-cli with the sid verbatim", got, ok)
	}
}

// TestUnmappedACPAgentsAreNeverStamped: an agent on the unmapped list has
// no acpAgents row (its pointer resolves to no tool), names a registry tool
// or none, and names the live check that would map it.
func TestUnmappedACPAgentsAreNeverStamped(t *testing.T) {
	mapped := jetbrainshost.ACPAgents()
	unmapped := jetbrainshost.UnmappedACPAgents()
	if len(unmapped) == 0 {
		t.Fatal("no unmapped ACP agents declared")
	}
	for agent, u := range unmapped {
		if _, ok := mapped[agent]; ok {
			t.Errorf("%s: both mapped and unmapped", agent)
		}
		if tool, ok := jetbrainshost.ToolForACPAgent(agent); ok || tool != "" {
			t.Errorf("%s: unmapped agent resolves to %q", agent, tool)
		}
		if u.Tool != "" {
			if _, ok := integration.For(u.Tool); !ok {
				t.Errorf("%s: tool %q is not a registry row", agent, u.Tool)
			}
		}
		if u.Reason == "" || u.LiveCheck == "" {
			t.Errorf("%s: needs a reason and a live check", agent)
		}
	}
	for agent, tool := range mapped {
		if _, ok := integration.For(tool); !ok {
			t.Errorf("mapped %s: tool %q is not a registry row", agent, tool)
		}
	}
}
