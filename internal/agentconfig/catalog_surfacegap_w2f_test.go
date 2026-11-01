package agentconfig

import (
	"strings"
	"testing"
)

// Surface-gap lane W2-F catalogue pins (S-10 Devin, S-11 Kiro;
// docs/audits/surface-settings-precedence-gap-review-2026-10-25.md).

// TestDevinCascadeMCPIsTheCLIFile: Cascade's MCP servers are documented in
// the Devin CLI's mcp_config.json (docs.devin.ai/desktop/cascade/mcp), so no
// Devin MCP row may still name the legacy ~/.codeium/windsurf file, and the
// CLI row carries the per-OS paths and the Cascade grounding.
func TestDevinCascadeMCPIsTheCLIFile(t *testing.T) {
	for _, f := range filesTable() {
		if f.Tool != "devin" || f.Kind != KindMCP {
			continue
		}
		for _, p := range f.Paths.All() {
			if strings.Contains(p, ".codeium") {
				t.Errorf("%s still names the legacy Cascade MCP path %q", f.ID, p)
			}
		}
	}
	f, ok := fileRowByID("devin/user-mcp")
	if !ok {
		t.Fatal("devin/user-mcp is missing")
	}
	want := OSPaths{Linux: "~/.config/devin/mcp_config.json", Darwin: "~/.config/devin/mcp_config.json", Windows: `%APPDATA%\devin\mcp_config.json`}
	if f.Paths != want {
		t.Errorf("devin/user-mcp paths = %+v, want %+v", f.Paths, want)
	}
	if f.Grounding.Source != devinCascadeMCP {
		t.Errorf("devin/user-mcp grounding = %q, want the Cascade MCP page %q", f.Grounding.Source, devinCascadeMCP)
	}
	if _, ok := fileRowByID("devin/cascade-mcp"); ok {
		t.Error("devin/cascade-mcp is still catalogued")
	}
}

// TestKiroWorkspaceCLISettingsRow: Kiro documents a workspace
// .kiro/settings/cli.json that overrides the global one (NEW-4). It is
// catalogued at project scope under its own shape, so no user-file setting
// becomes writable there by accident.
func TestKiroWorkspaceCLISettingsRow(t *testing.T) {
	f, ok := fileRowByID("kiro-cli/project-cli")
	if !ok {
		t.Fatal("kiro-cli/project-cli is missing")
	}
	if f.Scope != ScopeProjectShared || f.Kind != KindSettings {
		t.Errorf("scope/kind = %s/%s, want project-shared settings", f.Scope, f.Kind)
	}
	if f.Paths != samePath("<project>/.kiro/settings/cli.json") {
		t.Errorf("paths = %+v", f.Paths)
	}
	user, ok := fileRowByID("kiro-cli/user-cli")
	if !ok {
		t.Fatal("kiro-cli/user-cli is missing")
	}
	if f.Shape == user.Shape {
		t.Errorf("the workspace file shares shape %q with the user file; global-only keys would become project-writable", f.Shape)
	}
	if f.Precedence <= user.Precedence {
		t.Errorf("workspace precedence %d must exceed the user file's %d (the workspace value overrides)", f.Precedence, user.Precedence)
	}
	if strings.Contains(user.Note, "no project scope") {
		t.Errorf("kiro-cli/user-cli note still claims no project scope: %q", user.Note)
	}
}
