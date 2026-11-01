package integration

import (
	"strings"
	"testing"
)

// TestInstallSignalsAreWellFormed: a binary signal needs the row's Binary
// spec, an extension signal a lowercase publisher.name id; the two signals
// the Windows demo needed are declared (WINNODE item 5).
func TestInstallSignalsAreWellFormed(t *testing.T) {
	for _, c := range Capabilities() {
		for _, s := range c.InstallSignals {
			switch s.Kind {
			case InstallSignalBinary:
				if c.Binary == nil {
					t.Errorf("%s: a binary install signal without a Binary spec", c.Tool)
				}
			case InstallSignalEditorExtension:
				if s.ExtensionID == "" || s.ExtensionID != strings.ToLower(s.ExtensionID) || !strings.Contains(s.ExtensionID, ".") {
					t.Errorf("%s: extension id %q is not a lowercase publisher.name", c.Tool, s.ExtensionID)
				}
			default:
				t.Errorf("%s: unknown install signal kind %q", c.Tool, s.Kind)
			}
		}
	}
	want := map[string]InstallSignal{
		"claude-code":     {Kind: InstallSignalEditorExtension, ExtensionID: "anthropic.claude-code"},
		"antigravity-cli": {Kind: InstallSignalBinary},
	}
	for tool, sig := range want {
		c, _ := For(tool)
		found := false
		for _, s := range c.InstallSignals {
			found = found || s == sig
		}
		if !found {
			t.Errorf("%s: missing install signal %+v", tool, sig)
		}
	}
}
