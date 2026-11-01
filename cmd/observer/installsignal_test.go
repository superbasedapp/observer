package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestExtensionIDOf pins the extension folder name split.
func TestExtensionIDOf(t *testing.T) {
	for name, want := range map[string]string{
		"anthropic.claude-code-2.1.312":           "anthropic.claude-code",
		"anthropic.claude-code-2.1.312-win32-x64": "anthropic.claude-code",
		"Google.Gemini-Code-Assist-1.9.0":         "google.gemini-code-assist",
		"ms-python.python-2026.4.0":               "ms-python.python",
		"not-an-extension":                        "",
		".obsolete":                               "",
	} {
		got, ok := extensionIDOf(name)
		if got != want || ok != (want != "") {
			t.Errorf("extensionIDOf(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
}

// TestInstallSignalTools (WINNODE item 5): Claude Code installed as a VS
// Code extension only, and a freshly installed agy binary, are detected from
// the registry's install signals; a machine with neither detects nothing.
func TestInstallSignalTools(t *testing.T) {
	rows := []integration.Capability{
		{Tool: "claude-code", InstallSignals: []integration.InstallSignal{{Kind: integration.InstallSignalEditorExtension, ExtensionID: "anthropic.claude-code"}}},
		{Tool: "antigravity-cli", Binary: &integration.BinaryResolveSpec{}, InstallSignals: []integration.InstallSignal{{Kind: integration.InstallSignalBinary}}},
		{Tool: "plain"},
	}
	extHome := t.TempDir()
	if err := os.MkdirAll(filepath.Join(extHome, ".vscode", "extensions", "anthropic.claude-code-2.1.312-win32-x64"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		home     string
		resolves bool
		want     []string
	}{
		{"vs code extension only", extHome, false, []string{"claude-code"}},
		{"fresh agy binary", t.TempDir(), true, []string{"antigravity-cli"}},
		{"both", extHome, true, []string{"antigravity-cli", "claude-code"}},
		{"neither", t.TempDir(), false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := installSignalTools(rows, installSignalProbe{
				home: tc.home, readDir: os.ReadDir,
				resolves: func(integration.BinaryResolveSpec) bool { return tc.resolves },
			})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	// The production probe under a home override reads extensions only.
	if got := installSignalToolsFor(extHome); !reflect.DeepEqual(got, []string{"claude-code"}) {
		t.Fatalf("installSignalToolsFor(override) = %v, want [claude-code]", got)
	}
}
