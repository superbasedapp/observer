//go:build !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestToolInstallLedgerOnInstalled: the post-install callback fires exactly
// once, only for an install that settled as installed with its binary
// resolving; a failed install, an unresolved binary and an uninstall never
// fire it.
func TestToolInstallLedgerOnInstalled(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		exitCode int
		bin      string
		want     []string
	}{
		{"installed and resolving", 0, "/home/u/.local/bin/codex", []string{"codex"}},
		{"install failed", 1, "/home/u/.local/bin/codex", nil},
		{"installed but not resolving", 0, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, _, _, bin := newTestLedger(t, npmCodexPlan)
			*bin = tc.bin
			var got []string
			l.setOnInstalled(func(tool string) { got = append(got, tool) })
			if err := l.RecordInstall(ctx, "codex", "h1", npmCodexPlan.Argv, npmCodexPlan.Display); err != nil {
				t.Fatal(err)
			}
			l.observeExit("h1", tc.exitCode)
			l.observeExit("h1", tc.exitCode) // settles exactly once
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("onInstalled calls = %v, want %v", got, tc.want)
			}
			if tc.want == nil {
				return
			}
			rec, _, _ := l.Lookup(ctx, "codex")
			if _, err := l.Uninstall(ctx, "codex", rec.ID, func([]string) (string, error) { return "h2", nil }); err != nil {
				t.Fatal(err)
			}
			l.observeExit("h2", 0)
			if len(got) != 1 {
				t.Fatalf("an uninstall fired onInstalled: %v", got)
			}
		})
	}
	var nilLedger *toolInstallLedger
	nilLedger.setOnInstalled(func(string) {}) // nil-safe
}

// TestAutoRegisterInstalledTool drives the real writer under the TEST-ISO-1
// guard (throwaway HOME, a staged empty foreign layout): a freshly
// guided-installed tool whose mechanism auto-registers gets its hooks even
// though its config directory did not exist yet; a tool the auto-register
// decision refuses (no auto-registrable mechanism) writes nothing.
func TestAutoRegisterInstalledTool(t *testing.T) {
	requireComponents(t, "integration.hooks")
	requireActiveAdapters(t, "droid")
	crossmount.StageForeignLayoutForTest(t, crossmount.ForeignLayoutForTest{Root: t.TempDir()})
	home := t.TempDir()
	// Every profile root and tool home stays in the throwaway home
	// (surface-gap S-10, FU-4).
	pinToolHomesAt(t, home)

	var stdout, stderr bytes.Buffer
	autoRegisterInstalledTool(&stdout, &stderr, "", true, "droid")
	if !strings.Contains(stdout.String(), "auto-register droid: installed") {
		t.Fatalf("droid was not registered after its guided install: stdout %q stderr %q", stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".factory")); err != nil {
		t.Errorf("no Factory config written: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	autoRegisterInstalledTool(&stdout, &stderr, "", true, "kiro-cli")
	if stdout.Len() != 0 {
		t.Errorf("a tool with no auto-registrable mechanism was registered: %q", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".claude")); err == nil {
		t.Error("registering one installed tool touched another tool's config")
	}
}
