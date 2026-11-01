package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// withSelected returns a copy of r whose Options.Selected selects exactly
// the given components (none: a selection that selects nothing, which
// deselects; a nil Selected leaves opt-in events alone).
func withSelected(t *testing.T, r *Registry, ids ...string) *Registry {
	t.Helper()
	opts := r.opts
	opts.Selected = func(c string) bool { return slices.Contains(ids, c) }
	out, err := NewRegistry(opts)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestFeedbackEventsFollowTheSelection (lane sec-h, milestone 2d): the
// post-tool events only the security feedback uses are written while
// security.feedback is selected and removed when it is not, leaving the
// vendor file byte-identical to a registration that never selected it.
func TestFeedbackEventsFollowTheSelection(t *testing.T) {
	cases := []struct{ tool, dir, event string }{
		{"gemini-cli", ".gemini", "AfterTool"},
		{"qwen-code", ".qwen", "PostToolUse"},
		{"qoder", ".qoder", "PostToolUse"},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			base := genericSettingsRegistry(t, tc.dir)
			path := filepath.Join(base.opts.HomeDir, tc.dir, "settings.json")
			if res := base.Register(tc.tool); res.Error != nil || slices.Contains(res.HooksAdded, tc.event) {
				t.Fatalf("not selected: %+v", res)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			on := withSelected(t, base, "security.feedback")
			res := on.Register(tc.tool)
			if res.Error != nil || !slices.Contains(res.HooksAdded, tc.event) {
				t.Fatalf("selected: %+v", res)
			}
			with, _ := os.ReadFile(path)
			if !bytes.Contains(with, []byte(`"`+tc.event+`"`)) || !bytes.Contains(with, []byte("hook "+tc.tool+" "+tc.event)) {
				t.Fatalf("selected file lacks %s:\n%s", tc.event, with)
			}
			if again := dryRunTwin(t, on).Register(tc.tool); len(again.HooksAdded) != 0 {
				t.Fatalf("a current selected file reads %+v", again)
			}
			off := withSelected(t, base)
			if res := off.Register(tc.tool); res.Error != nil {
				t.Fatal(res.Error)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, before) {
				t.Fatalf("deselected file differs from the never-selected one:\n%s\nwant\n%s", after, before)
			}
		})
	}
}

// TestFeedbackKeepsAForeignPostToolEntry: a developer's own entry on the
// opt-in event survives both directions.
func TestFeedbackKeepsAForeignPostToolEntry(t *testing.T) {
	base := genericSettingsRegistry(t, ".qwen")
	path := filepath.Join(base.opts.HomeDir, ".qwen", "settings.json")
	mine := `{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"./mine.sh"}]}]}}`
	if err := os.WriteFile(path, []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := withSelected(t, base, "security.feedback").Register("qwen-code"); res.Error == nil {
		t.Fatalf("a foreign entry on the event is a conflict without --force: %+v", res)
	}
	if res := base.Register("qwen-code"); res.Error != nil {
		t.Fatal(res.Error)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Contains(got, []byte("./mine.sh")) {
		t.Fatalf("the developer's entry was removed:\n%s", got)
	}
}

// TestFeedbackPluginShimSubscribesOnlyWhileSelected: the shim gains the
// tool.execute.after handler and event only while selected; deselected,
// the next registration renders the shim as it was.
func TestFeedbackPluginShimSubscribesOnlyWhileSelected(t *testing.T) {
	for _, tool := range []string{"opencode", "kilo-code-cli"} {
		t.Run(tool, func(t *testing.T) {
			home := t.TempDir()
			base := pluginShimRegistry(t, home, false, nil)
			res := base.Register(tool)
			if res.Error != nil {
				t.Fatal(res.Error)
			}
			before, _ := os.ReadFile(res.ConfigPath)
			if bytes.Contains(before, []byte("tool.execute.after")) || bytes.Contains(before, []byte("@@OBSERVER_SHIM")) {
				t.Fatal("an unselected shim carries the post-tool block or a marker")
			}
			on := withSelected(t, base, "security.feedback")
			if res := on.Register(tool); res.Error != nil {
				t.Fatal(res.Error)
			}
			with, _ := os.ReadFile(res.ConfigPath)
			if !bytes.Contains(with, []byte(`"tool.execute.after":"context_inject"`)) || !bytes.Contains(with, []byte(`hooks["tool.execute.after"]`)) {
				t.Fatal("the selected shim lacks the post-tool event or handler")
			}
			if bytes.Contains(with, []byte("@@OBSERVER_SHIM")) {
				t.Fatal("a block marker leaked into the rendered shim")
			}
			if res := withSelected(t, base).Register(tool); res.Error != nil {
				t.Fatal(res.Error)
			}
			after, _ := os.ReadFile(res.ConfigPath)
			if !bytes.Equal(after, before) {
				t.Fatal("the deselected shim differs from the never-selected one")
			}
		})
	}
}

// TestFeedbackClineFileHookFollowsTheSelection: Observer's PostToolUse file
// hook is written while selected and removed when not; a developer's own
// PostToolUse is never touched.
func TestFeedbackClineFileHookFollowsTheSelection(t *testing.T) {
	if clineHooksUnsupportedOS(runtime.GOOS) {
		t.Skip("the Cline guard is macOS / Linux only")
	}
	base := toolGateRegistry(t, false, ".cline")
	path := filepath.Join(base.opts.HomeDir, ".cline", "hooks", "PostToolUse")
	if res := base.Register("cline-cli"); res.Error != nil {
		t.Fatal(res.Error)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("an unselected registration wrote the PostToolUse hook")
	}
	on := withSelected(t, base, "security.feedback")
	res := on.Register("cline-cli")
	if res.Error != nil || !slices.Contains(res.HooksAdded, "PostToolUse") {
		t.Fatalf("selected: %+v", res)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "exec /opt/observer/bin/observer hook cline-cli PostToolUse") || !clineHookExecutable(path) {
		t.Fatalf("script:\n%s", data)
	}
	if again := dryRunTwin(t, on).Register("cline-cli"); slices.Contains(again.HooksAdded, "PostToolUse") {
		t.Fatalf("a current script reads %+v", again)
	}
	if res := withSelected(t, base).Register("cline-cli"); res.Error != nil {
		t.Fatal(res.Error)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("deselected, the PostToolUse hook stayed")
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho mine\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, r := range []*Registry{on, base} {
		if res := r.Register("cline-cli"); res.Error != nil {
			t.Fatal(res.Error)
		}
		if got, _ := os.ReadFile(path); string(got) != "#!/bin/sh\necho mine\n" {
			t.Fatalf("the developer's hook was changed:\n%s", got)
		}
	}
	// Uninstall removes Observer's script.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if res := on.Register("cline-cli"); res.Error != nil {
		t.Fatal(res.Error)
	}
	if ur := on.Unregister("cline-cli"); ur.Error != nil || !slices.Contains(ur.HooksRemoved, "PostToolUse") {
		t.Fatalf("unregister: %+v", ur)
	}
}

// TestFeedbackNilSelectedLeavesOptInAlone (merge fix for audit finding 2):
// a writer built without Options.Selected (the interactive init, the doctor
// probe, the init dry runs, the benchmark provisioner, the dashboard's
// fallback) neither removes the opt-in entries a selected registration
// wrote nor adds them on an install that never selected the component.
func TestFeedbackNilSelectedLeavesOptInAlone(t *testing.T) {
	cases := []struct{ tool, dir, event string }{
		{"gemini-cli", ".gemini", "AfterTool"},
		{"qwen-code", ".qwen", "PostToolUse"},
		{"qoder", ".qoder", "PostToolUse"},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			base := genericSettingsRegistry(t, tc.dir)
			path := filepath.Join(base.opts.HomeDir, tc.dir, "settings.json")
			if res := withSelected(t, base, "security.feedback").Register(tc.tool); res.Error != nil {
				t.Fatal(res.Error)
			}
			with, _ := os.ReadFile(path)
			if res := base.Register(tc.tool); res.Error != nil {
				t.Fatal(res.Error)
			}
			if got, _ := os.ReadFile(path); !bytes.Equal(got, with) {
				t.Fatalf("a nil selection changed the file:\n%s\nwant\n%s", got, with)
			}
			if again := dryRunTwin(t, base).Register(tc.tool); len(again.HooksAdded) != 0 {
				t.Fatalf("a nil-selection dry run reads %+v", again)
			}
			fresh := genericSettingsRegistry(t, tc.dir)
			if res := fresh.Register(tc.tool); res.Error != nil || slices.Contains(res.HooksAdded, tc.event) {
				t.Fatalf("a nil selection added the opt-in event: %+v", res)
			}
		})
	}
	for _, tool := range []string{"opencode", "kilo-code-cli"} {
		t.Run(tool, func(t *testing.T) {
			home := t.TempDir()
			base := pluginShimRegistry(t, home, false, nil)
			res := withSelected(t, base, "security.feedback").Register(tool)
			if res.Error != nil {
				t.Fatal(res.Error)
			}
			with, _ := os.ReadFile(res.ConfigPath)
			if r := base.Register(tool); r.Error != nil {
				t.Fatal(r.Error)
			}
			if got, _ := os.ReadFile(res.ConfigPath); !bytes.Equal(got, with) {
				t.Fatal("a nil selection re-rendered the shim without its post block")
			}
			if again := dryRunTwin(t, base).Register(tool); len(again.HooksAdded) != 0 {
				t.Fatalf("a nil-selection dry run reads the selected shim as stale: %+v", again)
			}
			fresh := pluginShimRegistry(t, t.TempDir(), false, nil)
			fr := fresh.Register(tool)
			if fr.Error != nil {
				t.Fatal(fr.Error)
			}
			if got, _ := os.ReadFile(fr.ConfigPath); bytes.Contains(got, []byte("tool.execute.after")) {
				t.Fatal("a nil selection added the post-tool block")
			}
		})
	}
	t.Run("cline-cli", func(t *testing.T) {
		if clineHooksUnsupportedOS(runtime.GOOS) {
			t.Skip("the Cline guard is macOS / Linux only")
		}
		base := toolGateRegistry(t, false, ".cline")
		path := filepath.Join(base.opts.HomeDir, ".cline", "hooks", "PostToolUse")
		if res := withSelected(t, base, "security.feedback").Register("cline-cli"); res.Error != nil {
			t.Fatal(res.Error)
		}
		with, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if res := base.Register("cline-cli"); res.Error != nil {
			t.Fatal(res.Error)
		}
		if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, with) {
			t.Fatalf("a nil selection removed or changed the Cline script: %v", err)
		}
		fresh := toolGateRegistry(t, false, ".cline")
		if res := fresh.Register("cline-cli"); res.Error != nil {
			t.Fatal(res.Error)
		}
		if _, err := os.Stat(filepath.Join(fresh.opts.HomeDir, ".cline", "hooks", "PostToolUse")); !os.IsNotExist(err) {
			t.Fatal("a nil selection wrote the Cline script")
		}
	})
}
