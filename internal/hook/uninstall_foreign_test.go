package hook

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// FU-203: `observer uninstall` applies the FU-192 judgement on removal. An
// entry in Observer's `<bin> hook <tool> <event>` shape (or an Observer
// plugin whose PROFILE bin is) that runs a binary not judged an Observer
// binary is kept byte for byte, with or without --force, and reported in
// HooksKeptForeign; a moved Observer's entry is still removed.

// fu203Reports are the uninstall paths that recognise Observer's entries by
// command shape, file marker or plugin PROFILE (the paths FU-203 names: Claude
// Code, Cursor and Codex with their -windows, -xcode and -wsl forms, the
// generic settings writer, the owned scripts, the plugin shims), so they must
// report the entry they keep. Every other target keeps it too (its
// recogniser is token-strict), which the byte compare checks.
func fu203Reports(target string) bool {
	base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(target, "-windows"), "-xcode"), "-wsl")
	switch base {
	case "claude-code", "cursor", "codex", "gemini-cli", "qwen-code", "qoder",
		"dirac", "kimchi", "opencode", "kilo-code-cli", "pi", "cline-cli", "command-code":
		return true
	}
	return false
}

// TestFU203UninstallKeepsAForeignBinaryInObserversShape walks every hook
// writer's removal.
func TestFU203UninstallKeepsAForeignBinaryInObserversShape(t *testing.T) {
	var cases []fu192Case
	cases = append(cases, fu192ParityCases(t)...)
	cases = append(cases, fu192XcodeCases(t)...)
	cases = append(cases, fu192WSLCases(t)...)
	cases = append(cases, fu192GatedCases(t)...)
	var reported []string
	for _, c := range cases {
		if fu203Reports(c.target) {
			reported = append(reported, c.target)
		}
		t.Run(c.target, func(t *testing.T) {
			first := c.register(fu192Observer, false, false)
			if first.Error != nil || first.Skipped {
				t.Fatalf("first register = %+v", first)
			}
			clean := fu192Snapshot(t, c.root)
			if !fu192Rewrite(t, c.root, c.observer, c.foreign) {
				t.Fatalf("the written files never name %s", c.observer)
			}
			planted := fu192Snapshot(t, c.root)

			for _, force := range []bool{false, true} {
				res := c.unregister(fu192Observer, force)
				if res.Error != nil {
					t.Fatalf("force=%v: uninstall over a foreign binary: %v", force, res.Error)
				}
				if got := fu192Snapshot(t, c.root); !mapsEqual(got, planted) {
					t.Fatalf("force=%v: uninstall changed the foreign entry:\n%s", force, fu192Diff(planted, got))
				}
				if len(res.HooksRemoved) != 0 {
					t.Errorf("force=%v: HooksRemoved = %v, want none", force, res.HooksRemoved)
				}
				if fu203Reports(c.target) && len(res.HooksKeptForeign) == 0 {
					t.Errorf("force=%v: the kept entry is not reported: %+v", force, res)
				}
			}

			// A moved Observer: installed from one path, uninstalled from
			// another; its entries are removed without --force.
			for p := range planted {
				if _, ok := clean[p]; !ok {
					_ = os.Remove(p)
				}
			}
			for p, body := range clean {
				if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if res := c.register(fu192Moved, false, false); res.Error != nil {
				t.Fatalf("moved Observer register: %v", res.Error)
			}
			if !fu192Holds(t, c.root, c.moved) {
				t.Fatalf("the moved Observer's entry was not written")
			}
			res := c.unregister(fu192Observer, false)
			if res.Error != nil {
				t.Fatalf("uninstall of a moved Observer: %v", res.Error)
			}
			if len(res.HooksKeptForeign) != 0 {
				t.Errorf("a moved Observer's entry was reported foreign: %v", res.HooksKeptForeign)
			}
			if fu192Holds(t, c.root, c.moved) {
				t.Errorf("the moved Observer's entry was not removed:\n%v", fu192Snapshot(t, c.root))
			}
		})
	}
	sort.Strings(reported)
	if len(reported) == 0 {
		t.Fatal("no uninstall path names a reported target")
	}
}
