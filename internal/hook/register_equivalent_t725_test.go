package hook

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// T-725 (D-528, D-541): `observer start` auto-registration rewrote equivalent
// existing Claude Code hook commands (another observer binary path, no
// --config) into the running binary's path plus --config. With
// KeepEquivalentHooks (what `observer start` sets) an equivalent entry and the
// whole file stay byte-identical; only a missing or broken entry is rewritten,
// and every rewrite is reported. Every case runs in a throwaway HOME.

// t725Exec writes an executable stand-in observer binary.
func t725Exec(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// t725Settings renders a settings.json whose every Claude Code event carries
// cmdFor(event), in the hand-indented shape a user file has (CRLF-free, two
// spaces, a sibling top-level key) so any re-encode is visible.
func t725Settings(cmdFor func(event string) string) []byte {
	var b strings.Builder
	b.WriteString("{\n  \"model\": \"opus\",\n  \"hooks\": {\n")
	for i, ev := range claudeCodeEvents {
		fmt.Fprintf(&b, "    %q: [\n      {\n        \"matcher\": \"*\",\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": %q\n          }\n        ]\n      }\n    ]", ev, cmdFor(ev))
		if i < len(claudeCodeEvents)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  }\n}\n")
	return []byte(b.String())
}

type t725Case struct {
	name string
	// keep is Options.KeepEquivalentHooks.
	keep bool
	// windows drives the claude-code-windows bridge registrar.
	windows bool
	// existing returns the existing command for an event, given the
	// stand-in old binary and the home.
	existing func(oldBin, home string) func(string) string
	// removeOld deletes the old binary before registering (a broken hook).
	removeOld bool
	// wantIdentical: the file must stay byte-identical.
	wantIdentical bool
	// wantRule: the rule every event's rewrite must name ("" when kept).
	wantRule string
}

var t725Cases = []t725Case{
	{
		name: "native, other binary path, no --config: kept",
		keep: true,
		existing: func(oldBin, _ string) func(string) string {
			return func(ev string) string { return oldBin + " hook claude-code " + hookEventArg(ev) }
		},
		wantIdentical: true,
	},
	{
		name: "native, other binary path, explicit default --config: kept",
		keep: true,
		existing: func(oldBin, home string) func(string) string {
			return func(ev string) string {
				return oldBin + " hook claude-code " + hookEventArg(ev) + " --config '" + filepath.Join(home, ".observer", "config.toml") + "'"
			}
		},
		wantIdentical: true,
	},
	{
		name: "native, binary gone: rewritten",
		keep: true,
		existing: func(oldBin, _ string) func(string) string {
			return func(ev string) string { return oldBin + " hook claude-code " + hookEventArg(ev) }
		},
		removeOld: true,
		wantRule:  "binary-broken",
	},
	{
		name: "native, another config file: rewritten",
		keep: true,
		existing: func(oldBin, home string) func(string) string {
			return func(ev string) string {
				return oldBin + " hook claude-code " + hookEventArg(ev) + " --config '" + filepath.Join(home, "elsewhere", "config.toml") + "'"
			}
		},
		wantRule: "config",
	},
	{
		name: "native, consented init (keep off): refreshed to this binary",
		keep: false,
		existing: func(oldBin, _ string) func(string) string {
			return func(ev string) string { return oldBin + " hook claude-code " + hookEventArg(ev) }
		},
		wantRule: "refresh",
	},
	{
		name:    "bridge, other binary path, no --config: kept",
		keep:    true,
		windows: true,
		existing: func(oldBin, _ string) func(string) string {
			return func(ev string) string {
				return portableBridgeCommand("Ubuntu-20.04", oldBin, "claude-code", hookEventArg(ev), "")
			}
		},
		wantIdentical: true,
	},
	{
		name:    "bridge, other binary path, explicit default --config: kept",
		keep:    true,
		windows: true,
		existing: func(oldBin, home string) func(string) string {
			return func(ev string) string {
				return portableBridgeCommand("Ubuntu-20.04", oldBin, "claude-code", hookEventArg(ev), filepath.ToSlash(filepath.Join(home, ".observer", "config.toml")))
			}
		},
		wantIdentical: true,
	},
	{
		// AP-119: the Git-Bash-only MSYS_NO_PATHCONV=1 form is migrated
		// even though it runs the same binary.
		name:    "bridge, legacy MSYS_NO_PATHCONV form: rewritten",
		keep:    true,
		windows: true,
		existing: func(oldBin, _ string) func(string) string {
			return func(ev string) string {
				return "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- " + oldBin + " hook claude-code " + hookEventArg(ev)
			}
		},
		wantRule: "bridge-form",
	},
	{
		name:    "bridge, prefix-free form without the exit trailer: rewritten",
		keep:    true,
		windows: true,
		existing: func(oldBin, _ string) func(string) string {
			return func(ev string) string {
				return "wsl.exe -d Ubuntu-20.04 -- " + msysLiteralPath(oldBin) + " hook claude-code " + hookEventArg(ev)
			}
		},
		wantRule: "bridge-form",
	},
	{
		name:    "bridge target, native Windows entry: converted to the bridge",
		keep:    true,
		windows: true,
		existing: func(_, _ string) func(string) string {
			return func(ev string) string {
				return "C:/Users/u/observer/bin/observer.exe hook claude-code " + hookEventArg(ev)
			}
		},
		wantRule: "shape",
	},
	{
		name:    "bridge, another distro: rewritten",
		keep:    true,
		windows: true,
		existing: func(oldBin, _ string) func(string) string {
			return func(ev string) string {
				return "MSYS_NO_PATHCONV=1 wsl.exe -d Debian -- " + oldBin + " hook claude-code " + hookEventArg(ev)
			}
		},
		wantRule: "shape",
	},
}

func TestT725AutoRegisterKeepsEquivalentHooks(t *testing.T) {
	t.Parallel()
	for _, tc := range t725Cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			oldBin := t725Exec(t, filepath.Join(home, "old", "superbased-observer", "bin", "observer"))
			newBin := t725Exec(t, filepath.Join(home, "new", "observer.135"))
			opts := Options{
				BinaryPath:          newBin,
				HomeDir:             home,
				ChecksumsPath:       filepath.Join(home, ".observer", "hook_checksums.json"),
				ConfigPath:          filepath.Join(home, ".observer", "config.toml"),
				KeepEquivalentHooks: tc.keep,
			}
			tool := "claude-code"
			path := filepath.Join(home, ".claude", "settings.json")
			if tc.windows {
				tool = "claude-code-windows"
				opts.WSLDistro = "Ubuntu-20.04"
				opts.WindowsClaudeHome = filepath.Join(home, "winuser")
				path = filepath.Join(home, "winuser", ".claude", "settings.json")
			}
			r, err := NewRegistry(opts)
			if err != nil {
				t.Fatal(err)
			}
			body := t725Settings(tc.existing(oldBin, home))
			old := writeAged(t, path, body)
			if tc.removeOld {
				if err := os.Remove(oldBin); err != nil {
					t.Fatal(err)
				}
			}

			res := mustRegister(t, r, tool)
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantIdentical {
				if !bytes.Equal(after, body) {
					t.Fatalf("equivalent hooks rewrote the file:\nbefore %s\nafter  %s", body, after)
				}
				fi, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if !fi.ModTime().Equal(old) {
					t.Errorf("equivalent hooks touched the file (mtime %v, want %v)", fi.ModTime(), old)
				}
				if len(res.HooksAdded) != 0 || len(res.Rewrites) != 0 {
					t.Errorf("added %v rewrote %v; want nothing", res.HooksAdded, res.Rewrites)
				}
				got := append([]string(nil), res.KeptEquivalent...)
				want := append([]string(nil), claudeCodeEvents...)
				sort.Strings(got)
				sort.Strings(want)
				if strings.Join(got, ",") != strings.Join(want, ",") {
					t.Errorf("KeptEquivalent = %v, want every event", res.KeptEquivalent)
				}
				return
			}
			if bytes.Equal(after, body) {
				t.Fatal("a hook that must be rewritten was left as it was")
			}
			if len(res.Rewrites) != len(claudeCodeEvents) {
				t.Fatalf("Rewrites = %d, want one per event (%d): %+v", len(res.Rewrites), len(claudeCodeEvents), res.Rewrites)
			}
			for _, rw := range res.Rewrites {
				if rw.Rule != tc.wantRule {
					t.Errorf("event %s rewritten by rule %q, want %q (%s)", rw.Event, rw.Rule, tc.wantRule, rw.Reason)
				}
			}
			if !bytes.Contains(after, []byte(filepath.Base(newBin))) {
				t.Errorf("rewritten file does not name this binary:\n%s", after)
			}
		})
	}
}

// TestT725EquivalenceTable pins each equivalence rule on its own row.
func TestT725EquivalenceTable(t *testing.T) {
	t.Parallel()
	works := func(p string) bool { return p != "/gone/observer" }
	env := hookEquivalenceEnv{binaryWorks: works, defaultConfig: "/home/u/.observer/config.toml"}
	want := "/new/observer.135 hook claude-code stop --config '/home/u/.observer/config.toml'"
	rows := []struct {
		have string
		keep bool
		rule string
	}{
		{"/old/observer hook claude-code stop", true, ""},
		{"'/old dir/observer' hook claude-code stop --config /home/u/.observer/config.toml", true, ""},
		{"wsl.exe -d Ubuntu -- /old/observer hook claude-code stop", false, "shape"},
		{"/old/observer hook claude-code pre-tool", false, "tool-event"},
		{"/old/observer hook cursor stop", false, "tool-event"},
		{"/old/observer hook claude-code stop --verbose", false, "extra-args"},
		{"/gone/observer hook claude-code stop", false, "binary-broken"},
		{"/old/observer hook claude-code stop --config /tmp/other.toml", false, "config"},
		{"echo hi", false, "unparsed"},
	}
	for _, row := range rows {
		keep, rule, _ := decideHookEquivalence(row.have, want, env)
		if keep != row.keep || rule != row.rule {
			t.Errorf("%q: keep=%v rule=%q, want keep=%v rule=%q", row.have, keep, rule, row.keep, row.rule)
		}
	}
}
