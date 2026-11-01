package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/components"
)

// TestCrossEnvSiblingCheckScopedToWatchedAdapters (live run 2, finding N4:
// with enabled_adapters = ["poolside"] and auto_register = false the daemon
// start still stat'd the Windows mount's observer.db): an unrestricted list
// always checks; a restricted one checks only when it keeps a cross-OS
// bridge tool and hooks auto-register.
func TestCrossEnvSiblingCheckScopedToWatchedAdapters(t *testing.T) {
	defaults := []string{"claude-code", "codex", "poolside", "zed"}
	for _, tc := range []struct {
		enabled []string
		auto    bool
		want    bool
	}{
		{nil, false, true},
		{defaults, false, true},
		{[]string{"poolside"}, false, false},
		{[]string{"claude-code"}, false, false},
		{[]string{"claude-code"}, true, true},
		{[]string{"zed"}, true, false},
		{[]string{"not-a-tool"}, true, false},
	} {
		if got := crossEnvSiblingCheckApplies(tc.enabled, defaults, tc.auto); got != tc.want {
			t.Errorf("%v auto=%v: %v, want %v", tc.enabled, tc.auto, got, tc.want)
		}
	}
}

// TestAdapterAllowedScopesStartupWiring (finding N4: the antigravity
// wirer counted its .pb files though antigravity was not watched): the
// predicate the start-up wiring is gated on is the watcher's own allow-list
// rule, an empty list watching everything.
func TestAdapterAllowedScopesStartupWiring(t *testing.T) {
	all := adapterAllowed(nil)
	if !all("antigravity") || !all("poolside") {
		t.Error("an empty allow-list did not watch everything")
	}
	only := adapterAllowed([]string{"poolside"})
	if !only("poolside") || only("antigravity") || only("copilot") {
		t.Error("the allow-list did not scope the wiring")
	}
}

// TestBuildWatcherWiresOnlyWatchedAdapters drives the real start-up wiring
// with enabled_adapters = ["poolside"]: no adapter wirer runs for any other
// adapter (they scan or write their own files at start).
func TestBuildWatcherWiresOnlyWatchedAdapters(t *testing.T) {
	home := pinToolHomes(t)
	tool, selection := watchedAdapterForBuild(t)
	cfgPath := filepath.Join(home, "config.toml")
	body := "[observer]\ndb_path = " + strconv.Quote(filepath.Join(home, "observer.db")) + "\n\n[observer.watch]\nenabled_adapters = [" + strconv.Quote(tool) + "]\n" + selection
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var wired []string
	old := adapterWirers
	adapterWirers = append(append([]func(adapter.Adapter, adapterWireEnv){}, old...), func(a adapter.Adapter, _ adapterWireEnv) { wired = append(wired, a.Name()) })
	t.Cleanup(func() { adapterWirers = old })
	_, cleanup, err := buildWatcherWithOverride(context.Background(), cfgPath, "")
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if len(wired) == 0 {
		t.Fatal("the watched adapter was not wired either: the check is vacuous")
	}
	for _, n := range wired {
		if n != tool {
			t.Errorf("adapter %s was wired though not watched (wired %v)", n, wired)
		}
	}
}

// watchedAdapterForBuild picks the adapter the test watches from the
// component catalogue, with the [components] lines that make it active: a
// published edition starts an unconfigured node from its own default set
// (minimal activates no adapter at all) and an inactive adapter is never
// wired. Poolside where it is active by default (the full build, as before,
// no selection); else the first adapter active by default; else poolside, or
// the first adapter this edition offers, selected with [components] add.
func watchedAdapterForBuild(t *testing.T) (tool, selection string) {
	t.Helper()
	if defaultActive(components.AdapterID("poolside")) {
		return "poolside", ""
	}
	for _, c := range components.ForBinary(components.BinaryNode) {
		if tool, ok := strings.CutPrefix(c.ID, "adapter."); ok && defaultActive(c.ID) {
			return tool, ""
		}
	}
	offered := components.Compiled(components.BinaryNode)
	pick := ""
	for _, id := range offered {
		if id == components.AdapterID("poolside") {
			pick = id
			break
		}
		if pick == "" && strings.HasPrefix(id, "adapter.") {
			pick = id
		}
	}
	if pick == "" {
		t.Fatalf("this build offers no adapter (distro %q)", components.BuildDistro())
	}
	return strings.TrimPrefix(pick, "adapter."), "\n[components]\nadd = [" + strconv.Quote(pick) + "]\n"
}
