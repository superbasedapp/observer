package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
)

func fullNodeIDs() []string {
	var out []string
	for _, c := range components.ForBinary(components.BinaryNode) {
		out = append(out, c.ID)
	}
	return out
}

// TestLegacySnapshotChangesNothing is the byte-identical guarantee at the
// daemon seam: with no [components] block every loop starts and the
// overlay leaves the config untouched.
func TestLegacySnapshotChangesNothing(t *testing.T) {
	requireUnstampedBuild(t)
	snap := componentstate.Resolve(config.ComponentsConfig{}, fullNodeIDs())
	for name := range daemonLoopComponents {
		if !loopAllowed(snap, name) {
			t.Errorf("legacy: loop %s would not start", name)
		}
	}
	cfg := config.Default()
	cfg.Remote.Enabled, cfg.Exporter.OTel.Enabled, cfg.Browser.Enabled = true, true, true
	got := applyInertOverlay(cfg, snap)
	if !got.Remote.Enabled || !got.Exporter.OTel.Enabled || !got.Browser.Enabled || got.Handoff.AllowDashboardLaunch != cfg.Handoff.AllowDashboardLaunch {
		t.Fatal("legacy overlay changed the config")
	}
	var buf bytes.Buffer
	reportComponentIssues(&buf, snap)
	if buf.Len() != 0 {
		t.Fatalf("legacy start printed component lines: %q", buf.String())
	}
}

// removalSnapshot resolves the selection `observer components remove ids`
// would write: the ids plus every dependant that requires one of them (a
// component another active one requires otherwise stays active).
func removalSnapshot(t *testing.T, ids ...string) componentstate.Snapshot {
	t.Helper()
	svc, err := componentsvc.New(componentsvc.Options{
		ConfigPath: filepath.Join(t.TempDir(), "config.toml"), Compiled: fullNodeIDs(),
		Load: func() (config.Config, error) { return config.Config{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.Preview(context.Background(), componentsvc.Change{Remove: ids})
	if err != nil {
		t.Fatal(err)
	}
	return componentstate.Resolve(p.Proposed, fullNodeIDs())
}

func TestInactiveComponentsStopLoopsAndBuilders(t *testing.T) {
	requireUnstampedBuild(t)
	snap := removalSnapshot(t, "terminals", "remote", "codeintel", "org.client", "org.update")
	for _, name := range []string{"attach-socket", "tailnet-backend", "codeintel", "org-push", "grant-renewal"} {
		if loopAllowed(snap, name) {
			t.Errorf("loop %s starts with its component removed", name)
		}
	}
	for _, name := range []string{"watcher", "retention", "proxy", "dashboard"} {
		if !loopAllowed(snap, name) {
			t.Errorf("loop %s must still start", name)
		}
	}
	cfg := config.Default()
	cfg.Remote.Enabled, cfg.Handoff.AllowDashboardLaunch, cfg.Terminal.Attach.Enabled, cfg.Update.Enabled = true, true, true, true
	got := applyInertOverlay(cfg, snap)
	if got.Remote.Enabled || got.Handoff.AllowDashboardLaunch || got.Terminal.Attach.Enabled || got.Update.Enabled {
		t.Fatalf("overlay left an inactive component's switch on (inactive: %v)", snap.Inactive())
	}
	// otlp-receiver serves ingest.otlp OR obs.
	only := removalSnapshot(t, "ingest.otlp")
	if !loopAllowed(only, "otlp-receiver") {
		t.Fatal("otlp-receiver must keep running while obs is active")
	}
}

func TestVerbGateRefusesInactiveComponentWithExitCode3(t *testing.T) {
	requireComponents(t, "codeintel")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[components]\nremove = [\"codeintel\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(dir, "legacy.toml")
	if err := os.WriteFile(legacyPath, []byte("[observer]\nlog_level = \"info\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ran := 0
	build := func() *cobra.Command {
		root := &cobra.Command{Use: "observer"}
		ci := &cobra.Command{Use: "codeintel", RunE: func(*cobra.Command, []string) error { ran++; return nil }}
		var p string
		ci.Flags().StringVar(&p, "config", "", "")
		sub := &cobra.Command{Use: "status", Run: func(*cobra.Command, []string) { ran++ }}
		sub.Flags().StringVar(&p, "config", "", "")
		ci.AddCommand(sub)
		root.AddCommand(ci, &cobra.Command{Use: "scan", RunE: func(*cobra.Command, []string) error { ran++; return nil }})
		gateComponentVerbs(root)
		return root
	}
	var errBuf bytes.Buffer
	for _, args := range [][]string{{"codeintel", "--config", cfgPath}, {"codeintel", "status", "--config", cfgPath}} {
		root := build()
		root.SetErr(&errBuf)
		root.SetArgs(args)
		err := root.Execute()
		var ec exitErr
		if !errors.As(err, &ec) || int(ec) != 3 {
			t.Fatalf("%v: want exit 3, got %v", args, err)
		}
	}
	if ran != 0 {
		t.Fatal("an inactive component's verb ran")
	}
	if !bytes.Contains(errBuf.Bytes(), []byte("installed but inactive")) {
		t.Fatalf("refusal line: %q", errBuf.String())
	}
	root := build()
	root.SetArgs([]string{"codeintel", "status", "--config", legacyPath})
	if err := root.Execute(); err != nil || ran != 1 {
		t.Fatalf("legacy config: err=%v ran=%d", err, ran)
	}
}

// TestVerbOwnersExistInTheCommandTree checks that every verb the gate
// owns is a real top-level command (catalog truth, plan 3.2 item 4).
func TestVerbOwnersExistInTheCommandTree(t *testing.T) {
	root := newRootCmdWith(usageDeps{})
	have := map[string]bool{}
	for _, c := range root.Commands() {
		have[c.Name()] = true
	}
	var missing []string
	for verb := range verbComponents() {
		if !have[verb] {
			missing = append(missing, verb)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("verbs the catalog assigns to a component but the CLI does not register: %v", missing)
	}
	if got := gatedVerbNames(root); len(got) < 20 {
		t.Fatalf("only %d gated verbs: %v", len(got), got)
	}
}

// TestVerbOwnersFollowTheCatalog (T-661, T-671): verb ownership comes from
// the catalog alone (the former override table is gone), and follows the
// plane split: the guard verb is Plane B guard, obs and eval are Plane A.
func TestVerbOwnersFollowTheCatalog(t *testing.T) {
	owners := verbComponents()
	for verb, want := range map[string]string{
		"mcp":       "agentaccess.relay",
		"mcp-relay": "agentaccess.relay",
		"serve":     "integration.mcp-server",
		"intel":     "org.client",
		"guard":     "guard",
		"obs":       "obs",
		"eval":      "obs",
	} {
		if got := owners[verb]; got != want {
			t.Errorf("verb %s owned by %q, want %q", verb, got, want)
		}
	}
}
