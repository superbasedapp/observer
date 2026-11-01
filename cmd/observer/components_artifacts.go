package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/artifactstate"
	"github.com/marmutapp/superbased-observer/internal/browserhost"
	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hook/pluginshim"
	"github.com/marmutapp/superbased-observer/internal/intervention/inspectionbroker"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// components_artifacts.go is the artifact class of the component model
// (modular packaging plan 3.3.1 and 3.3.2, lane MP-ART, T-601): the
// components that ship as separate artifacts (the browser extension, the
// VS Code extension, the plugin shims, the helper binaries). Observer does
// not control their lifecycle, so their state is OBSERVED, never selected:
// this file gathers the observations (a handshake record, presence probes,
// editor extension folders) and internal/artifactstate decides each state
// through its rule tables. `observer components artifacts` prints them and
// `observer doctor components` turns a stale, incompatible or leftover one
// into a warning. Nothing here writes, deletes, or runs another program.

// browserConnectedWindow is how recent the extension's last handshake must
// be for the report to call it connected (plan 3.3.1: "in the last N days").
const browserConnectedWindow = 14 * 24 * time.Hour

// vscodeExtensionID is the VS Code extension's publisher.name
// (vscode/package.json).
const vscodeExtensionID = "superbased.superbased-observer"

// editorExtensionRoots are the per-user extension folders checked, relative
// to a home. A portable or custom-location install is outside them and is
// reported as not detected, never as not installed.
var editorExtensionRoots = []struct{ editor, rel string }{
	{"VS Code", ".vscode/extensions"},
	{"VS Code Insiders", ".vscode-insiders/extensions"},
	{"VS Code Server", ".vscode-server/extensions"},
	{"Cursor", ".cursor/extensions"},
	{"Windsurf", ".windsurf/extensions"},
	{"VSCodium", ".vscode-oss/extensions"},
}

// artifactProbes are the observations the report needs. Production fills
// them from the machine (productionArtifactProbes); tests inject them, so
// no test reads the real home, /mnt/c or /run.
type artifactProbes struct {
	Home          string
	WindowsHomes  []string
	ObserverDir   string
	GOOS          string
	WSL           bool
	UID           int
	BinaryVersion string
	Now           func() time.Time
	Getenv        func(string) string
	BridgePath    func() (string, error)
	PathExists    func(string) bool
}

// productionArtifactProbes binds the probes to this machine. Call it only
// from a command's RunE (it reads the ambient home, WSL state and env). The
// relocation variables that move a plugin-shim host's directory are read
// under the pinned-home rule (crossmount.HomeEnvAt, FU-129): an isolated
// process home reads none, so the probe reports the shims under that home.
func productionArtifactProbes(cfg config.Config) artifactProbes {
	home, _ := os.UserHomeDir()
	winHomes, _ := detectWindowsBrowserHomes()
	return artifactProbes{
		Home: home, WindowsHomes: winHomes, ObserverDir: browserObserverDir(cfg),
		GOOS: runtime.GOOS, WSL: crossmount.IsWSL(), UID: os.Getuid(), BinaryVersion: version,
		Now: time.Now, Getenv: crossmount.HomeEnvAt(home, nil), BridgePath: antigravityBridgeLocator,
		PathExists: func(p string) bool { _, err := os.Stat(p); return err == nil }, //nolint:gosec // G703: a metadata read of the user's own local path; no privilege boundary is crossed
	}
}

// collectArtifactStates derives every artifact row's state, in catalog
// order.
func collectArtifactStates(p artifactProbes, snap componentstate.Snapshot) []artifactstate.Status {
	var out []artifactstate.Status
	for _, a := range components.Artifacts() {
		switch a.Kind {
		case components.ArtifactBrowserExtension:
			out = append(out, browserArtifactState(a.ID, p, snap))
		case components.ArtifactEditorExtension:
			out = append(out, editorArtifactState(a.ID, p))
		case components.ArtifactPluginShim:
			out = append(out, shimArtifactState(a.ID, p, snap))
		case components.ArtifactHelperBinary:
			out = append(out, helperArtifactState(a, p, snap))
		}
	}
	return out
}

func browserArtifactState(id string, p artifactProbes, snap componentstate.Snapshot) artifactstate.Status {
	in := artifactstate.BrowserInput{
		ComponentActive:   snap.Active("capture.browser"),
		HostPresent:       len(browserhost.Present(browserhost.PresenceOptions{Home: p.Home, GOOS: p.GOOS, WindowsHomes: p.WindowsHomes})) > 0,
		NowMs:             p.Now().UnixMilli(),
		ConnectedWindowMs: browserConnectedWindow.Milliseconds(),
		ProtocolMin:       browserhost.ProtocolMin,
		ProtocolMax:       browserhost.ProtocolMax,
		BinaryVersion:     p.BinaryVersion,
	}
	seen, err := browserhost.LoadSeen(p.ObserverDir)
	if seen != nil {
		in.Seen = &artifactstate.Seen{Version: seen.Version, Protocol: seen.Protocol, LastSeenMs: seen.LastSeenMs}
	}
	st := artifactstate.Browser(id, in)
	if err != nil {
		st.Detail += " (the handshake record could not be read: " + err.Error() + ")"
	}
	return st
}

func editorArtifactState(id string, p artifactProbes) artifactstate.Status {
	in := artifactstate.EditorInput{BinaryVersion: p.BinaryVersion}
	scan := func(home, suffix string) {
		for _, r := range editorExtensionRoots {
			dir := filepath.Join(home, filepath.FromSlash(r.rel))
			in.Searched = append(in.Searched, dir)
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				if v, ok := artifactstate.EditorExtensionVersion(e.Name(), vscodeExtensionID); ok {
					in.Installs = append(in.Installs, artifactstate.EditorInstall{Editor: r.editor + suffix, Dir: filepath.Join(dir, e.Name()), Version: v})
				}
			}
		}
	}
	if p.Home != "" {
		scan(p.Home, "")
	}
	for _, h := range p.WindowsHomes {
		scan(h, " (Windows)")
	}
	return artifactstate.Editor(id, in)
}

func shimArtifactState(id string, p artifactProbes, snap componentstate.Snapshot) artifactstate.Status {
	getenv := p.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	hooks := snap.Active("integration.hooks")
	var hosts []artifactstate.ShimHost
	for _, tool := range pluginshim.Tools() {
		h, ok := pluginshim.HostFor(tool)
		if !ok || !h.Writable() || p.Home == "" {
			continue
		}
		dir, err := h.Dir(p.Home, getenv)
		if err != nil {
			continue
		}
		path := filepath.Join(dir, h.File())
		sh := artifactstate.ShimHost{Tool: tool, Path: path, AdapterActive: snap.AdapterActive(tool), HooksActive: hooks}
		sh.Component = "integration.hooks"
		if !sh.AdapterActive {
			sh.Component = components.AdapterID(tool)
		}
		if raw, err := os.ReadFile(path); err == nil {
			sh.Present = true
			sh.Ours = pluginshim.LooksLikeObserverShim(raw)
		}
		hosts = append(hosts, sh)
	}
	return artifactstate.Shims(id, hosts)
}

func helperArtifactState(a components.ArtifactComponent, p artifactProbes, snap componentstate.Snapshot) artifactstate.Status {
	in := artifactstate.HelperInput{}
	if len(a.Requires) > 0 {
		in.Component = a.Requires[0]
		in.ComponentActive = snap.Active(in.Component)
	}
	switch a.ID {
	case "artifact.antigravity-bridge":
		// The bridge serves a daemon under WSL reading the Windows store.
		in.Applicable = p.GOOS == "linux" && p.WSL
		if p.GOOS == "linux" && !p.WSL {
			// U13: the Linux packages carry it on purpose (a WSL daemon
			// runs it Windows-side); outside WSL it is simply unused.
			in.NotApplicableDetail = "ships beside the Linux binary for a daemon running under WSL; this daemon is not under WSL, so it is not used"
		}
		if in.Applicable && p.BridgePath != nil {
			if path, err := p.BridgePath(); err == nil {
				in.Present, in.Path = true, path
			}
		}
	case "artifact.node-inspection":
		in.Applicable = p.GOOS == "linux" && p.UID >= 0
		if in.Applicable && p.PathExists != nil {
			path := inspectionbroker.DefaultSocketPath(p.UID)
			in.Path = path
			in.Present = p.PathExists(path)
		}
	}
	return artifactstate.Helper(a.ID, in)
}

// artifactWarns reports whether a status deserves a doctor warning.
func artifactWarns(s artifactstate.Status) bool {
	switch s.State {
	case artifactstate.StateStale, artifactstate.StateIncompatible, artifactstate.StateHostRemoved:
		return true
	}
	return s.Leftover
}

// componentsArtifactChecks turns the artifact states into doctor rows, one
// per artifact, named components.artifact.<name>.
func componentsArtifactChecks(states []artifactstate.Status) []diag.Check {
	out := make([]diag.Check, 0, len(states))
	for _, s := range states {
		c := diag.Check{
			Name:    "components." + s.ID,
			Status:  diag.StatusOK,
			Message: string(s.State) + ": " + s.Detail,
		}
		if artifactWarns(s) {
			c.Status = diag.StatusWarn
			if s.Leftover {
				c.Message = "leftover, " + c.Message
			}
		}
		if s.Remedy != "" {
			c.Details = append(c.Details, "fix: "+s.Remedy)
		}
		for _, it := range s.Items {
			line := it.Name + ": " + it.State
			if it.Version != "" {
				line += " " + it.Version
			}
			if it.Path != "" {
				line += " (" + it.Path + ")"
			}
			if it.Detail != "" {
				line += ", " + it.Detail
			}
			c.Details = append(c.Details, line)
		}
		out = append(out, c)
	}
	return out
}

// componentsArtifactChecksFor wires the doctor rows for a config path.
// homeOverride is doctor's --home pin: when set, the probes look under it
// only (no cross-mounted Windows homes), like every other doctor row.
func componentsArtifactChecksFor(configPath, homeOverride string) []diag.Check {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return []diag.Check{{Name: "components.artifacts", Status: diag.StatusWarn, Message: "could not load config to check the separately installed artifacts: " + err.Error()}}
	}
	p := productionArtifactProbes(cfg)
	if homeOverride != "" {
		p.Home, p.WindowsHomes = homeOverride, nil
	}
	return componentsArtifactChecks(collectArtifactStates(p, componentSnapshotForConfig(cfg)))
}

// dashboardComponentArtifacts is the dashboard's artifact observer
// (dashapi.Options.ComponentArtifacts, T-707): each GET /api/components
// re-reads the config and observes the machine the way `observer components
// artifacts` does, so the Components page and the CLI cannot disagree. A
// config that does not load yields no states (the page then shows none).
func dashboardComponentArtifacts(configPath string) func(context.Context) []artifactstate.Status {
	return func(context.Context) []artifactstate.Status {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return nil
		}
		return collectArtifactStates(productionArtifactProbes(cfg), componentSnapshotForConfig(cfg))
	}
}

// artifactsReport is the JSON shape of `observer components artifacts --json`.
type artifactsReport struct {
	Artifacts []artifactstate.Status `json:"artifacts"`
	Note      string                 `json:"note"`
}

// artifactsNote is the honest one-liner shown with the report.
const artifactsNote = "These ship separately from the observer binary, so Observer observes them and never installs or uninstalls them. not_detected means Observer cannot see it, not that it is absent. Observer registers no URL or protocol handler."

func newComponentsArtifactsCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "artifacts",
		Short: "Show the state of the separately installed artifacts (browser and VS Code extensions, plugin shims, helpers)",
		Long: "Shows what Observer can observe about the components that ship as separate\n" +
			"artifacts: whether the browser extension is connected (and which version and\n" +
			"protocol it speaks), which VS Code extension installs are present and whether\n" +
			"they are older than this observer, the plugin shims Observer wrote into plugin\n" +
			"hosts, and the helper binaries. Read-only: it writes nothing, deletes nothing\n" +
			"and runs no other program.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("components artifacts: %w", err)
			}
			states := collectArtifactStates(productionArtifactProbes(cfg), componentSnapshotForConfig(cfg))
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(artifactsReport{Artifacts: states, Note: artifactsNote})
			}
			renderArtifactStates(cmd.OutOrStdout(), states)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Print the states as JSON")
	return cmd
}

// renderArtifactStates prints the human table plus one remedy line per
// artifact that has one.
func renderArtifactStates(w io.Writer, states []artifactstate.Status) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ARTIFACT\tSTATE\tVERSION\tDETAIL")
	for _, s := range states {
		st := string(s.State)
		if s.Leftover {
			st += " (leftover)"
		}
		v := s.Version
		if v == "" {
			v = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.ID, st, v, s.Detail)
	}
	_ = tw.Flush()
	for _, s := range states {
		if s.Remedy != "" {
			fmt.Fprintf(w, "%s: %s\n", s.ID, s.Remedy)
		}
		for _, it := range s.Items {
			fmt.Fprintf(w, "  %s %s: %s %s\n", s.ID, it.Name, it.State, strings.TrimSpace(it.Version+" "+it.Path))
		}
	}
	fmt.Fprintln(w, artifactsNote)
}
