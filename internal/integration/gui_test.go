package integration

import (
	"regexp"
	"sort"
	"testing"
)

// This file is the coverage gate for the GUI launch table (gui.go +
// gui_hosts.go + the Capability.GUI fields), the same way
// registry_coverage_test.go gates the registry: every rule the data model's
// doc comments state is pinned here as a table-driven sweep, so a new row
// cannot land with a fabricated or structurally impossible cell.
//
// In-package (not integration_test) on purpose: the completeness test has to
// count guiHosts and registry directly, which is the only honest way to
// assert that GUILaunchables() is the SINGLE accessor over BOTH carriers.

// guiIDPattern is the launch-id shape: lowercase alphanumerics separated by
// single dashes. The id is a map key the launch/preflight/install endpoints
// accept from a client, so keeping it to this alphabet keeps it obviously
// non-argv-shaped.
var guiIDPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// guiEnvNamePattern is the POSIX-ish environment-variable-name shape a
// WrapChildEnv row may export.
var guiEnvNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// guiValidSurface is the closed Surface vocabulary (models.SurfaceIDE /
// models.SurfaceDesktop, carried as strings so this package stays
// stdlib-only).
var guiValidSurface = map[string]bool{"ide": true, "desktop": true}

// guiValidInstallOS is the closed OS vocabulary for a GUI row's install
// hints. Unlike the registry's InstallHint, a GUI row may NOT use "" (any
// OS): a desktop app's install channel is always OS-specific.
var guiValidInstallOS = map[string]bool{"windows": true, "darwin": true, "linux": true}

// guiValidInstallChannel mirrors installHintValidChannel in
// dashboard_install_data_test.go. That test walks registry Binary rows only,
// so GUI rows need their own sweep over the SAME closed vocabulary
// (capability.go's InstallHint.Channel doc) — "choco" stays excluded.
var guiValidInstallChannel = map[string]bool{
	"npm": true, "script": true, "brew": true, "winget": true, "uv": true, "scoop": true,
}

// TestGUILaunchIDsUnique pins that the launch id is a usable map key across
// BOTH carriers: no registry row's GUI.ID may collide with another row's or
// with a guiHosts key, and every id is lowercase-dashed.
func TestGUILaunchIDsUnique(t *testing.T) {
	seen := map[string]string{} // id -> carrier description
	for _, g := range GUILaunchables() {
		carrier := "host table"
		if g.Adapter != "" {
			carrier = "adapter " + g.Adapter
		}
		if prev, dup := seen[g.Spec.ID]; dup {
			t.Errorf("GUI launch id %q is claimed twice: %s and %s", g.Spec.ID, prev, carrier)
			continue
		}
		seen[g.Spec.ID] = carrier
		if !guiIDPattern.MatchString(g.Spec.ID) {
			t.Errorf("GUI launch id %q (%s) is not lowercase-dashed [a-z0-9-]", g.Spec.ID, carrier)
		}
		if g.Spec.Label == "" {
			t.Errorf("GUI row %q (%s): Label is empty — the picker has nothing to render", g.Spec.ID, carrier)
		}
	}

	// The hosts table is keyed by id; a key that disagrees with the spec it
	// holds would make GUILaunchFor and the map disagree.
	for key, spec := range guiHosts {
		if key != spec.ID {
			t.Errorf("guiHosts key %q holds a spec with ID %q — the map key must be the launch id", key, spec.ID)
		}
	}
}

// TestGUILaunchHostsAreRegistryTools pins GUILaunchSpec.Hosts: every entry
// names a real registry adapter (the dashboard resolves them through For),
// and a row carried ON an adapter lists at least that adapter — otherwise a
// launch would advertise sessions it cannot attribute.
func TestGUILaunchHostsAreRegistryTools(t *testing.T) {
	for _, g := range GUILaunchables() {
		if len(g.Spec.Hosts) == 0 {
			t.Errorf("GUI row %q: Hosts is empty — a launch row that hosts no adapter captures nothing", g.Spec.ID)
		}
		seen := map[string]bool{}
		for i, host := range g.Spec.Hosts {
			if _, ok := For(host); !ok {
				t.Errorf("GUI row %q: Hosts[%d] = %q is not a registry tool", g.Spec.ID, i, host)
			}
			if seen[host] {
				t.Errorf("GUI row %q: Hosts lists %q twice", g.Spec.ID, host)
			}
			seen[host] = true
		}
		if g.Adapter != "" && !seen[g.Adapter] {
			t.Errorf("GUI row %q is carried on adapter %q but does not list it under Hosts %v",
				g.Spec.ID, g.Adapter, g.Spec.Hosts)
		}
	}
}

// TestGUIWrapSpecsStructurallyValid pins the WrapSpec contract from gui.go:
// WrapNone REQUIRES a grounded Reason (never a silent nothing), child_env
// REQUIRES well-formed env names, and config_write REQUIRES a ConfigTool
// that is a registry adapter with an actual route row — so the wrap note can
// name a writer that exists.
func TestGUIWrapSpecsStructurallyValid(t *testing.T) {
	for _, g := range GUILaunchables() {
		w := g.Spec.Wrap
		switch w.Kind {
		case WrapNone:
			if w.Reason == "" {
				t.Errorf("GUI row %q: WrapNone with an empty Reason — the grounded negative is required", g.Spec.ID)
			}
			if len(w.Env) != 0 {
				t.Errorf("GUI row %q: WrapNone but Env is non-empty %v — nothing is exported", g.Spec.ID, w.Env)
			}
			if w.ConfigTool != "" {
				t.Errorf("GUI row %q: WrapNone but ConfigTool = %q — no writer is named", g.Spec.ID, w.ConfigTool)
			}
		case WrapChildEnv:
			if len(w.Env) == 0 {
				t.Errorf("GUI row %q: child_env with no Env vars — nothing would be injected", g.Spec.ID)
			}
			for i, ev := range w.Env {
				if !guiEnvNamePattern.MatchString(ev.Name) {
					t.Errorf("GUI row %q: Env[%d].Name = %q is not a plain env-var name ^[A-Z][A-Z0-9_]*$",
						g.Spec.ID, i, ev.Name)
				}
				// A NAME carrying "=" would smuggle a value into the
				// launcher's environment composition.
				for _, r := range ev.Name {
					if r == '=' {
						t.Errorf("GUI row %q: Env[%d].Name = %q contains '=' — names only, never values",
							g.Spec.ID, i, ev.Name)
					}
				}
			}
			if w.ConfigTool != "" {
				t.Errorf("GUI row %q: child_env but ConfigTool = %q — the two mechanisms are distinct",
					g.Spec.ID, w.ConfigTool)
			}
		case WrapConfigWrite:
			if w.ConfigTool == "" {
				t.Errorf("GUI row %q: config_write with no ConfigTool — no writer is named", g.Spec.ID)
				continue
			}
			c, ok := For(w.ConfigTool)
			if !ok {
				t.Errorf("GUI row %q: config_write ConfigTool = %q is not a registry tool", g.Spec.ID, w.ConfigTool)
				continue
			}
			if c.Proxy == nil && c.ProxyProbe == nil {
				t.Errorf("GUI row %q: config_write ConfigTool = %q has neither a Proxy nor a ProxyProbe row — "+
					"there is no config-lane writer to apply the route", g.Spec.ID, w.ConfigTool)
			}
			if len(w.Env) != 0 {
				t.Errorf("GUI row %q: config_write but Env is non-empty %v — the route is persisted, not exported",
					g.Spec.ID, w.Env)
			}
		default:
			t.Errorf("GUI row %q: Wrap.Kind = %q is not in the closed vocabulary {\"\", child_env, config_write}",
				g.Spec.ID, string(w.Kind))
		}
	}
}

// TestGUIGroundedRowsHaveASpelling pins gui.go's honesty rule in both
// directions: a Grounded row carries at least one executable spelling (so it
// is Launchable), and an UNVERIFIED row carries a Note, no Names, and is
// never launchable — listed for the record, never offered.
func TestGUIGroundedRowsHaveASpelling(t *testing.T) {
	for _, g := range GUILaunchables() {
		s := g.Spec
		if s.Grounded {
			if !s.Launchable() {
				t.Errorf("GUI row %q: Grounded but Launchable() is false — no Names, DarwinApp or "+
					"AppsFolderAUMID to launch", s.ID)
			}
			continue
		}
		if s.Note == "" {
			t.Errorf("GUI row %q: Grounded=false requires a Note explaining what is unverified", s.ID)
		}
		if n := len(s.Binary.Names.Unix) + len(s.Binary.Names.Windows); n != 0 {
			t.Errorf("GUI row %q: Grounded=false but Binary.Names carries %d spelling(s) — an ungrounded "+
				"row must carry an empty Binary", s.ID, n)
		}
		if s.Launchable() {
			t.Errorf("GUI row %q: Grounded=false but Launchable() is true — an ungrounded row is never "+
				"offered for launch", s.ID)
		}
		if g.Advertised() {
			t.Errorf("GUI row %q: Grounded=false but Advertised() is true", s.ID)
		}
	}
}

// TestGUIAppsFolderRowsAreWrapNone pins the AppsFolderAUMID doc: a packaged
// app launched via `explorer.exe shell:AppsFolder\<AUMID>` inherits
// explorer's environment, never the daemon's, so such a row can never claim
// an env wrap. It must also be ProbeOnly (there is no exec-able path).
func TestGUIAppsFolderRowsAreWrapNone(t *testing.T) {
	for _, g := range GUILaunchables() {
		if g.Spec.AppsFolderAUMID == "" {
			continue
		}
		if g.Spec.Wrap.Kind == WrapChildEnv {
			t.Errorf("GUI row %q: AppsFolderAUMID rows cannot use child_env — an explorer launch inherits "+
				"explorer's environment, not the daemon's", g.Spec.ID)
		}
		if !g.Spec.ProbeOnly {
			t.Errorf("GUI row %q: AppsFolderAUMID rows must set ProbeOnly — a packaged app has no exec-able "+
				"PATH entry and the stem can collide with an unrelated binary", g.Spec.ID)
		}
		if len(g.Spec.Binary.Names.Windows) != 0 {
			t.Errorf("GUI row %q: AppsFolderAUMID rows must not declare Windows Names — the MSIX payload "+
				"under %%ProgramFiles%%\\WindowsApps is not exec'd directly", g.Spec.ID)
		}
	}
}

// TestGUIInstallHintsUseClosedVocabulary pins the guided-install data a GUI
// row feeds the same dashboard endpoint the terminal rows feed: the channel
// stays in the closed vocabulary, the OS is one of the three real ones (no
// "any OS" for a desktop app), and both Argv and Display are populated —
// Argv is spawned verbatim, Display is what the operator consents to.
func TestGUIInstallHintsUseClosedVocabulary(t *testing.T) {
	for _, g := range GUILaunchables() {
		for i, h := range g.Spec.Binary.Installs {
			if !guiValidInstallChannel[h.Channel] {
				t.Errorf("GUI row %q: Installs[%d].Channel = %q is not in the closed vocabulary "+
					"{npm,script,brew,winget,uv,scoop}", g.Spec.ID, i, h.Channel)
			}
			if !guiValidInstallOS[h.OS] {
				t.Errorf("GUI row %q: Installs[%d].OS = %q is not one of {windows,darwin,linux}",
					g.Spec.ID, i, h.OS)
			}
			if len(h.Argv) == 0 {
				t.Errorf("GUI row %q: Installs[%d] has an empty Argv — there is nothing to spawn",
					g.Spec.ID, i)
			}
			if h.Display == "" {
				t.Errorf("GUI row %q: Installs[%d] has an empty Display — the operator would consent to "+
					"an unlabelled command", g.Spec.ID, i)
			}
		}
		// The honest-zero carrier: a row with no install hint at all must
		// say why (BinaryResolveSpec.InstallNote), never render a blank.
		if len(g.Spec.Binary.Installs) == 0 && g.Spec.Grounded && g.Spec.Binary.InstallNote == "" {
			t.Errorf("GUI row %q: no Installs and no InstallNote — the grounded reason for the gap is "+
				"required", g.Spec.ID)
		}
	}
}

// TestGUISurfaceVocabulary pins Surface to the two capture-surface kinds the
// sessions.surface column carries for a GUI launch.
func TestGUISurfaceVocabulary(t *testing.T) {
	for _, g := range GUILaunchables() {
		if !guiValidSurface[g.Spec.Surface] {
			t.Errorf("GUI row %q: Surface = %q is not one of {ide,desktop}", g.Spec.ID, g.Spec.Surface)
		}
	}
}

// TestGUILaunchablesIsSortedAndComplete pins that GUILaunchables() really is
// the SINGLE accessor: it returns every registry row carrying a GUI spec
// PLUS every host row, sorted by id, with Adapter/Lifecycle composed from
// the carrier.
func TestGUILaunchablesIsSortedAndComplete(t *testing.T) {
	wantRows := 0
	for _, c := range registry {
		if c.GUI != nil {
			wantRows++
		}
	}
	got := GUILaunchables()
	if want := wantRows + len(guiHosts); len(got) != want {
		t.Fatalf("GUILaunchables() returned %d rows, want %d (%d adapter-carried + %d hosts)",
			len(got), want, wantRows, len(guiHosts))
	}

	ids := make([]string, len(got))
	for i, g := range got {
		ids[i] = g.Spec.ID
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("GUILaunchables() is not sorted by Spec.ID: %v", ids)
	}

	for _, g := range got {
		if g.Adapter == "" {
			if _, ok := guiHosts[g.Spec.ID]; !ok {
				t.Errorf("GUI row %q has no Adapter but is not in guiHosts", g.Spec.ID)
			}
			if g.Lifecycle != LifecycleActive {
				t.Errorf("GUI host row %q carries lifecycle %q — a host is not a product Observer "+
					"categorises, so it is always active", g.Spec.ID, string(g.Lifecycle))
			}
			continue
		}
		c, ok := For(g.Adapter)
		if !ok || c.GUI == nil {
			t.Errorf("GUI row %q names adapter %q, which carries no GUI spec", g.Spec.ID, g.Adapter)
			continue
		}
		if c.GUI.ID != g.Spec.ID {
			t.Errorf("GUI row %q was composed from adapter %q whose GUI.ID is %q", g.Spec.ID, g.Adapter, c.GUI.ID)
		}
		if c.Lifecycle != g.Lifecycle {
			t.Errorf("GUI row %q carries lifecycle %q but adapter %q is %q — the carrier's lifecycle must "+
				"compose through", g.Spec.ID, string(g.Lifecycle), g.Adapter, string(c.Lifecycle))
		}
	}
}

// TestGUILaunchForResolvesEveryRow pins the lookup every endpoint uses.
func TestGUILaunchForResolvesEveryRow(t *testing.T) {
	for _, want := range GUILaunchables() {
		got, ok := GUILaunchFor(want.Spec.ID)
		if !ok {
			t.Errorf("GUILaunchFor(%q) = not found, want the row", want.Spec.ID)
			continue
		}
		if got.Spec.ID != want.Spec.ID || got.Adapter != want.Adapter {
			t.Errorf("GUILaunchFor(%q) resolved to {%q, adapter %q}, want {%q, adapter %q}",
				want.Spec.ID, got.Spec.ID, got.Adapter, want.Spec.ID, want.Adapter)
		}
	}
}

// TestGUILaunchForUnknown pins the endpoints' 400 path: an unknown or empty
// id resolves to a zero row with ok=false, never a fabricated match.
func TestGUILaunchForUnknown(t *testing.T) {
	for _, id := range []string{"", "not-a-real-ide", "VSCODE", "vscode ", "claude-code"} {
		got, ok := GUILaunchFor(id)
		if ok {
			t.Errorf("GUILaunchFor(%q) = ok, want not-found (resolved to %q)", id, got.Spec.ID)
		}
		if got.Spec.ID != "" || got.Adapter != "" {
			t.Errorf("GUILaunchFor(%q) returned a non-zero row %+v on the not-found path", id, got)
		}
	}
}

// TestGUIUnadvertisedLifecycleIsNeverAdvertised pins the lifecycle policy on
// the GUI surface with a SYNTHETIC row, so the guarantee holds even while
// every real carrier happens to be active: a launchable spec on a deprecated
// or dead adapter is still never offered.
func TestGUIUnadvertisedLifecycleIsNeverAdvertised(t *testing.T) {
	launchable := GUILaunchSpec{
		ID:       "synthetic-ide",
		Label:    "Synthetic IDE",
		Surface:  "ide",
		Binary:   BinaryResolveSpec{Names: BinaryNames{Unix: []string{"synthetic"}}},
		Wrap:     WrapSpec{Kind: WrapNone, Reason: "synthetic row"},
		Hosts:    []string{"claude-code"},
		Grounded: true,
	}
	if !launchable.Launchable() {
		t.Fatal("synthetic spec is not Launchable — the fixture no longer exercises the lifecycle gate")
	}

	for _, tc := range []struct {
		name      string
		lifecycle Lifecycle
		want      bool
	}{
		{"active", LifecycleActive, true},
		{"deprecated", LifecycleDeprecated, false},
		{"dead", LifecycleDead, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := GUILaunchable{Spec: launchable, Adapter: "synthetic", Lifecycle: tc.lifecycle}
			if got := g.Advertised(); got != tc.want {
				t.Errorf("Advertised() = %v for lifecycle %q, want %v", got, string(tc.lifecycle), tc.want)
			}
		})
	}

	// An ungrounded spec is never advertised regardless of lifecycle.
	ungrounded := GUILaunchable{
		Spec:      GUILaunchSpec{ID: "synthetic-unverified", Label: "x", Surface: "desktop", Note: "unverified"},
		Adapter:   "synthetic",
		Lifecycle: LifecycleActive,
	}
	if ungrounded.Advertised() {
		t.Error("an ungrounded GUI row on an active adapter is Advertised — it must never be offered")
	}
}
