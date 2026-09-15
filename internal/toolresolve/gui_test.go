package toolresolve

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// sysApps is the system /Applications bundle path as the RESOLVER itself
// spells it (applyGUIFallbacks joins the literal "/Applications"). On a
// Windows test host filepath.Join turns that into "\Applications\…", so the
// fixture must be built the same way rather than through p(), which would
// prepend a drive letter the resolver never produces (DI-20 discipline).
func sysApps(bundle string) string { return filepath.Join("/Applications", bundle) }

// guiSpec is a synthetic GUI row. The rows here are deliberately synthetic
// (never a live registry lookup) so this table pins ResolveGUI's ladder rather
// than the current contents of internal/integration.
func guiSpec() integration.GUILaunchSpec {
	return integration.GUILaunchSpec{
		ID:      "editor",
		Label:   "Editor",
		Surface: "ide",
		Binary: integration.BinaryResolveSpec{
			Names: integration.BinaryNames{
				Unix:    []string{"editor"},
				Windows: []string{"Editor.exe"},
			},
		},
		Grounded: true,
	}
}

func TestResolveGUIFindsBinaryOnPath(t *testing.T) {
	t.Parallel()
	ffs := fakeFS{files: map[string]fs.FileMode{p("/usr/bin/editor"): exeMode}}
	env := ffs.env(Env{GOOS: "linux", ProcessPath: []string{p("/usr/bin")}})

	res := ResolveGUI(guiSpec(), env)
	if res.Verdict != VerdictOK || res.Bin != p("/usr/bin/editor") {
		t.Fatalf("verdict=%s bin=%s, want ok at /usr/bin/editor", res.Verdict, res.Bin)
	}
}

// TestResolveGUIProbeOnlySkipsPathAndSharedTables is the collision guard: a
// ProbeOnly row must never resolve a same-named binary from PATH or the shared
// HOME table — that is a DIFFERENT program (Claude Desktop's claude.exe vs the
// Claude Code CLI).
func TestResolveGUIProbeOnlySkipsPathAndSharedTables(t *testing.T) {
	t.Parallel()
	spec := guiSpec()
	spec.ProbeOnly = true
	spec.Binary.ProbeDirs = []integration.ProbeDir{{OS: integration.ProbeUnix, Rel: "Apps/Editor"}}

	ffs := fakeFS{files: map[string]fs.FileMode{
		p("/usr/bin/editor"):            exeMode, // PATH — must be ignored
		p("/home/u/.local/bin/editor"):  exeMode, // shared HOME table — must be ignored
		p("/home/u/Apps/Editor/editor"): exeMode, // the row's own probe dir — the only hit
	}}
	env := ffs.env(Env{
		GOOS: "linux", Home: p("/home/u"), ProcessPath: []string{p("/usr/bin")},
	})

	res := ResolveGUI(spec, env)
	if res.Bin != p("/home/u/Apps/Editor/editor") {
		t.Fatalf("bin=%s, want the probe-dir hit only (PATH + shared tables must be skipped)", res.Bin)
	}
	if res.Verdict != VerdictOKOffPath {
		t.Errorf("verdict=%s, want ok_off_path", res.Verdict)
	}
	for _, c := range res.Considered {
		if c.Path == p("/usr/bin/editor") || c.Path == p("/home/u/.local/bin/editor") {
			t.Errorf("ProbeOnly row considered %s — the PATH/shared ladder must not run", c.Path)
		}
	}
}

// TestResolveGUIAbsProbeDirWalksRelVerbatim pins ProbeDir.Abs: no HOME join.
func TestResolveGUIAbsProbeDirWalksRelVerbatim(t *testing.T) {
	t.Parallel()
	spec := guiSpec()
	spec.ProbeOnly = true
	spec.Binary.ProbeDirs = []integration.ProbeDir{
		{OS: integration.ProbeDarwin, Rel: p("/Applications/Editor.app/Contents/MacOS"), Abs: true},
	}
	ffs := fakeFS{files: map[string]fs.FileMode{
		p("/Applications/Editor.app/Contents/MacOS/editor"): exeMode,
	}}
	env := ffs.env(Env{GOOS: "darwin", Home: p("/Users/u")})

	res := ResolveGUI(spec, env)
	if res.Bin != p("/Applications/Editor.app/Contents/MacOS/editor") {
		t.Fatalf("bin=%s, want the verbatim absolute probe dir", res.Bin)
	}
}

// TestResolveGUIDarwinProbeDirIsDarwinOnly pins that a ProbeDarwin row is
// walked ONLY on a darwin daemon — a linux daemon must not probe it.
func TestResolveGUIDarwinProbeDirIsDarwinOnly(t *testing.T) {
	t.Parallel()
	spec := guiSpec()
	spec.ProbeOnly = true
	spec.Binary.ProbeDirs = []integration.ProbeDir{
		{OS: integration.ProbeDarwin, Rel: p("/Applications/Editor.app/Contents/MacOS"), Abs: true},
	}
	ffs := fakeFS{files: map[string]fs.FileMode{
		p("/Applications/Editor.app/Contents/MacOS/editor"): exeMode,
	}}

	if res := ResolveGUI(spec, ffs.env(Env{GOOS: "linux", Home: p("/home/u")})); res.Verdict != VerdictNotFound {
		t.Errorf("linux verdict=%s bin=%s, want not_found (a darwin probe dir is darwin-only)", res.Verdict, res.Bin)
	}
	if res := ResolveGUI(spec, ffs.env(Env{GOOS: "darwin", Home: p("/Users/u")})); res.Verdict == VerdictNotFound {
		t.Errorf("darwin verdict=%s, want a hit", res.Verdict)
	}
}

// TestResolveGUIDarwinBundleFallback pins the .app bundle probe: Bin is the
// BUNDLE directory and the note names the open -a launch.
func TestResolveGUIDarwinBundleFallback(t *testing.T) {
	t.Parallel()
	spec := guiSpec()
	spec.DarwinApp = "Editor"

	tests := []struct {
		name    string
		dirs    []string
		home    string
		wantBin string
	}{
		{
			name:    "system Applications",
			dirs:    []string{sysApps("Editor.app")},
			home:    p("/Users/u"),
			wantBin: sysApps("Editor.app"),
		},
		{
			name:    "user Applications",
			dirs:    []string{p("/Users/u/Applications/Editor.app")},
			home:    p("/Users/u"),
			wantBin: p("/Users/u/Applications/Editor.app"),
		},
		{
			name:    "system wins over user",
			dirs:    []string{sysApps("Editor.app"), p("/Users/u/Applications/Editor.app")},
			home:    p("/Users/u"),
			wantBin: sysApps("Editor.app"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			files := map[string]fs.FileMode{}
			for _, d := range tc.dirs {
				files[d] = fs.ModeDir | 0o755
			}
			ffs := fakeFS{files: files}
			res := ResolveGUI(spec, ffs.env(Env{GOOS: "darwin", Home: tc.home}))
			if res.Verdict != VerdictOK || res.Bin != tc.wantBin {
				t.Fatalf("verdict=%s bin=%s, want ok at %s", res.Verdict, res.Bin, tc.wantBin)
			}
			if !containsNote(res.Notes, "launch via open -a") {
				t.Errorf("notes=%q, want the open -a note", res.Notes)
			}
		})
	}
}

// TestResolveGUIDarwinBundleLosesToRealExecutable pins the precedence: a
// resolved executable always beats the bundle fallback.
func TestResolveGUIDarwinBundleLosesToRealExecutable(t *testing.T) {
	t.Parallel()
	spec := guiSpec()
	spec.DarwinApp = "Editor"
	ffs := fakeFS{files: map[string]fs.FileMode{
		p("/usr/local/bin/editor"): exeMode,
		sysApps("Editor.app"):      fs.ModeDir | 0o755,
	}}
	env := ffs.env(Env{GOOS: "darwin", Home: p("/Users/u"), ProcessPath: []string{p("/usr/local/bin")}})

	res := ResolveGUI(spec, env)
	if res.Bin != p("/usr/local/bin/editor") {
		t.Fatalf("bin=%s, want the resolved executable to win over the bundle", res.Bin)
	}
}

// TestResolveGUIPackagedAppFallback pins the Windows AUMID branch: verdict ok,
// EMPTY Bin, and a note naming the explorer launch. Nothing about the AppX
// REGISTRATION is asserted — this package cannot read the registry.
func TestResolveGUIPackagedAppFallback(t *testing.T) {
	t.Parallel()
	spec := guiSpec()
	spec.ProbeOnly = true
	spec.AppsFolderAUMID = "Vendor_abc123!App"

	res := ResolveGUI(spec, fakeFS{}.env(Env{GOOS: "windows", Home: `C:\Users\u`}))
	if res.Verdict != VerdictOK {
		t.Fatalf("verdict=%s, want ok", res.Verdict)
	}
	if res.Bin != "" {
		t.Errorf("bin=%q, want empty for a packaged app", res.Bin)
	}
	if !containsNote(res.Notes, `shell:AppsFolder\Vendor_abc123!App`) {
		t.Errorf("notes=%q, want the packaged-app note", res.Notes)
	}
}

// TestResolveGUIPackagedAppIsWindowsOnly pins that an AUMID row on a non-Windows
// daemon stays not_found — a Linux daemon cannot launch an MSIX.
func TestResolveGUIPackagedAppIsWindowsOnly(t *testing.T) {
	t.Parallel()
	spec := guiSpec()
	spec.ProbeOnly = true
	spec.AppsFolderAUMID = "Vendor_abc123!App"

	res := ResolveGUI(spec, fakeFS{}.env(Env{GOOS: "linux", Home: p("/home/u")}))
	if res.Verdict != VerdictNotFound {
		t.Errorf("verdict=%s, want not_found on linux", res.Verdict)
	}
}

// TestResolveGUINotFound pins the honest floor.
func TestResolveGUINotFound(t *testing.T) {
	t.Parallel()
	res := ResolveGUI(guiSpec(), fakeFS{}.env(Env{GOOS: "linux", Home: p("/home/u")}))
	if res.Verdict != VerdictNotFound || res.Bin != "" {
		t.Fatalf("verdict=%s bin=%q, want not_found with no bin", res.Verdict, res.Bin)
	}
}

// TestResolveGUIForeignOnlyOnWSL pins that a WSL daemon which finds only a
// Windows install still reports foreign_only — and that
// ForeignInteropLaunchable extracts that path for the GUI launch path.
func TestResolveGUIForeignOnlyOnWSL(t *testing.T) {
	t.Parallel()
	foreignHome := p("/mnt/c/Users/u")
	winExe := filepath.Join(foreignHome, "AppData/Local/Programs", "Editor.exe")
	ffs := fakeFS{files: map[string]fs.FileMode{winExe: regMode}}
	env := ffs.env(Env{
		GOOS: "linux", WSL: true, Home: p("/home/u"),
		ForeignHomes: []string{foreignHome},
	})

	res := ResolveGUI(guiSpec(), env)
	if res.Verdict != VerdictForeignOnly {
		t.Fatalf("verdict=%s, want foreign_only", res.Verdict)
	}
	if res.Bin != "" {
		t.Errorf("bin=%q, want empty for foreign_only (the resolver stays honest)", res.Bin)
	}
	bin, ok := ForeignInteropLaunchable(res)
	if !ok || bin != winExe {
		t.Errorf("ForeignInteropLaunchable = (%q, %v), want (%q, true)", bin, ok, winExe)
	}
}

// TestForeignInteropLaunchableRefusesOtherVerdicts pins that the interop
// escape hatch fires ONLY for foreign_only: every other verdict already carries
// a launchable Bin (or nothing at all), so returning a foreign shim there would
// launch the wrong binary.
func TestForeignInteropLaunchableRefusesOtherVerdicts(t *testing.T) {
	t.Parallel()
	for _, v := range []Verdict{VerdictOK, VerdictOKOffPath, VerdictShadowed, VerdictNotFound} {
		res := Resolution{
			Verdict:    v,
			Considered: []Candidate{{Path: "/mnt/c/x.exe", Foreign: true}},
		}
		if bin, ok := ForeignInteropLaunchable(res); ok {
			t.Errorf("verdict %s returned interop bin %q, want ok=false", v, bin)
		}
	}
}

// TestResolveGUICarriesInstallsForDaemonOS pins that the GUI ladder filters the
// row's install hints exactly like the terminal ladder, so the preflight's
// guided-install plan is composed from the same data.
func TestResolveGUICarriesInstallsForDaemonOS(t *testing.T) {
	t.Parallel()
	spec := guiSpec()
	spec.Binary.Installs = []integration.InstallHint{
		{OS: "linux", Channel: "script", Argv: []string{"bash", "-c", "x"}, Display: "linux"},
		{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "x"}, Display: "windows"},
	}
	res := ResolveGUI(spec, fakeFS{}.env(Env{GOOS: "linux", Home: p("/home/u")}))
	if len(res.Installs) != 1 || res.Installs[0].Display != "linux" {
		t.Fatalf("installs = %+v, want only the linux hint", res.Installs)
	}
}
