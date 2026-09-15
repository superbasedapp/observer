package toolresolve

import (
	"fmt"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// ResolveGUI is Resolve's sibling for a GUI launch row
// (integration.GUILaunchSpec — docs/plans/ide-desktop-launch-plan-2026-09-03.md
// §2.3). It returns the SAME Resolution shape and the SAME closed verdict
// vocabulary, so the preflight / doctor / dashboard surfaces render one honest
// string for a terminal tool and an IDE alike.
//
// Three things differ from Resolve, all of them capability-shaped facts the
// spec carries (never a product-name branch):
//
//   - ProbeOnly. A row whose executable spelling COLLIDES with an unrelated
//     PATH binary (Claude Desktop's claude.exe vs the Claude Code CLI), or
//     which ships as a packaged app with no PATH alias, sets ProbeOnly: the
//     PATH walk AND the shared probe tables are skipped, and the row resolves
//     ONLY through its own Binary.ProbeDirs. Resolving such a row off PATH
//     would launch the wrong program.
//   - DarwinApp. When nothing else resolved on a darwin daemon, the row's .app
//     BUNDLE is probed under /Applications and ~/Applications. A hit is
//     VerdictOK with Bin = the bundle DIRECTORY (not an executable) and a note
//     saying the launch goes through `open -a`; internal/guilaunch composes
//     that argv.
//   - AppsFolderAUMID. A Windows packaged app (MSIX/AppX) with no resolvable
//     executable is VerdictOK with an EMPTY Bin and a note naming the
//     `explorer.exe shell:AppsFolder\<AUMID>` launch. The AppX registration is
//     deliberately NOT verified here — this package is pure (no registry, no
//     PowerShell), so the honest report is "packaged app, not probed" rather
//     than a fabricated installed / not-installed verdict.
//
// A WSL daemon that finds only a Windows install still reports
// VerdictForeignOnly, exactly as Resolve does. The GUI LAUNCH path — not this
// resolver — treats that verdict as launchable-through-interop; see
// ForeignInteropLaunchable.
func ResolveGUI(spec integration.GUILaunchSpec, env Env) Resolution {
	var notes []string

	names := candidateNames(spec.Binary, env.GOOS)
	if env.GOOS == "windows" {
		names = orderNamesByPathExt(names, env.PathExt)
	}

	// A ProbeOnly row must never resolve off PATH: an unrelated binary with the
	// same spelling would be launched instead. mergePath still runs (its
	// login-only dirs are reported for the launcher's PATH parity, and a
	// login-capture failure is still an honest Note) but contributes no
	// candidate.
	merged := mergePath(env, &notes)
	var considered []Candidate
	if !spec.ProbeOnly {
		for _, e := range merged {
			origin := OriginProcessPath
			if e.login {
				origin = OriginLoginPath
			}
			for _, name := range names {
				if c, ok := statCandidate(env, filepath.Join(e.dir, name), origin); ok {
					considered = append(considered, c)
				}
			}
		}
	}

	probeDirs := guiProbeDirs(spec, env, &notes)
	for _, dir := range probeDirs {
		for _, name := range names {
			if c, ok := statCandidate(env, filepath.Join(dir, name), OriginProbeDir); ok {
				considered = append(considered, c)
			}
		}
	}

	// Foreign probes: Windows homes over /mnt from a WSL daemon. Unlike the
	// terminal ladder these hits are not a dead end — the GUI launch path can
	// exec a Windows .exe through interop — but the VERDICT stays foreign_only
	// so every surface keeps telling the same truth about what was found.
	if env.WSL && len(spec.Binary.Names.Windows) > 0 {
		for _, home := range env.ForeignHomes {
			var rels []string
			if !spec.ProbeOnly {
				rels = append(rels, commonForeignWindowsDirs...)
			}
			for _, pd := range spec.Binary.ProbeDirs {
				if pd.OS == integration.ProbeWindows && !pd.Abs {
					rels = append(rels, pd.Rel)
				}
			}
			for _, dir := range expandProbeDirs(env, home, rels) {
				for _, name := range spec.Binary.Names.Windows {
					if c, ok := statForeignCandidate(env, filepath.Join(dir, name)); ok {
						considered = append(considered, c)
					}
				}
			}
		}
	}

	res := classify(considered)
	res.Considered = considered
	res.Installs = filterInstalls(spec.Binary.Installs, env.GOOS)
	res.LoginOnlyDirs = loginOnlyDirs(merged)
	applyInterpreterNote(&res, env, merged, probeDirs)
	// The two launch mechanisms with no resolvable executable path fire ONLY
	// when nothing executable resolved: a real hit always wins over a bundle
	// probe or a packaged-app assertion.
	if res.Bin == "" {
		applyGUIFallbacks(&res, spec, env)
	}
	res.Notes = append(notes, res.Notes...)
	return res
}

// applyGUIFallbacks applies the two OS-specific launch mechanisms that have no
// resolvable executable path: the macOS .app bundle and the Windows packaged
// app. They are mutually exclusive by daemon OS. A fallback that fires REPLACES
// the verdict with VerdictOK — each is a grounded, launchable way to start the
// app, just not through an exec of a resolved binary. The Windows arm asserts
// nothing about whether the package is actually REGISTERED: verifying that
// needs the registry / Get-AppxPackage, which this pure package must not touch,
// so the note says "packaged app" and the preflight copy says it was not
// probed.
func applyGUIFallbacks(res *Resolution, spec integration.GUILaunchSpec, env Env) {
	switch {
	case env.GOOS == "darwin" && spec.DarwinApp != "":
		bundle := spec.DarwinApp + ".app"
		dirs := []string{filepath.Join("/Applications", bundle)}
		if env.Home != "" {
			dirs = append(dirs, filepath.Join(env.Home, "Applications", bundle))
		}
		for _, dir := range dirs {
			if !statDir(env, dir) {
				continue
			}
			res.Verdict = VerdictOK
			res.Bin = dir
			res.Notes = append(res.Notes, fmt.Sprintf(
				"%s resolved as an application bundle at %s — launch via open -a",
				spec.DarwinApp, dir))
			return
		}
	case env.GOOS == "windows" && spec.AppsFolderAUMID != "":
		res.Verdict = VerdictOK
		res.Bin = ""
		res.Notes = append(res.Notes, fmt.Sprintf(
			`packaged app: launched via explorer shell:AppsFolder\%s`, spec.AppsFolderAUMID))
	}
}

// guiProbeDirs builds the ordered ABSOLUTE probe dirs for a GUI row. It defers
// to nativeProbeDirs for an ordinary row — one ladder, no copy — and narrows to
// the row's OWN ProbeDirs for a ProbeOnly row (no shared HOME table, no
// absolute table, no npm prefix), which is exactly what ProbeOnly means.
func guiProbeDirs(spec integration.GUILaunchSpec, env Env, notes *[]string) []string {
	if !spec.ProbeOnly {
		return nativeProbeDirs(spec.Binary, env, notes)
	}
	var dirs []string
	for _, pd := range spec.Binary.ProbeDirs {
		if !probeOSMatchesDaemon(pd.OS, env.GOOS) {
			continue
		}
		dirs = append(dirs, resolveProbeDirRoot(pd, env)...)
	}
	return expandGlobDirs(env, dirs)
}

// statDir reports whether path stats as a DIRECTORY. It is the macOS .app
// bundle probe: a bundle IS a directory, so statCandidate's regular-file gate
// would reject it. A nil Stat (no injected filesystem) is false — the honest
// "cannot tell", never an assumed hit.
func statDir(env Env, path string) bool {
	if env.Stat == nil {
		return false
	}
	fi, err := env.Stat(path)
	return err == nil && fi.IsDir()
}

// ForeignInteropLaunchable answers the ONE question the GUI launch path asks
// that the terminal path does not: a WSL daemon that resolved only a Windows
// install (VerdictForeignOnly) can still exec that .exe through WSL interop, so
// the launch IS possible — with the honest caveat that the daemon's environment
// does not cross the boundary (no WSLENV), which is why such a launch records
// its wrap as not-applied.
//
// It returns the FIRST foreign candidate's path and ok=true only for
// VerdictForeignOnly; every other verdict — including a native hit that merely
// SHADOWS a foreign shim — returns ok=false, because those already carry a
// launchable Bin. This is a READ over the resolver's own evidence trail, not a
// second resolution ladder, so what a surface renders can never diverge from
// what the launcher runs.
func ForeignInteropLaunchable(r Resolution) (bin string, ok bool) {
	if r.Verdict != VerdictForeignOnly {
		return "", false
	}
	for _, c := range r.Considered {
		if c.Foreign {
			return c.Path, true
		}
	}
	return "", false
}
