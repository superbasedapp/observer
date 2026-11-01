package diag

import (
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/jetbrainshost"
)

// checkSurfaceCoverage names, per tool, every coding surface Observer does
// not cover in full (surface-gap Wave 8, integration.CodingSurfaces), plus the
// JetBrains ACP agents whose sessions are captured but not stamped
// (jetbrainshost.UnmappedACPAgents). One informational row per tool, named
// "<tool>.surfaces" so `observer doctor <tool>` scopes to it. Each detail
// line says, per dimension, covered / gated / probe_required / not_covered /
// vendor_none with the live check that decides it. Rows are filtered to the
// platforms this node can host (surfaceOSLetters): a Visual Studio row never
// prints on a Mac, an Xcode row never on Windows. The one disk read is the
// read-only extension detector (FU-152, installedVSCodeExtensions): a row
// whose Detect names a VS Code extension installed here is marked
// "installed here" and its tool's row becomes a warning, since a surface the
// developer uses is not covered in full.
func checkSurfaceCoverage(home string, pinned bool, getenv func(string) string) []Check {
	return surfaceCoverageChecksWith(surfaceOSLetters(runtime.GOOS, crossmount.IsWSL()), installedVSCodeExtensions(doctorHomeRoot(home, pinned), getenv))
}

// surfaceOSLetters is the CodingSurface.OS letters a node on goos covers:
// its own OS, plus Windows for a WSL daemon (Observer reaches the Windows
// side's tools from WSL).
func surfaceOSLetters(goos string, wsl bool) map[string]bool {
	letters := map[string]bool{}
	switch goos {
	case "windows":
		letters["W"] = true
	case "darwin":
		letters["M"] = true
	case "linux":
		letters["L"] = true
		if wsl {
			letters["W"] = true
		}
	}
	return letters
}

// surfaceOnThisOS reports whether a row's platforms ("W M L", "M", or
// "unverified") include one of letters. An unverified row is kept: its
// platforms are what the grounding run would establish.
func surfaceOnThisOS(os string, letters map[string]bool) bool {
	if os == "unverified" {
		return true
	}
	for _, l := range strings.Fields(os) {
		if letters[l] {
			return true
		}
	}
	return false
}

// surfaceCoverageChecks builds the rows for one set of OS letters, with no
// extension installed.
func surfaceCoverageChecks(letters map[string]bool) []Check {
	return surfaceCoverageChecksWith(letters, nil)
}

// surfaceCoverageChecksWith builds the rows for one set of OS letters and
// the installed VS Code extensions (id to product host).
func surfaceCoverageChecksWith(letters map[string]bool, installed map[string]string) []Check {
	lines := map[string][]string{}
	warn := map[string]bool{}
	for _, s := range integration.CodingSurfaces() {
		if s.FullyCovered() || !surfaceOnThisOS(s.OS, letters) {
			continue
		}
		line := s.Line()
		for _, id := range s.ExtensionIDs() {
			if host, ok := installed[id]; ok {
				line = "installed here (" + id + " in " + host + "): " + line
				warn[s.Group()] = true
				break
			}
		}
		lines[s.Group()] = append(lines[s.Group()], line)
	}
	unmapped := jetbrainshost.UnmappedACPAgents()
	agents := make([]string, 0, len(unmapped))
	for id := range unmapped {
		agents = append(agents, id)
	}
	sort.Strings(agents)
	for _, id := range agents {
		u := unmapped[id]
		group, capture := u.Tool, "captured by its own adapter, not stamped ide/jetbrains-*"
		if group == "" {
			group, capture = "acp-"+id, "not captured"
		}
		lines[group] = append(lines[group], fmt.Sprintf("JetBrains ACP agent %s: %s (%s; %s)", id, capture, u.Reason, u.LiveCheck))
	}
	groups := make([]string, 0, len(lines))
	for g := range lines {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	out := make([]Check, 0, len(groups))
	for _, g := range groups {
		c := Check{
			Name:    g + ".surfaces",
			Status:  StatusOK,
			Message: fmt.Sprintf("%d surface(s) not covered in full: a live check or a writer is owed", len(lines[g])),
			Details: lines[g],
		}
		if warn[g] {
			c.Status = StatusWarn
			c.Message += "; one of them is installed here"
		}
		out = append(out, c)
	}
	return out
}
