package toolresolve

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// FormatVerdict renders a Resolution as honest, one-screen prose keyed to the
// tool name. It is pure (no color codes, no I/O) so the launcher stderr, the
// doctor, and the dashboard surface an identical explanation and fix. The text
// tells the operator exactly what happened and, when a tool is unusable, the
// grounded command to make it usable.
//
// pathFlag is the EXACT override flag the CALLER owns (e.g. "--opencode-path"
// for `observer opencode`) — it is NOT fabricated from the tool key, whose
// spelling differs from the real launcher flags ("--claude-path",
// "--cursor-agent-path"). When pathFlag is "" (a caller that owns no flag, e.g.
// the doctor) only the [launch.tools.<tool>].path config override is named.
func FormatVerdict(tool, pathFlag string, r Resolution) string {
	var b strings.Builder
	switch r.Verdict {
	case VerdictOK:
		fmt.Fprintf(&b, "%s: found at %s.\n", tool, r.Bin)

	case VerdictOKOffPath:
		fmt.Fprintf(&b, "%s: using %s.\n", tool, r.Bin)
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "  note: %s\n", n)
		}

	case VerdictShadowed:
		fmt.Fprintf(&b, "%s: a Windows interop shim shadows the native install on PATH.\n", tool)
		for _, s := range r.Shadowing {
			fmt.Fprintf(&b, "  shim (earlier on PATH): %s\n", s.Path)
		}
		fmt.Fprintf(&b, "  using the native %s at %s instead (the shim would crash under this OS).\n", tool, r.Bin)

	case VerdictForeignOnly:
		fmt.Fprintf(&b, "%s: installed on Windows, not in WSL — the daemon cannot launch it. Install it natively:\n", tool)
		if cmd := firstInstallDisplay(r.Installs); cmd != "" {
			fmt.Fprintf(&b, "  %s\n", cmd)
		} else {
			fmt.Fprintf(&b, "  %s\n", NoGroundedInstallMsg)
		}
		// Escape hatch: an operator who KNOWS the found /mnt candidate is a real
		// Linux-executable binary (not a Windows shim) can force it past the
		// classifier via the override the caller owns.
		fmt.Fprintf(&b, "  %s\n", overrideHint(tool, pathFlag,
			"if you know the found /mnt binary is a real Linux executable, force it"))
		fmt.Fprintf(&b, "  note: launching the Windows install from here is a planned follow-up, not yet supported.\n")

	case VerdictNotFound:
		fmt.Fprintf(&b, "%s: not installed.\n", tool)
		displays := installDisplays(r.Installs)
		if len(displays) == 0 {
			fmt.Fprintf(&b, "  %s\n", NoGroundedInstallMsg)
		}
		for _, d := range displays {
			fmt.Fprintf(&b, "  install: %s\n", d)
		}
		fmt.Fprintf(&b, "  %s.\n", overrideHint(tool, pathFlag, "override"))

	default:
		fmt.Fprintf(&b, "%s: %s.\n", tool, r.Verdict)
	}
	return b.String()
}

// overrideHint renders the manual-override escape hatch honestly. lead is the
// sentence opener ("override", or the foreign-only force-it phrase). When
// pathFlag is non-empty it names the EXACT launcher flag plus the config key;
// when it is "" (a caller that owns no flag) it names only the config key —
// never a fabricated flag.
func overrideHint(tool, pathFlag, lead string) string {
	if pathFlag != "" {
		return fmt.Sprintf(
			"%s: pass %s <path>, or set [launch.tools.%s].path in ~/.observer/config.toml",
			lead, pathFlag, tool,
		)
	}
	return fmt.Sprintf(
		"%s: set [launch.tools.%s].path in ~/.observer/config.toml",
		lead, tool,
	)
}

// firstInstallDisplay returns the first hint's Display, or "" when none.
func firstInstallDisplay(hints []integration.InstallHint) string {
	for _, h := range hints {
		if h.Display != "" {
			return h.Display
		}
	}
	return ""
}

// installDisplays collects the non-empty Display strings from the hints.
func installDisplays(hints []integration.InstallHint) []string {
	var out []string
	for _, h := range hints {
		if h.Display != "" {
			out = append(out, h.Display)
		}
	}
	return out
}
