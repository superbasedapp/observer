package shellwrap

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// The WSL bridge target (T-419). With the observer daemon inside WSL and the
// AI tools / IDEs installed on Windows, a Windows shell (PowerShell, cmd.exe)
// never sees the daemon's own shims. The bridge target writes WINDOWS shims
// (<name>.cmd under the Windows home) and a marked PowerShell profile block,
// and every shim reaches the daemon the way the existing cross-OS bridges do:
// through `wsl.exe -d <distro> -e <linux-observer> ...` (the Claude Code hook
// bridge in internal/hook/register_crossos.go is the precedent).
//
// Each wrapped row is assigned a SIDE from its capability shape, never its
// name (CLAUDE.md #3, #5):
//
//   - SideHost: the vendor ships a Windows build (the row has Windows
//     spellings), so the Windows program keeps running AS Windows. The shim
//     asks the WSL observer (`observer shell-wrap launch-env <id>`) for the
//     routing environment the wrapped form applies - the base-URL variables
//     BridgeEnvFor names, pointed at the daemon's localhost-forwarded proxy -
//     sets it, and runs the real Windows binary.
//   - SideWSL: the row has no Windows build at all (only Unix spellings), so
//     typing its command on Windows runs `observer <verb>` INSIDE the distro.

// WSLBridge describes the Windows target reached from a daemon inside WSL.
// When Host.Bridge is set (and Host.GOOS is "windows") the planner renders
// bridge shims; the ObserverPath it bakes in is the observer binary INSIDE the
// distro (an absolute Unix path).
type WSLBridge struct {
	// Distro is the WSL distribution name passed to `wsl.exe -d`. wsl.exe
	// does not strip quotes from that argument (grounded on Windows 11,
	// 2026-10-05), so it is rendered bare and must match distroRE.
	Distro string `json:"distro"`
}

// distroRE is the closed spelling a distro name may take in a shim.
var distroRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidDistro reports whether name can be rendered into a bridge shim.
func ValidDistro(name string) bool { return distroRE.MatchString(name) }

func (b WSLBridge) validate() error {
	if !ValidDistro(b.Distro) {
		return fmt.Errorf("shellwrap: WSL distro %q cannot be rendered into a shim", b.Distro)
	}
	return nil
}

// Side says where a wrapped command's real program runs.
type Side string

// Sides. The zero value is SideHost.
const (
	// SideHost: the target OS's own program (every native shim, and a bridge
	// shim for a tool that ships a Windows build).
	SideHost Side = "host"
	// SideWSL: the program runs inside the WSL distro (bridge target only).
	SideWSL Side = "wsl"
)

// EnvVar is one base-URL variable the wrapped form points at the proxy:
// Name = <proxy URL><Suffix>.
type EnvVar struct {
	Name   string `json:"name"`
	Suffix string `json:"suffix"`
}

// envNameRE is the closed spelling of a variable name a bridge shim sets
// (and lists in WSLENV).
var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// bridgeEnvRule is one row of the table that decides which base-URL variables
// a SideHost bridge shim may carry for a row, walked top-down; the first match
// decides (CLAUDE.md #5).
type bridgeEnvRule struct {
	why   string
	match func(c integration.Capability, g *integration.GUILaunchable) bool
	vars  func(c integration.Capability, g *integration.GUILaunchable) []EnvVar
}

var bridgeEnvRules = []bridgeEnvRule{
	{"a GUI row carries exactly its child-env wrap", func(_ integration.Capability, g *integration.GUILaunchable) bool {
		return g != nil
	}, func(_ integration.Capability, g *integration.GUILaunchable) []EnvVar {
		if g.Spec.Wrap.Kind != integration.WrapChildEnv {
			return nil
		}
		out := make([]EnvVar, 0, len(g.Spec.Wrap.Env))
		for _, v := range g.Spec.Wrap.Env {
			out = append(out, EnvVar{Name: v.Name, Suffix: v.Suffix})
		}
		return out
	}},
	{"no proxy route: nothing to inject", func(c integration.Capability, _ *integration.GUILaunchable) bool {
		return c.Proxy == nil || strings.TrimSpace(c.Proxy.EnvVar) == ""
	}, nil},
	{"a gated route needs the developer's own key, which only the launcher evaluates", func(c integration.Capability, _ *integration.GUILaunchable) bool {
		return c.Proxy.Gate != nil
	}, nil},
	{"an opt-in route applies only with its launcher flag, which the shim never passes", func(c integration.Capability, _ *integration.GUILaunchable) bool {
		return c.Proxy.LaunchFlag != ""
	}, nil},
	{"a lane route needs the launcher's upstream check before it routes", func(c integration.Capability, _ *integration.GUILaunchable) bool {
		return c.Proxy.Lane != nil
	}, nil},
	{"only an environment route is read from the process environment", func(c integration.Capability, _ *integration.GUILaunchable) bool {
		return c.Proxy.Kind != integration.RouteLauncher && c.Proxy.Kind != integration.RouteEnvSettings
	}, nil},
	{
		"the row's own base-URL variable", func(integration.Capability, *integration.GUILaunchable) bool { return true },
		func(c integration.Capability, _ *integration.GUILaunchable) []EnvVar {
			return []EnvVar{{Name: c.Proxy.EnvVar, Suffix: c.Proxy.Suffix}}
		},
	},
}

// BridgeEnvFor returns the base-URL variables a SideHost bridge shim sets for
// id: the same variable (name AND suffix) the wrapped form applies through
// the process environment. It is the ONE owner of that list - the renderer
// bakes the names into the shim's WSLENV hand-over, and `observer shell-wrap
// launch-env` emits values only for these names. Empty for a row whose route
// lives only in a config file, is gated on the developer's own key, needs an
// opt-in launcher flag, or needs an upstream lane check (the honest answer
// there is "launches, no routing").
func BridgeEnvFor(id string) []EnvVar {
	var g *integration.GUILaunchable
	c, isTool := integration.For(id)
	if !isTool {
		gl, ok := integration.GUILaunchFor(id)
		if !ok {
			return nil
		}
		g = &gl
	}
	for _, r := range bridgeEnvRules {
		if !r.match(c, g) {
			continue
		}
		if r.vars == nil {
			return nil
		}
		var out []EnvVar
		for _, v := range r.vars(c, g) {
			if envNameRE.MatchString(v.Name) {
				out = append(out, v)
			}
		}
		return out
	}
	return nil
}

// commandRule is one row of the table that turns a row's grounded binary
// spellings into the command names a shim replaces on a target, and the side
// the real program runs on. Walked top-down; the first row whose match holds
// AND whose spellings yield at least one usable command name decides.
type commandRule struct {
	why   string
	match func(w integration.WrappedCommand, h Host) bool
	// names returns the raw spellings; commandNames applies the target's
	// extension strip and the closed command-name spelling.
	names func(w integration.WrappedCommand, h Host) []string
	side  Side
}

var commandRules = []commandRule{
	{
		"the target OS's own spellings", func(integration.WrappedCommand, Host) bool { return true },
		func(w integration.WrappedCommand, h Host) []string {
			if h.GOOS == "windows" {
				return w.Replaces.Windows
			}
			return w.Replaces.Unix
		}, SideHost,
	},
	{
		"a Windows build whose every executable name cannot be typed as a command " +
			"(a space: `Qoder IDE.exe`) keeps the row's Unix command stem, which its installer also puts on PATH",
		func(w integration.WrappedCommand, h Host) bool {
			return h.GOOS == "windows" && len(w.Replaces.Windows) > 0
		}, func(w integration.WrappedCommand, _ Host) []string { return w.Replaces.Unix }, SideHost,
	},
	{
		"a terminal tool with no Windows build at all runs inside WSL (bridge target only)",
		func(w integration.WrappedCommand, h Host) bool {
			return h.GOOS == "windows" && h.Bridge != nil && len(w.Replaces.Windows) == 0 &&
				w.Kind == integration.LaunchKindTerminal
		}, func(w integration.WrappedCommand, _ Host) []string { return w.Replaces.Unix }, SideWSL,
	},
}

// CheckBridgeObserverPath reports whether p (the observer binary inside the
// distro) can be baked into a bridge shim.
func CheckBridgeObserverPath(p string) error { return checkBridgeObserverPath(p) }

// ParseRegQueryValue extracts the data of value name from `reg query <key>
// /v <name>` output, whose value line reads `<name>  REG_<TYPE>  <data>`.
// The data may contain spaces. ok=false when the line is absent or carries no
// data.
func ParseRegQueryValue(out, name string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		rest, ok := strings.CutPrefix(line, name)
		if !ok || rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		rest = strings.TrimSpace(rest)
		if !strings.HasPrefix(rest, "REG_") {
			continue
		}
		i := strings.IndexAny(rest, " \t")
		if i < 0 {
			return "", false
		}
		data := strings.TrimSpace(rest[i:])
		return data, data != ""
	}
	return "", false
}

// whereText is the human line a bridge candidate carries.
func whereText(side Side, b WSLBridge) string {
	if side == SideWSL {
		return "runs inside WSL (" + b.Distro + "): this tool has no Windows build"
	}
	return "runs the Windows program; routing is asked from observer in WSL (" + b.Distro + ")"
}

// resolveCommands applies commandRules. ok=false when no row yields a name.
func resolveCommands(w integration.WrappedCommand, h Host) ([]string, Side, bool) {
	for _, r := range commandRules {
		if !r.match(w, h) {
			continue
		}
		if cmds := commandNames(r.names(w, h), h.GOOS); len(cmds) > 0 {
			return cmds, r.side, true
		}
	}
	return nil, SideHost, false
}
