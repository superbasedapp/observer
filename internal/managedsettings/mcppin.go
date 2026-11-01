package managedsettings

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/winshim"
)

// mcpPinLaunch returns the command and args of Observer's npx-bootstrapped
// MCP pin in the form tool's client starts on targetOS. On native Windows an
// npm shim needs a client-specific form (`npx.cmd` or `cmd /c npx`); the
// client's registry row says which (MCPTarget.WindowsStdio), so this never
// branches on the tool name. Every other OS, and a client with no grounded
// Windows behaviour, gets the plain `npx -y <pkg> serve`.
func mcpPinLaunch(tool, pkg, targetOS string) (string, []string) {
	how := winshim.LaunchAsIs
	if c, ok := integration.For(tool); ok && c.MCP != nil {
		how = c.MCP.WindowsStdio
	}
	return winshim.StdioLaunch("npx", []string{"-y", pkg, "serve"}, targetOS, how)
}

// cmdMetachars are the characters cmd.exe interprets on a command line. On
// native Windows every pin form reaches cmd.exe (`cmd /c`, or the batch file
// `npx.cmd`), so a package spec carrying one could run a second command.
const cmdMetachars = "&|<>^%!\"() \t\r\n"

// validatePinPackage refuses a package spec the Windows pin cannot carry
// safely. Other target OSes keep their unchanged behaviour (an exec argv,
// no shell), so it only checks a Windows target.
func validatePinPackage(pkg, targetOS string) error {
	if targetOS != "windows" {
		return nil
	}
	if i := strings.IndexAny(pkg, cmdMetachars); i >= 0 {
		return fmt.Errorf("managedsettings: MCP package %q contains %q, which cmd.exe would interpret on a Windows node", pkg, pkg[i])
	}
	return nil
}

// windowsPinNote is the README paragraph for a pin rewritten for native
// Windows (its command is no longer the plain `npx`), indented by indent.
// It returns "" for the plain form, so a POSIX README is unchanged.
func windowsPinNote(command string, args []string, indent string) string {
	if command == "npx" {
		return ""
	}
	return indent + "This pin is written for native Windows nodes, where `npx` is an npm `.cmd`\n" +
		indent + "shim: `" + launchLine(command, args) + "` is the form this client starts\n" +
		indent + "there. Regenerate with `--target-os linux` or `--target-os darwin` for other\n" +
		indent + "nodes.\n\n"
}

// tomlString renders s as a TOML basic string: `"` and `\` escaped, a
// control character as \uXXXX (or its short escape), everything else
// verbatim. For an ordinary value it matches Go's %q byte for byte.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// launchLine renders a command and its args as one space-joined line for a
// README, matching what the pin runs.
func launchLine(command string, args []string) string {
	return strings.Join(append([]string{command}, args...), " ")
}
