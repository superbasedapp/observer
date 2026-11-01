package hook

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/hookbridge"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// The fail-closed Windows hook bridge on the registration side (surface-gap
// ruling AW-37, decision D12; internal/hookbridge). For the TOOL-GATE events
// of an enforcing managed node (Options.WindowsBridgeFailClosed), a cross-OS
// Windows registrar writes
//
//	<Windows observer.exe> hook-bridge --distro <d> --bin //<bin> --tool <t> --event <e> [--config //<cfg>]
//
// instead of the `wsl.exe ... ; exit $LASTEXITCODE` bridge, so a call whose
// hook WSL cannot start BLOCKS instead of reading as a non-blocking error.
// Every other event, an unmanaged or non-enforcing node, a node without the
// installer's Windows observer.exe, and any field outside the bridge's
// closed spellings keep today's bridge, byte for byte. The whole writer is
// switched off behind live check LC6 (DEC-12): while the gate waits,
// gateBridgeCommand returns the legacy command unconditionally.
//
// SWITCH-ON PREREQUISITE (second audit of 4767d49c1, item 3): today the
// writer checks only that the Windows observer.exe EXISTS. An older
// observer.exe without `hook-bridge` exits 1 (cobra: unknown command) and a
// removed one gives 127; both are non-blocking to the host, so the gate
// would be skipped even with WSL up. Before the LC6 rows are deleted the
// writer must require a version or capability stamp of that exe (the
// installer writes none today; a stamp file the installer or the exe's own
// first run writes, or a bounded `observer.exe hook-bridge --probe` at
// registration, declared as an exec site).

// hookBridgeGateFor is the gate lookup (a var so this package's tests can
// run the switched-on branch; production clears the gate in the registry).
var hookBridgeGateFor = func(tool string) integration.LiveGates {
	return integration.RowlessWriterGates(tool, integration.WriterKindHookBridge)
}

// windowsObserverExeRel is where the edition installer puts the Windows
// observer.exe under a Windows home (scripts/install.ps1 Get-DefaultPrefix:
// %LOCALAPPDATA%\SuperBased\Observer\bin, with %LOCALAPPDATA% at its
// default AppData\Local). Another install (npm, PyPI, the VS Code bundle)
// is not looked for: the bridge is written only where its program is known.
var windowsObserverExeRel = filepath.Join("AppData", "Local", "SuperBased", "Observer", "bin", "observer.exe")

// windowsExeSpelling turns the exe's path as this daemon reaches it into the
// Windows spelling the host runs (a var for tests: their homes are not
// under /mnt).
var windowsExeSpelling = crossmount.WindowsPathFromMount

// gateBridgeCommand returns the command to write for one event of a cross-OS
// Windows target: the hook-bridge entry when every condition holds, else
// legacy (today's bridge) unchanged. base is the registry tool, winHome the
// Windows home this daemon reaches, nativeEvent the binding's event and
// argEvent the `observer hook` event argument.
func (r *Registry) gateBridgeCommand(base, winHome, distro, nativeEvent, argEvent, legacy string) string {
	if !r.opts.WindowsBridgeFailClosed || hookBridgeGateFor(base).Waiting() {
		return legacy
	}
	c, ok := integration.For(base)
	if !ok {
		return legacy
	}
	b, ok := c.Hook.Binding(nativeEvent)
	if !ok || b.Cap != integration.HookCapToolGate || !b.Wired {
		return legacy
	}
	exe := filepath.Join(winHome, windowsObserverExeRel)
	fi, err := os.Lstat(exe) //nolint:gosec // G703: an existence check of the installer's own observer.exe under the detected Windows home, never read
	if err != nil || !fi.Mode().IsRegular() {
		return legacy
	}
	win, ok := windowsExeSpelling(exe)
	if !ok {
		return legacy
	}
	entry := hookbridge.Entry{
		Distro: distro,
		Bin:    unMSYSLiteralPath(r.opts.BinaryPath),
		Tool:   base,
		Event:  argEvent,
		Config: unMSYSLiteralPath(r.opts.ConfigPath),
	}
	cmd, err := entry.Command(strings.ReplaceAll(win, `\`, "/"))
	if err != nil {
		return legacy
	}
	return cmd
}

// isHookBridgeEntry recognises a hook-bridge command written for tool.
func isHookBridgeEntry(cmd, tool string) bool {
	return strings.Contains(cmd, " hook-bridge ") && strings.Contains(cmd, " --tool "+tool+" ")
}
