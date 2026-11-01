package hook

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/psparse"
)

// FU-162: Codex on Windows starts every hook command as `powershell.exe
// -NoProfile -Command "<command>"` (Windows rig run A8), so every Codex hook
// command Observer writes for Windows must parse in PowerShell as the one
// observer invocation it means. psparse.Parse is the strict reader; the live
// probe (PowerShell 5.1, 2026-10-29) is in the lane report.

// codexWindowsHomes are Windows homes with a space, and with the characters
// PowerShell reads specially that a Windows file name may hold: ', $, ;, &,
// (, ), %, and a backtick.
var codexWindowsHomes = []string{
	`C:\Users\First Last`,
	`C:\Users\O'Brien $x;y&z(1) 100% a` + "`" + `b`,
}

// wantCodexArgv is the observer invocation a Codex hook command must run.
func wantCodexArgv(bin, event, cfg string) []string {
	return []string{bin, "hook", "codex", event, "--config", cfg}
}

// TestCodexNativeWindowsCommandsParseInPowerShell renders the native codex
// target for an observer.exe and config under a Windows home with a space
// (and with PowerShell-special characters) and checks each event's command
// is one PowerShell command running that binary with the right arguments.
func TestCodexNativeWindowsCommandsParseInPowerShell(t *testing.T) {
	t.Parallel()
	for _, winHome := range codexWindowsHomes {
		bin := winHome + `\AppData\Local\SuperBased\Observer\bin\observer.exe`
		cfg := winHome + `\.observer\config.toml`
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
			t.Fatal(err)
		}
		r, err := NewRegistry(Options{
			BinaryPath: bin, ConfigPath: cfg, HomeDir: home,
			ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		})
		if err != nil {
			t.Fatal(err)
		}
		mustRegister(t, r, "codex")
		cmds := readCodexHookCommands(t, filepath.Join(home, ".codex", codexHooksFile))
		if len(cmds) != len(codexEvents) {
			t.Fatalf("%s: %d events written, want %d", winHome, len(cmds), len(codexEvents))
		}
		for _, ev := range codexEvents {
			got := cmds[ev]
			if len(got) != 1 {
				t.Fatalf("%s %s: %q, want one command", winHome, ev, got)
			}
			argv, err := psparse.Parse(got[0])
			if err != nil || !reflect.DeepEqual(argv, wantCodexArgv(bin, ev, cfg)) {
				t.Errorf("%s %s: %q parses in PowerShell as %q, %v; want %q", winHome, ev, got[0], argv, err, wantCodexArgv(bin, ev, cfg))
			}
			if !strings.HasPrefix(got[0], "& '") {
				t.Errorf("%s %s: %q, want the call operator before the quoted binary", winHome, ev, got[0])
			}
			// The registrar and the doctor still own the entry.
			if !IsObserverCodexHookCommand(got[0]) || !isObserverCodexEntryNative(got[0]) || !IsObserverHookCommand(got[0]) {
				t.Errorf("%s %s: %q is no longer recognised as Observer's", winHome, ev, got[0])
			}
		}
		if again := mustRegister(t, r, "codex"); len(again.HooksAdded) != 0 {
			t.Errorf("%s: re-register rewrote %v", winHome, again.HooksAdded)
		}
	}
	// The binaries the trust and stale checks read back.
	cmd := `& 'C:\Users\First Last\AppData\Local\SuperBased\Observer\bin\observer.exe' hook codex PreToolUse`
	if got := ObserverHookCommandBinaries(cmd); len(got) == 0 || got[0] != `C:\Users\First Last\AppData\Local\SuperBased\Observer\bin\observer.exe` {
		t.Errorf("ObserverHookCommandBinaries(%q) = %q", cmd, got)
	}
}

// TestCodexNativeWindowsPlainPathIsBare: a Windows path PowerShell reads
// literally is written bare, byte for byte as before (both cmd.exe and
// PowerShell run it).
func TestCodexNativeWindowsPlainPathIsBare(t *testing.T) {
	t.Parallel()
	for _, p := range []string{`D:\programsx\observer.exe`, `C:\Users\a%b\observer.exe`} {
		if got := codexHookExe(p); got != p {
			t.Errorf("codexHookExe(%q) = %q, want it bare", p, got)
		}
	}
	if got := codexHookExe("/usr/local/bin/my observer"); got != "'/usr/local/bin/my observer'" {
		t.Errorf("a POSIX path keeps POSIX quoting, got %q", got)
	}
}

// codexWindowsHomeAt makes a Windows home with the given user name under a
// fresh WSL sandbox home, with an empty .codex.
func codexWindowsHomeAt(t *testing.T, user string) (wslHome, winHome string) {
	t.Helper()
	wslHome = t.TempDir()
	winHome = filepath.Join(wslHome, "mnt", "c", "Users", user)
	if err := os.MkdirAll(filepath.Join(winHome, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	return wslHome, winHome
}

// TestCodexWindowsBridgeCommandsParseInPowerShell renders the codex-windows
// target (a WSL daemon writing the Windows-side .codex) for a Windows home
// with a space: the home only places hooks.json, and every command is one
// PowerShell command running wsl.exe with the Linux invocation after `--`
// (the shape the Windows rig ran live, A2 and A8). A Linux binary with a
// space is double-quoted, which survived PowerShell and the distro's shell
// in the live probe.
func TestCodexWindowsBridgeCommandsParseInPowerShell(t *testing.T) {
	t.Parallel()
	for _, bin := range []string{"/home/u/.local/bin/observer", "/home/u/my tools/observer"} {
		cfg := "/home/u/.observer/config.toml"
		wslHome, winHome := codexWindowsHomeAt(t, "First Last")
		r, err := NewRegistry(Options{
			BinaryPath: bin, ConfigPath: cfg, HomeDir: wslHome,
			ChecksumsPath:    filepath.Join(wslHome, ".observer", "hook_checksums.json"),
			WindowsCodexHome: winHome, WSLDistro: "Ubuntu-20.04",
		})
		if err != nil {
			t.Fatal(err)
		}
		mustRegister(t, r, "codex-windows")
		cmds := readCodexHookCommands(t, filepath.Join(winHome, ".codex", codexHooksFile))
		for _, ev := range codexEvents {
			got := cmds[ev]
			want := append([]string{"wsl.exe", "-d", "Ubuntu-20.04", "--"}, wantCodexArgv(bin, ev, cfg)...)
			if len(got) != 1 {
				t.Fatalf("%s: %q", ev, got)
			}
			if argv, err := psparse.Parse(got[0]); err != nil || !reflect.DeepEqual(argv, want) {
				t.Errorf("%s %s: %q parses as %q, %v; want %q", bin, ev, got[0], argv, err, want)
			}
		}
	}
}

// TestCodexWindowsBridgeRefusesPathsItCannotCarry: a codex-windows binary,
// config or distro holding a character PowerShell or the Linux shell behind
// `wsl.exe --` re-reads is refused at registration (each failed the live
// probe), instead of writing a hook that fails, and so allows, every call.
func TestCodexWindowsBridgeRefusesPathsItCannotCarry(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"/home/u/a$b/observer", "/home/u/a`b/observer", "/home/u/a'b/observer", "/home/u/a;b/observer", "/home/u/a&b/observer", "/home/u/a(b)/observer"} {
		wslHome, winHome := codexWindowsHomeAt(t, "First Last")
		r, err := NewRegistry(Options{
			BinaryPath: bad, HomeDir: wslHome,
			ChecksumsPath:    filepath.Join(wslHome, ".observer", "hook_checksums.json"),
			WindowsCodexHome: winHome, WSLDistro: "Ubuntu-20.04",
		})
		if err != nil {
			t.Fatal(err)
		}
		res := r.Register("codex-windows")
		if res.Error == nil || !strings.Contains(res.Error.Error(), "PowerShell") {
			t.Errorf("%s: Register error %v, want the PowerShell refusal", bad, res.Error)
		}
		if _, err := os.Stat(filepath.Join(winHome, ".codex", codexHooksFile)); err == nil {
			t.Errorf("%s: hooks.json written despite the refusal", bad)
		}
	}
}

// TestCodexHookBridgeCommandParsesInPowerShell renders the AW-37 hook-bridge
// form for codex (gate open, the installer's observer.exe present): the
// PreToolUse entry is one PowerShell command; for a Windows home with a
// space the exe path is not a closed spelling, so today's wsl.exe bridge is
// written instead, which parses too.
func TestCodexHookBridgeCommandParsesInPowerShell(t *testing.T) {
	for _, tc := range []struct {
		user, spelling string
		wantBridge     bool
	}{
		{"tester", "C:/Users/tester/AppData/Local/SuperBased/Observer/bin/observer.exe", true},
		{"First Last", "C:/Users/First Last/AppData/Local/SuperBased/Observer/bin/observer.exe", false},
	} {
		wslHome, winHome := codexWindowsHomeAt(t, tc.user)
		stubHookBridge(t, true, winHome, true, tc.spelling)
		r, err := NewRegistry(Options{
			BinaryPath: apBin, ConfigPath: apCfg, HomeDir: wslHome,
			ChecksumsPath:    filepath.Join(wslHome, ".observer", "hook_checksums.json"),
			WindowsCodexHome: winHome, WSLDistro: apDistro, WindowsBridgeFailClosed: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		mustRegister(t, r, "codex-windows")
		got := readCodexHookCommands(t, filepath.Join(winHome, ".codex", codexHooksFile))["PreToolUse"]
		if len(got) != 1 {
			t.Fatalf("%s: %q", tc.user, got)
		}
		argv, err := psparse.Parse(got[0])
		if err != nil {
			t.Fatalf("%s: %q does not parse in PowerShell: %v", tc.user, got[0], err)
		}
		want := append([]string{"wsl.exe", "-d", apDistro, "--"}, wantCodexArgv(apBin, "PreToolUse", apCfg)...)
		if tc.wantBridge {
			want = []string{tc.spelling, "hook-bridge", "--distro", apDistro, "--bin", "/" + apBin, "--tool", "codex", "--event", "PreToolUse", "--config", "/" + apCfg}
		}
		if !reflect.DeepEqual(argv, want) {
			t.Errorf("%s: %q parses as %q, want %q", tc.user, got[0], argv, want)
		}
	}
}
