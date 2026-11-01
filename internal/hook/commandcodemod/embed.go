// Package commandcodemod places SuperBased Observer's commandcode Mods SDK
// bridge (Part B item 2 phase-3a's HookCommandCodeMod mechanism) at
// `~/.commandcode/mods/observer-guard.ts` (a user-scope loose file;
// commandcode.ai/docs/mods documents `~/.commandcode/mods/*.ts`, no build
// step, jiti-compiled at load time).
//
// Since hook-parity Lane D (2026-10-03) the bridge is the ONE embedded
// plugin shim (internal/hook/pluginshim) rendered for the commandcode host:
// the Mods contract (`export default function (cmd) { cmd.hooks({...}) }`)
// with the subscribed events taken from the internal/integration
// command-code row's Registered bindings, today transformInput (the prompt
// gate, payload exactly {text}, synchronous, the command-code prompt
// dialect) and beforeToolCall (the tool gate, the plugin dialect,
// {block: true, additionalContext} on a deny). This package keeps the
// file name and the write / remove / identity helpers the registry's
// commandcode writers use.
package commandcodemod

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/hook/pluginshim"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// toolID is the registry row (and `observer hook` tool id) of commandcode.
const toolID = "command-code"

// ModFileName is the leaf filename WritePlugin writes and
// registerCommandCode/unregisterCommandCode look for.
const ModFileName = "observer-guard.ts"

// host is the commandcode row of the plugin-shim host table.
func host() pluginshim.Host {
	h, _ := pluginshim.HostFor(toolID)
	h.FileName = ModFileName
	return h
}

// shimDialects are the dialects a commandcode mod event speaks.
var shimDialects = map[string]bool{"command-code": true, "plugin-shim": true}

// Events returns the mod's subscribed events (native event -> capability),
// from the registry's command-code row.
func Events() map[string]string {
	out := map[string]string{}
	c, ok := integration.For(toolID)
	if !ok {
		return out
	}
	for _, b := range c.Hook.Bindings {
		if b.Registered && shimDialects[b.Dialect] {
			if _, seen := out[b.NativeEvent]; !seen {
				out[b.NativeEvent] = string(b.Cap)
			}
		}
	}
	return out
}

// EventsExcept is Events without the events skip reports (nil = none): the
// registration seam's Options.SkipEvent, so `observer start` never writes a
// gate that still owes a live test (cmd/observer autoRegisterOwesLive) into
// the one mod file every subscribed event shares.
func EventsExcept(skip func(event string) bool) map[string]string {
	out := Events()
	if skip == nil {
		return out
	}
	for e := range out {
		if skip(e) {
			delete(out, e)
		}
	}
	return out
}

// NamesOf returns the keys of an event map, sorted.
func NamesOf(events map[string]string) []string {
	out := make([]string, 0, len(events))
	for k := range events {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ShellGateRegistered reports whether the registry's command-code row
// registers a shell-hook PreToolUse binding (the ~/.commandcode/settings.json
// gate). Since hook-parity Lane D the mod's beforeToolCall is the tool gate
// of record and the shell row is dialect-only, so the shell gate is not
// written.
func ShellGateRegistered() bool {
	c, ok := integration.For(toolID)
	if !ok {
		return false
	}
	for _, b := range c.Hook.Bindings {
		if b.Registered && b.NativeEvent == "PreToolUse" {
			return true
		}
	}
	return false
}

// EventNames returns Events' keys, sorted.
func EventNames() []string {
	ev := Events()
	out := make([]string, 0, len(ev))
	for k := range ev {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// WritePlugin renders the shim for a native install into destDir.
// defaultObserverBin is baked in (empty = the bare "observer" PATH lookup;
// OBSERVER_BIN still wins at run time), configPath becomes the hook
// invocation's --config, and observerDir (the directory holding the global
// config; empty = none) locates guard-posture.json and guard-hookfail.jsonl
// for the shim's failure rule. Re-running overwrites (the upgrade path).
func WritePlugin(destDir, defaultObserverBin, configPath, observerDir string) error {
	return WritePluginEvents(destDir, defaultObserverBin, configPath, observerDir, Events())
}

// WritePluginEvents is WritePlugin subscribing exactly events (a subset of
// Events, e.g. EventsExcept's result).
func WritePluginEvents(destDir, defaultObserverBin, configPath, observerDir string, events map[string]string) error {
	_, err := pluginshim.Write(destDir, host(), nativeOptions(defaultObserverBin, configPath, observerDir, events))
	return err
}

// RenderPluginEvents returns the exact bytes WritePluginEvents writes, so a
// registrar can tell a current mod from a stale or hand-edited one (T-847:
// byte-exact currency, as the plugin-shim writer already does).
func RenderPluginEvents(defaultObserverBin, configPath, observerDir string, events map[string]string) ([]byte, error) {
	return pluginshim.Render(host(), nativeOptions(defaultObserverBin, configPath, observerDir, events))
}

// nativeOptions is the one builder of a native install's render options.
func nativeOptions(defaultObserverBin, configPath, observerDir string, events map[string]string) pluginshim.RenderOptions {
	o := pluginshim.RenderOptions{Events: events, Bin: defaultObserverBin, Config: configPath, PostureSchema: postureSchema}
	if observerDir != "" {
		o.PosturePath = filepath.Join(observerDir, postureFile)
		o.SpoolPath = filepath.Join(observerDir, spoolFile)
	}
	return o
}

// WritePluginBridge renders the shim for the command-code-windows cross-OS
// bridge (internal/hook register_crossos.go): on win32 it runs
// `wsl.exe -d <distro> -- <wslBin> hook ...`, so the hook executes inside the
// WSL daemon's OS context. The Windows-side Node process cannot read the
// daemon's posture file, so a bridge install relies on observer's own
// answer (its watchdog fails closed under enforcement) and fails open only
// when wsl.exe itself cannot run.
func WritePluginBridge(destDir, wslBin, distro, configPath string) error {
	return WritePluginBridgeEvents(destDir, wslBin, distro, configPath, Events())
}

// WritePluginBridgeEvents is WritePluginBridge subscribing exactly events.
func WritePluginBridgeEvents(destDir, wslBin, distro, configPath string, events map[string]string) error {
	_, err := pluginshim.Write(destDir, host(), bridgeOptions(wslBin, distro, configPath, events))
	return err
}

// RenderPluginBridgeEvents returns the exact bytes WritePluginBridgeEvents
// writes (see RenderPluginEvents).
func RenderPluginBridgeEvents(wslBin, distro, configPath string, events map[string]string) ([]byte, error) {
	return pluginshim.Render(host(), bridgeOptions(wslBin, distro, configPath, events))
}

// bridgeOptions is the one builder of a bridge install's render options.
func bridgeOptions(wslBin, distro, configPath string, events map[string]string) pluginshim.RenderOptions {
	return pluginshim.RenderOptions{
		Events: events, Bin: "observer", Config: configPath, WSLBin: wslBin, WSLDistro: distro,
	}
}

// RemovePlugin removes the observer-owned mod file from destDir, if
// present. Never errors on an already-absent file; a file there that is not
// an observer-written mod is kept (pluginshim.ErrNotObserverShim, FU-212).
func RemovePlugin(destDir string) error {
	return pluginshim.Remove(destDir, host())
}

// Installed reports whether destDir already carries the observer mod file.
func Installed(destDir string) bool {
	_, err := os.Stat(filepath.Join(destDir, ModFileName))
	return err == nil
}

// LooksLikeObserverPlugin reports whether data is (or was) an
// observer-written mod: the current shim or the pre-shim prompt bridge.
func LooksLikeObserverPlugin(data []byte) bool {
	return pluginshim.LooksLikeObserverShim(data)
}

// Posture / spool basenames and schema (internal/guardposture's, spelled
// here so this package stays free of the posture package's file I/O).
const (
	postureFile   = "guard-posture.json"
	spoolFile     = "guard-hookfail.jsonl"
	postureSchema = 1
)
