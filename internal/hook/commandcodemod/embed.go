// Package commandcodemod embeds the SuperBased Observer prompt-submit
// guard bridge for commandcode's Mods SDK and exposes a single
// WritePlugin helper that drops it into the mods directory at install
// time — the SAME embed-and-substitute pattern
// internal/hook/hermesplugin uses for Hermes' Python plugin bridge
// (Part B item 2, phase-3a,
// docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
// §6.7's HookCommandCodeMod mechanism).
//
// `observer init`/the registry's registerCommandCode writer invokes
// WritePlugin against `~/.commandcode/mods/observer-guard.ts` (a
// user-scope loose file — commandcode.ai/docs/mods documents
// `~/.commandcode/mods/*.ts` as one of the discovery locations, no
// build step, jiti-compiled at load time).
//
// One file ships: observer-guard.ts — the TypeScript bridge that
// shells out to `observer hook command-code transformInput` on every
// user-typed prompt, mirroring every other prompt-submit dialect's
// argv shape.
package commandcodemod

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed observer-guard.ts
var pluginFS embed.FS

// ModFileName is the leaf filename WritePlugin writes and
// registerCommandCode/unregisterCommandCode look for.
const ModFileName = "observer-guard.ts"

// observerBinPlaceholder mirrors internal/hook/hermesplugin's
// placeholder convention exactly — substituted with the resolved
// observer binary path at install time.
const observerBinPlaceholder = "{{OBSERVER_BIN_DEFAULT}}"

// observerConfigPlaceholder is substituted with the operator's
// Options.ConfigPath (the `--config <path>` flag), when set, so a
// custom config path survives into the registered hook invocation —
// the same job every other writer's configFlagSuffix family does for
// a shell-command target. Empty when no custom config path was given.
const observerConfigPlaceholder = "{{OBSERVER_CONFIG_DEFAULT}}"

// observerPluginMarker is a string unique to this repo's own
// observer-guard.ts template (the file header, never substituted or
// stripped) — used by LooksLikeObserverPlugin to tell an
// observer-written copy of the mod apart from an unrelated file a
// user or another tool happens to have placed at the same path.
const observerPluginMarker = "SuperBased Observer prompt-submit guard bridge"

// observerWSLBinPlaceholder / wslDistroPlaceholder are the
// command-code-windows cross-OS bridge's own placeholders — see
// WritePluginBridge. WritePlugin (the native writer) blanks both so a
// native install's resolveExec() never mistakes a leftover
// "{{...}}" literal for a real (truthy) bridge target.
const (
	observerWSLBinPlaceholder = "{{OBSERVER_WSL_BIN}}"
	wslDistroPlaceholder      = "{{WSL_DISTRO}}"
)

// WritePlugin writes the embedded observer-guard.ts into destDir
// (expected to be `~/.commandcode/mods/`), creating the directory if
// it doesn't exist. defaultObserverBin gets baked into the
// OBSERVER_BIN_DEFAULT constant at write time — pass the running
// observer's resolved absolute path. An empty string falls back to
// the bare "observer" PATH-lookup default (tests only; the module
// still honours a runtime OBSERVER_BIN env override regardless).
// configPath, when non-empty, is baked into the OBSERVER_CONFIG_DEFAULT
// constant so the registered hook invocation carries the operator's
// `--config <path>` the same way every other writer's hook command
// does; an empty configPath leaves the mod's default at "" (the
// runtime OBSERVER_CONFIG env override still works regardless).
//
// Re-running WritePlugin against an existing install is idempotent:
// the existing file is overwritten with whatever the embedded copy
// holds — the same upgrade-on-reinit contract as hermesplugin.
func WritePlugin(destDir, defaultObserverBin, configPath string) error {
	if defaultObserverBin == "" {
		defaultObserverBin = "observer"
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("commandcodemod.WritePlugin: mkdir %s: %w", destDir, err)
	}
	data, err := pluginFS.ReadFile(ModFileName)
	if err != nil {
		return fmt.Errorf("commandcodemod.WritePlugin: read embedded %s: %w", ModFileName, err)
	}
	data = bytes.Replace(data, []byte(observerBinPlaceholder), []byte(escapeTSStringContents(defaultObserverBin)), 1)
	data = bytes.Replace(data, []byte(observerConfigPlaceholder), []byte(escapeTSStringContents(configPath)), 1)
	// Native install: never a cross-OS bridge target. Blank these two so
	// resolveExec()'s win32+OBSERVER_WSL_BIN gate stays false — see
	// WritePluginBridge for the counterpart that fills them in.
	data = bytes.Replace(data, []byte(observerWSLBinPlaceholder), nil, 1)
	data = bytes.Replace(data, []byte(wslDistroPlaceholder), nil, 1)
	if err := os.WriteFile(filepath.Join(destDir, ModFileName), data, 0o600); err != nil {
		return fmt.Errorf("commandcodemod.WritePlugin: write %s: %w", ModFileName, err)
	}
	return nil
}

// WritePluginBridge writes the embedded observer-guard.ts configured for
// the command-code-windows cross-OS bridge target
// (internal/hook/register.go::registerCommandCodeWindows): the mod's own
// OBSERVER_WSL_BIN/WSL_DISTRO constants are baked in so its runtime
// resolveExec() shells out through wsl.exe when it detects it is
// running on win32, instead of exec'ing a Windows-side observer binary
// directly. destDir is expected to be the WINDOWS-side
// `<winhome>/.commandcode/mods/` (reached via crossmount, e.g.
// /mnt/c/Users/<u>/.commandcode/mods). wslBin is the Linux-side observer
// binary path the wsl.exe bridge invokes (e.g.
// /home/u/superbased-observer/bin/observer — the SAME BinaryPath every
// other *-windows registrar in this package expects); distro is the WSL
// distribution name (`wsl.exe -d <distro>`).
//
// The native OBSERVER_BIN_DEFAULT constant is still filled in (as the
// bare "observer" PATH-lookup fallback) rather than left blank: it is a
// documented, harmless fallback path resolveExec() only reaches when
// OBSERVER_WSL_BIN is unset or the mod somehow runs off win32 — a shape
// that should never occur for a bridge install, but a real fallback
// value is safer than an empty string there.
// configPath, when non-empty, is baked into the OBSERVER_CONFIG_DEFAULT
// constant exactly like WritePlugin's own configPath parameter — the
// SAME Options.ConfigPath the daemon-side wsl.exe bridge target needs
// (a Linux-side path, since the daemon and its --config both live in
// the WSL distro the bridge shells out to).
func WritePluginBridge(destDir, wslBin, distro, configPath string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("commandcodemod.WritePluginBridge: mkdir %s: %w", destDir, err)
	}
	data, err := pluginFS.ReadFile(ModFileName)
	if err != nil {
		return fmt.Errorf("commandcodemod.WritePluginBridge: read embedded %s: %w", ModFileName, err)
	}
	data = bytes.Replace(data, []byte(observerBinPlaceholder), []byte("observer"), 1)
	data = bytes.Replace(data, []byte(observerConfigPlaceholder), []byte(escapeTSStringContents(configPath)), 1)
	data = bytes.Replace(data, []byte(observerWSLBinPlaceholder), []byte(escapeTSStringContents(wslBin)), 1)
	data = bytes.Replace(data, []byte(wslDistroPlaceholder), []byte(escapeTSStringContents(distro)), 1)
	if err := os.WriteFile(filepath.Join(destDir, ModFileName), data, 0o600); err != nil {
		return fmt.Errorf("commandcodemod.WritePluginBridge: write %s: %w", ModFileName, err)
	}
	return nil
}

// RemovePlugin removes the observer-owned mod file from destDir, if
// present. Never errors on an already-absent file (matches every
// other unregister writer's idempotent-removal contract).
func RemovePlugin(destDir string) error {
	err := os.Remove(filepath.Join(destDir, ModFileName))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("commandcodemod.RemovePlugin: %w", err)
	}
	return nil
}

// Installed reports whether destDir already carries the observer mod
// file — used by registerCommandCode's idempotent-register check.
func Installed(destDir string) bool {
	_, err := os.Stat(filepath.Join(destDir, ModFileName))
	return err == nil
}

// LooksLikeObserverPlugin reports whether data is (or was) an
// observer-written observer-guard.ts, by checking for the file
// header's marker text — never substituted or stripped by either
// WritePlugin or WritePluginBridge, so it survives regardless of
// which placeholders got filled in. Used by registerCommandCode's
// conflict guard to tell an observer-owned copy (safe to silently
// overwrite/refresh on reinit) apart from an unrelated file a user or
// another tool happens to have placed at the same path (refused
// without --force, like every other writer's foreign-entry guard).
func LooksLikeObserverPlugin(data []byte) bool {
	return bytes.Contains(data, []byte(observerPluginMarker))
}

// escapeTSStringContents returns s with the characters that would
// terminate or alter the TS double-quoted string literal it gets
// substituted into escaped — the same discipline as hermesplugin's
// escapePythonStringContents, adapted for TS/JS string literal rules
// (identical escape set for backslash/quote/newline/tab).
func escapeTSStringContents(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
