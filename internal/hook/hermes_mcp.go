package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// HermesMCPServerName is the key we write under config.yaml's
// `mcp_servers` block: the one name every Observer MCP writer uses
// (models.ObserverMCPServerName), so Hermes carries the same server name
// as every other client (surface-gap FU-2).
const HermesMCPServerName = models.ObserverMCPServerName

// HermesLegacyMCPServerName is the key builds before FU-2 wrote the Hermes
// MCP entry under. Register and unregister remove an entry under it, but
// only when that entry is Observer's own (hermesObserverMCPEntry); a
// server the user named this way themselves is left alone.
const HermesLegacyMCPServerName = "superbased-observer"

// hermesObserverMCPEntry reports whether an mcp_servers value is the entry
// an Observer Hermes writer wrote: a mapping whose command names an
// observer binary (IsObserverBinary) and whose args are `serve` or
// `serve --config <path>`, and nothing else that would make it a
// different server (no url).
func hermesObserverMCPEntry(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	if _, remote := m["url"]; remote {
		return false
	}
	cmd, _ := m["command"].(string)
	if cmd == "" || !IsObserverBinary(cmd) {
		return false
	}
	raw, _ := m["args"].([]any)
	args := make([]string, 0, len(raw))
	for _, a := range raw {
		s, ok := a.(string)
		if !ok {
			return false
		}
		args = append(args, s)
	}
	switch len(args) {
	case 1:
		return args[0] == "serve"
	case 3:
		return args[0] == "serve" && args[1] == "--config"
	}
	return false
}

// dropLegacyHermesMCPEntry removes the pre-FU-2 `superbased-observer` entry
// from mcpServers when Observer wrote it, reporting whether it did.
func dropLegacyHermesMCPEntry(mcpServers map[string]any) bool {
	v, ok := mcpServers[HermesLegacyMCPServerName]
	if !ok || !hermesObserverMCPEntry(v) {
		return false
	}
	delete(mcpServers, HermesLegacyMCPServerName)
	return true
}

// RegisterHermesPluginEnabled adds the superbased-observer plugin
// name to the `plugins.enabled` allow-list in
// <hermes-home>/config.yaml. Hermes's plugin loader auto-discovers
// plugin directories on startup BUT honours an explicit allow-list
// when present: a plugin not listed is skipped with
// "Skipping '<name>' (not in plugins.enabled)" in the plugin debug
// log.
//
// Validation 2026-06-06 caught this — without the enabled-list
// entry, the dropped plugin files at ~/.hermes/plugins/superbased-
// observer/ are parsed but never loaded, so no hooks fire and the
// real-time capture path silently does nothing.
//
// Safe against pre-existing `plugins:` blocks: merges into the
// existing list, no-op when the entry is already present. Creates
// the `plugins:` and `plugins.enabled:` keys when absent.
func RegisterHermesPluginEnabled(opts HermesOptions) (string, error) {
	path, err := registerHermesPluginEnabled(opts)
	if hooksShareCredentialFile("hermes") {
		err = credentialSafeError("hermes", path, err)
	}
	return path, err
}

// registerHermesPluginEnabled is RegisterHermesPluginEnabled's body.
func registerHermesPluginEnabled(opts HermesOptions) (string, error) {
	configPath, err := hermesConfigPath(opts)
	if err != nil {
		return "", err
	}
	doc, err := readYAMLMap(configPath)
	if err != nil {
		return configPath, fmt.Errorf("hook.RegisterHermesPluginEnabled: read: %w", err)
	}
	plugins, _ := doc["plugins"].(map[string]any)
	if plugins == nil {
		plugins = map[string]any{}
	}
	enabledRaw, _ := plugins["enabled"].([]any)
	enabled := append([]any(nil), enabledRaw...)
	for _, v := range enabled {
		if s, ok := v.(string); ok && s == HermesPluginDirName {
			// Already enabled — nothing to do.
			return configPath, nil
		}
	}
	enabled = append(enabled, HermesPluginDirName)
	plugins["enabled"] = enabled
	doc["plugins"] = plugins

	if opts.DryRun {
		return configPath, nil
	}
	if err := writeHermesPluginsYAML(configPath, doc); err != nil {
		return configPath, fmt.Errorf("hook.RegisterHermesPluginEnabled: write: %w", err)
	}
	return configPath, nil
}

// UnregisterHermesPluginEnabled removes the superbased-observer
// entry from `plugins.enabled` in config.yaml. Safe against absent
// blocks or already-clean state. Removes the `enabled` key when it
// would otherwise be empty; removes the `plugins` key when IT would
// otherwise be empty.
func UnregisterHermesPluginEnabled(opts HermesOptions) (string, error) {
	path, err := unregisterHermesPluginEnabled(opts)
	if hooksShareCredentialFile("hermes") {
		err = credentialSafeError("hermes", path, err)
	}
	return path, err
}

// unregisterHermesPluginEnabled is UnregisterHermesPluginEnabled's body.
func unregisterHermesPluginEnabled(opts HermesOptions) (string, error) {
	configPath, err := hermesConfigPath(opts)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return configPath, nil
	} else if err != nil {
		return configPath, fmt.Errorf("hook.UnregisterHermesPluginEnabled: stat: %w", err)
	}
	doc, err := readYAMLMap(configPath)
	if err != nil {
		return configPath, fmt.Errorf("hook.UnregisterHermesPluginEnabled: read: %w", err)
	}
	plugins, _ := doc["plugins"].(map[string]any)
	if plugins == nil {
		return configPath, nil
	}
	enabledRaw, _ := plugins["enabled"].([]any)
	out := enabledRaw[:0]
	found := false
	for _, v := range enabledRaw {
		if s, ok := v.(string); ok && s == HermesPluginDirName {
			found = true
			continue
		}
		out = append(out, v)
	}
	if !found {
		return configPath, nil
	}
	if len(out) == 0 {
		delete(plugins, "enabled")
	} else {
		plugins["enabled"] = out
	}
	if len(plugins) == 0 {
		delete(doc, "plugins")
	} else {
		doc["plugins"] = plugins
	}
	if opts.DryRun {
		return configPath, nil
	}
	if err := writeHermesPluginsYAML(configPath, doc); err != nil {
		return configPath, fmt.Errorf("hook.UnregisterHermesPluginEnabled: write: %w", err)
	}
	return configPath, nil
}

// RegisterHermesMCP merges the SuperBased Observer MCP entry into
// `<hermes-home>/config.yaml` under the `mcp_servers` key. The merge
// is point-mutating — we read the file, set / overwrite the one
// `mcp_servers.observer` entry (HermesMCPServerName), drop the legacy
// `mcp_servers.superbased-observer` entry when Observer wrote it, and
// write back. Other
// top-level keys (inference, plugins, gateway, …) and other
// mcp_servers.* siblings are preserved verbatim.
//
// config.yaml holds provider keys, so the write edits only the
// mcp_servers node (writeHermesMCPYAML, the credential-file rules):
// comments, key order and every other value survive, and no backup copy
// of the file is made (review T-384).
//
// Returns the path of the config file written and any error.
func RegisterHermesMCP(opts HermesOptions) (string, error) {
	path, err := registerHermesMCP(opts)
	return path, credentialSafeError("hermes MCP", path, err)
}

// registerHermesMCP is RegisterHermesMCP's body.
func registerHermesMCP(opts HermesOptions) (string, error) {
	configPath, err := hermesConfigPath(opts)
	if err != nil {
		return "", err
	}

	doc, err := readYAMLMap(configPath)
	if err != nil {
		return configPath, fmt.Errorf("hook.RegisterHermesMCP: read: %w", err)
	}

	entry := map[string]any{
		"command": "observer",
		"args":    []any{"serve"},
	}
	if opts.BinaryPath != "" {
		entry["command"] = opts.BinaryPath
	}

	mcpServers, _ := doc["mcp_servers"].(map[string]any)
	if mcpServers == nil {
		mcpServers = map[string]any{}
	}
	dropLegacyHermesMCPEntry(mcpServers)
	mcpServers[HermesMCPServerName] = entry
	doc["mcp_servers"] = mcpServers

	if opts.DryRun {
		return configPath, nil
	}
	if err := writeHermesMCPYAML(configPath, doc); err != nil {
		return configPath, fmt.Errorf("hook.RegisterHermesMCP: write: %w", err)
	}
	return configPath, nil
}

// UnregisterHermesMCP removes the SuperBased Observer entry from
// config.yaml's mcp_servers block: `observer` (HermesMCPServerName) and the
// legacy `superbased-observer` (HermesLegacyMCPServerName), each only when
// it is Observer's own entry (hermesObserverMCPEntry), so a server the user
// gave either name survives. Safe against an absent file or an
// already-clean configuration (returns nil + the path that would
// have been written).
//
// Other mcp_servers.* siblings are left untouched; the `mcp_servers`
// key is removed entirely only when it would otherwise be empty.
func UnregisterHermesMCP(opts HermesOptions) (string, error) {
	path, err := unregisterHermesMCP(opts)
	return path, credentialSafeError("hermes MCP", path, err)
}

// unregisterHermesMCP is UnregisterHermesMCP's body.
func unregisterHermesMCP(opts HermesOptions) (string, error) {
	configPath, err := hermesConfigPath(opts)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return configPath, nil
	} else if err != nil {
		return configPath, fmt.Errorf("hook.UnregisterHermesMCP: stat: %w", err)
	}

	doc, err := readYAMLMap(configPath)
	if err != nil {
		return configPath, fmt.Errorf("hook.UnregisterHermesMCP: read: %w", err)
	}

	mcpServers, _ := doc["mcp_servers"].(map[string]any)
	if mcpServers == nil {
		return configPath, nil
	}
	removed := dropLegacyHermesMCPEntry(mcpServers)
	if v, exists := mcpServers[HermesMCPServerName]; exists && hermesObserverMCPEntry(v) {
		delete(mcpServers, HermesMCPServerName)
		removed = true
	}
	if !removed {
		return configPath, nil
	}
	if len(mcpServers) == 0 {
		delete(doc, "mcp_servers")
	} else {
		doc["mcp_servers"] = mcpServers
	}

	if opts.DryRun {
		return configPath, nil
	}
	if err := writeHermesMCPYAML(configPath, doc); err != nil {
		return configPath, fmt.Errorf("hook.UnregisterHermesMCP: write: %w", err)
	}
	return configPath, nil
}

// hermesConfigPath returns the full path to <hermes-home>/config.yaml.
func hermesConfigPath(opts HermesOptions) (string, error) {
	home, err := resolveHermesHome(opts)
	if err != nil {
		return "", err
	}
	return filepath.Join(home, HermesConfigFile), nil
}

// readYAMLMap reads path as a YAML mapping. Returns an empty map when
// the file is absent so callers can unconditionally mutate-and-write.
// An empty file yields an empty map too.
func readYAMLMap(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("readYAMLMap: %w", err)
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

// hermesConfigBackedUp tracks (by absolute path) which config.yaml files
// this process has already backed up. RegisterHermesPluginEnabled and
// RegisterHermesMCP (and their Unregister counterparts) round-trip the SAME
// file through writeYAMLMap when both run in one `observer init --hermes`
// invocation; without this guard the second call's backup would clobber
// the first with the already-rewritten (post-first-call) content instead
// of preserving the pre-invocation original.
var hermesConfigBackedUp sync.Map

// backupYAMLConfig writes a `.bak` copy of path — mirroring the discipline
// in cmd/observer/hermes.go's ensureHermesObserverProvider — the FIRST time
// this process touches it, preserving the original file's permission bits
// on the copy. Subsequent calls for the same path within this process
// no-op, so a multi-write invocation backs up the pre-invocation original
// exactly once rather than an intermediate state.
//
// Returns the original file's permission bits (0 when the file doesn't
// exist yet, i.e. a fresh install with nothing to back up or preserve).
func backupYAMLConfig(path string) (os.FileMode, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("backupYAMLConfig: stat: %w", err)
	}
	mode := info.Mode().Perm()
	if _, alreadyBackedUp := hermesConfigBackedUp.LoadOrStore(path, struct{}{}); alreadyBackedUp {
		return mode, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return mode, fmt.Errorf("backupYAMLConfig: read: %w", err)
	}
	if err := os.WriteFile(path+".bak", data, mode); err != nil { //nolint:gosec // G703: the operator's own hermes config path
		return mode, fmt.Errorf("backupYAMLConfig: write backup: %w", err)
	}
	return mode, nil
}

// writeYAMLMap writes m back to path with 2-space indent (Hermes
// convention), preserving the original file's permission bits (0o600 for a
// fresh install that has none to preserve). Creates the parent directory
// if missing.
//
// Backs up the pre-existing file to path+".bak" first via
// backupYAMLConfig: yaml.v3's map round-trip loses comments and key order
// (see the RegisterHermesMCP doc comment above), and an unbacked-up
// rewrite destroyed ~750 comment lines of a real operator's config once
// (2026-06-26).
func writeYAMLMap(path string, m map[string]any) error {
	if err := testwriteguard.Check("write", path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	mode, err := backupYAMLConfig(path)
	if err != nil {
		return err
	}
	if mode == 0 {
		mode = 0o600
	}
	out, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, mode)
}

// writeHermesPluginsYAML is the plugins.enabled write. Hermes keeps that
// list in config.yaml beside provider keys, so under the D-268
// credential-file exception only the top-level "plugins" node is edited
// (writeCredentialYAMLKey: comments and every other key kept, mode kept, no
// backup); without the exception it is writeYAMLMap.
func writeHermesPluginsYAML(path string, doc map[string]any) error {
	if !hooksShareCredentialFile("hermes") {
		return writeYAMLMap(path, doc)
	}
	return writeCredentialYAMLKey(pinWriteTarget(path), "plugins", doc)
}

// writeHermesMCPYAML is the mcp_servers write. config.yaml holds provider
// keys, so the MCP writer follows the same credential-file rules as the
// plugins write (review T-384): only a row declaring the file
// (integration.MCPTarget.SharesCredentialFile) may write it, only the
// top-level "mcp_servers" node changes (comments, key order and every
// other value kept), the mode is kept, and no backup copy of the file is
// made.
func writeHermesMCPYAML(path string, doc map[string]any) error {
	if !integration.MCPSharesCredentialFile("hermes") {
		return safeErrorf("hook.RegisterHermesMCP: the registry row does not declare %s for MCP; nothing was written", path)
	}
	return writeCredentialYAMLKey(pinWriteTarget(path), "mcp_servers", doc)
}
