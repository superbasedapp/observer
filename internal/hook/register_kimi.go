package hook

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Kimi Code hook writer (T-378, D-268 / D-270). Kimi Code reads hooks only
// from the [[hooks]] array of tables in ~/.kimi-code/config.toml
// ($KIMI_CODE_HOME/config.toml): {event, matcher, command, timeout}, where
// any other field fails the vendor's config load. The same file can hold a
// plaintext provider api_key, so the registry row declares the
// credential-file exception and this writer:
//
//   - edits only Observer's own [[hooks]] tables, line by line
//     (setTOMLHookTables): every other line, comment and key keeps its
//     bytes, and the result must decode to the original values plus
//     Observer's tables or nothing is written;
//   - keeps the file mode, writes atomically, makes no backup;
//   - never logs or returns a value from the file (Register wraps every
//     error through credentialSafeError) and records only a hooks-subtree
//     digest in hook_checksums.json.
//
// Several rules matching one event run in parallel (vendor doc), so a
// foreign [[hooks]] table on the same event is left in place and is not a
// conflict.

// kimiHookTimeoutSeconds is the timeout Observer writes on its tables (the
// vendor default; a timeout is an allow, the vendor fails open).
const kimiHookTimeoutSeconds = 30

// kimiHookEvents are the events Observer registers, in file order: the
// prompt gate and the PreToolUse tool gate (equal to the registry row's
// Registered bindings; TestRegisteredBindingsMatchRegisteredEvents).
var kimiHookEvents = []string{"UserPromptSubmit", "PreToolUse"}

// kimiCodeConfigPath is the config.toml the vendor reads: the
// kimi-code/user-config artifact, so $KIMI_CODE_HOME (the vendor's own
// storage-root override) moves it, the same rule the route writer follows.
// A relative value is an error: Kimi Code would read it against its own
// working directory.
func (r *Registry) kimiCodeConfigPath() (string, error) {
	return r.artifactPath("kimi-code/user-config")
}

// kimiHookTableIsObservers reports whether a [[hooks]] table is Observer's.
func kimiHookTableIsObservers(t map[string]any) bool {
	cmd, _ := t["command"].(string)
	return isObserverAnyHookEntry(cmd, "kimi-code")
}

// kimiWantedTables is the [[hooks]] tables Observer wants for the events
// this registration writes.
func (r *Registry) kimiWantedTables() (tables []map[string]any, events []string) {
	bin := shellQuoteIfNeeded(forwardSlashPath(r.opts.BinaryPath))
	for _, event := range kimiHookEvents {
		if r.skipEvent("kimi-code", event) {
			continue
		}
		tables = append(tables, map[string]any{
			"event":   event,
			"command": bin + " hook kimi-code " + event + r.configFlagSuffixForwardSlash(),
			"timeout": int64(kimiHookTimeoutSeconds),
		})
		events = append(events, event)
	}
	return tables, events
}

// registerKimiCode writes Observer's [[hooks]] tables into Kimi Code's
// config.toml (creating the file when Kimi Code has none yet).
func (r *Registry) registerKimiCode() RegistrationResult {
	res := RegistrationResult{Tool: "kimi-code", DryRun: r.opts.DryRun}
	path, err := r.kimiCodeConfigPath()
	if err != nil {
		res.Error = fmt.Errorf("hook.registerKimiCode: %w", err)
		return res
	}
	res.ConfigPath = path
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerKimiCode: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	orig, err := readSettingsFile(pinned.target)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("hook.registerKimiCode: read: %w", err)
		return res
	}
	// FU-192: an entry in Observer's shape running another binary is kept.
	if r.refusesForeignBinary(&res, "hook.registerKimiCode", path, identityContent, shapedHooksInText(orig, "kimi-code")) {
		return res
	}
	want, events := r.kimiWantedTables()
	body, changed, err := setTOMLHookTables(orig, kimiHookTableIsObservers, want)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerKimiCode: %w", err)
		return res
	}
	if !changed {
		res.AlreadySet = append(res.AlreadySet, events...)
		return res
	}
	res.HooksAdded = append(res.HooksAdded, events...)
	if r.opts.DryRun {
		return res
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		res.Error = fmt.Errorf("hook.registerKimiCode: %w", err)
		return res
	}
	if err := pinned.verifyUnmoved(); err != nil {
		res.Error = fmt.Errorf("hook.registerKimiCode: %w", err)
		return res
	}
	if err := atomicWriteFileMode(pinned, body, fileModeOr(pinned.target, 0o600)); err != nil {
		res.Error = fmt.Errorf("hook.registerKimiCode: write: %w", err)
		return res
	}
	if err := r.recordHookChecksum("kimi-code", path); err != nil {
		res.Error = err
	}
	return res
}

// unregisterKimiCode removes ONLY Observer's [[hooks]] tables. A file left
// holding nothing (Observer created it) is removed.
func (r *Registry) unregisterKimiCode() UnregistrationResult {
	res := UnregistrationResult{Tool: "kimi-code", DryRun: r.opts.DryRun}
	path, err := r.kimiCodeConfigPath()
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterKimiCode: %w", err)
		return res
	}
	res.ConfigPath = path
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterKimiCode: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	orig, err := readSettingsFile(pinned.target)
	if errors.Is(err, os.ErrNotExist) {
		return res
	}
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterKimiCode: read: %w", err)
		return res
	}
	body, changed, err := setTOMLHookTables(orig, kimiHookTableIsObservers, nil)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterKimiCode: %w", err)
		return res
	}
	if !changed {
		return res
	}
	res.HooksRemoved = append(res.HooksRemoved, kimiHookEventsIn(orig)...)
	if r.opts.DryRun {
		return res
	}
	if strings.TrimSpace(string(body)) == "" {
		if err := removeEmptyConfigFile(pinned.target, orig); err != nil {
			res.Error = fmt.Errorf("hook.unregisterKimiCode: %w", err)
			return res
		}
	} else {
		if err := pinned.verifyUnmoved(); err != nil {
			res.Error = fmt.Errorf("hook.unregisterKimiCode: %w", err)
			return res
		}
		if err := atomicWriteFileMode(pinned, body, fileModeOr(pinned.target, 0o600)); err != nil {
			res.Error = fmt.Errorf("hook.unregisterKimiCode: write: %w", err)
			return res
		}
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
	}
	return res
}

// kimiHookEventsIn lists the events of Observer's tables in body, in file
// order (event names only, for the unregistration result).
func kimiHookEventsIn(body []byte) []string {
	top := map[string]any{}
	if _, err := toml.Decode(string(body), &top); err != nil {
		return nil
	}
	tables, _ := tomlHookTables(top["hooks"])
	var out []string
	for _, t := range tables {
		if e, _ := t["event"].(string); e != "" && kimiHookTableIsObservers(t) {
			out = append(out, e)
		}
	}
	return out
}
