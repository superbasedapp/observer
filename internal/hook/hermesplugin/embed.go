// Package hermesplugin embeds the SuperBased Observer plugin files for
// Hermes Agent and exposes a single WritePlugin helper that drops them
// into a target directory at install time.
//
// `observer init --hermes` invokes WritePlugin against
// `~/.hermes/plugins/superbased-observer/` (Linux/macOS/WSL2) or
// `%LOCALAPPDATA%\hermes\plugins\superbased-observer\` (Windows
// native). Hermes auto-discovers plugins from those directories on
// agent startup — no config.yaml entry needed (confirmed via
// hermes_cli/plugins.py docstring lines 1-33; the plugins.disabled
// deny-list is a hard veto if the operator wants to suppress without
// uninstalling).
//
// Two files ship:
//
//   - plugin.yaml — the Hermes plugin manifest.
//   - __init__.py — the actual Python bridge that calls
//     `observer hook hermes <event>` as a fire-and-forget subprocess
//     on each lifecycle hook the observer adapter consumes, and as a
//     GATE on pre_tool_call (hook-parity Lane A7: Observer's guard can
//     block a Hermes tool call or raise Hermes' own approval prompt).
//
// Re-running WritePlugin against an existing install is idempotent:
// existing files are overwritten with whatever the embedded copy
// holds. A no-op upgrade is what `observer init --hermes` performs
// when the operator re-runs init after an `npm i -g
// @superbased/observer` upgrade.
package hermesplugin

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed plugin.yaml __init__.py
var pluginFS embed.FS

// observerBinPlaceholder is the marker string in the embedded
// __init__.py that WritePlugin substitutes with the resolved observer
// binary path at install time. Format is `{{OBSERVER_BIN_DEFAULT}}` so
// it's unambiguous, easy to grep, and won't accidentally match
// real-world content. Replaced exactly once via bytes.Replace with n=1.
const observerBinPlaceholder = "{{OBSERVER_BIN_DEFAULT}}"

// WritePlugin writes the embedded plugin files into destDir, creating
// the directory if it doesn't exist. Returns an error wrapping the
// underlying I/O failure on first error encountered.
//
// destDir is expected to be the leaf plugin path
// (e.g. `~/.hermes/plugins/superbased-observer/`), not the
// `~/.hermes/plugins/` parent — the caller is responsible for
// composing the leaf name so future renames (different plugin
// identifier, branded variant) don't require touching the embed
// package.
//
// defaultObserverBin gets baked into the `OBSERVER_BIN` default in
// __init__.py at write time so the operator doesn't need to set the
// env var manually. Pass the running observer's `os.Executable()`
// absolute path. An empty string falls back to the bare "observer"
// PATH-lookup default — useful for unit tests that don't have a real
// binary, but NOT recommended in production because PATH on Windows
// frequently resolves to a broken npm shim. The plugin still honours
// an explicit OBSERVER_BIN env override at runtime regardless.
//
// File modes:
//   - Directory: 0o755 (rwxr-xr-x)
//   - Files:     0o644 (rw-r--r--)
//
// WritePlugin overwrites whatever is at each path. It has one caller,
// hook.RegisterHermes, which runs the foreign-file guard first (FU-207): a
// file that is not Observer's plugin file, or a bridge whose OBSERVER_BIN
// default is not an observer binary, is kept byte for byte and refused
// without --force. Any new caller must take that guard too.
//
// Hermes's plugin loader only needs read access; the conservative
// modes match the cursor adapter's hook-file writes and the
// `observer init --claude-code` settings-file writes already in
// production.
func WritePlugin(destDir, defaultObserverBin string) error {
	if defaultObserverBin == "" {
		defaultObserverBin = "observer"
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("hermesplugin.WritePlugin: mkdir %s: %w", destDir, err)
	}
	return fs.WalkDir(pluginFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." || d.IsDir() {
			return nil
		}
		data, err := pluginFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("hermesplugin.WritePlugin: read embedded %s: %w", path, err)
		}
		if path == "__init__.py" {
			data = bytes.Replace(data, []byte(observerBinPlaceholder), []byte(escapePythonStringContents(defaultObserverBin)), 1)
		}
		if err := os.WriteFile(filepath.Join(destDir, path), data, 0o600); err != nil {
			return fmt.Errorf("hermesplugin.WritePlugin: write %s: %w", path, err)
		}
		return nil
	})
}

// escapePythonStringContents returns s with the characters that would
// terminate or alter a Python double-quoted string literal escaped.
// Caller substitutes the result INSIDE a `"..."` pair in the rendered
// __init__.py — so we escape backslash and double-quote at minimum.
// Newlines / tabs / control chars get standard \n / \t escapes for the
// (rare) case where a path contains them — defends against the
// embedded substitution producing un-parseable Python without forcing
// raw-string r"" semantics (which can't end in a single backslash).
func escapePythonStringContents(s string) string {
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

// Files returns the slice of embedded filenames in deterministic
// order. Used by tests + by the install-status output of
// `observer init --hermes` to show the operator what got written.
func Files() []string {
	var out []string
	_ = fs.WalkDir(pluginFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == "." || d.IsDir() {
			return nil
		}
		out = append(out, path)
		return nil
	})
	return out
}
