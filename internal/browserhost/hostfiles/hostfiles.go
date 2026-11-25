package hostfiles

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed host.js host-launcher.sh
var hostFS embed.FS

const (
	// HostScriptName is the embedded Node stdio host filename.
	HostScriptName = "host.js"
	// LauncherName is the embedded launcher filename — the executable the
	// native-messaging manifest "path" points at.
	LauncherName = "host-launcher.sh"

	observerBinMarker    = "{{OBSERVER_BIN}}"
	observerConfigMarker = "{{OBSERVER_CONFIG}}"
	nodeBinMarker        = "{{NODE_BIN}}"
)

// Env carries the values baked into the launcher at write time. Every field
// is optional: empty ObserverBin / NodeBin fall back to a bare PATH lookup
// ("observer" / "node"); empty ObserverConfig means the host runs without a
// --config flag (the daemon-default config path).
type Env struct {
	// ObserverBin is the absolute observer binary path (os.Executable +
	// EvalSymlinks — like hermes) baked into OBSERVER_BIN so the host does
	// not depend on PATH at runtime. "" → "observer".
	ObserverBin string
	// ObserverConfig is the observer config.toml path baked into
	// OBSERVER_CONFIG (forwarded as --config). "" → no --config.
	ObserverConfig string
	// NodeBin is the node interpreter path baked into the launcher's exec
	// line. "" → "node" (PATH lookup). WriteHost never fails on a missing
	// node — resolving/​warning is the caller's job (honest disabled copy).
	NodeBin string
}

// LauncherPath returns the absolute path the launcher WOULD be written to in
// dir, without writing anything. Used by dry-run previews so the manifest can
// point at the resolved (would-be) host path.
func LauncherPath(dir string) string {
	return filepath.Join(dir, LauncherName)
}

// WriteHost writes host.js + host-launcher.sh into dir (creating it), stamps
// env into the launcher, and returns the absolute launcher path. The launcher
// gets mode 0o755 (Chrome requires an executable); host.js gets 0o644. It is
// idempotent — an existing install is overwritten with the freshly-stamped
// copies.
func WriteHost(dir string, env Env) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("hostfiles.WriteHost: mkdir %s: %w", dir, err)
	}

	host, err := hostFS.ReadFile(HostScriptName)
	if err != nil {
		return "", fmt.Errorf("hostfiles.WriteHost: read embedded %s: %w", HostScriptName, err)
	}
	hostPath := filepath.Join(dir, HostScriptName)
	if err := os.WriteFile(hostPath, host, 0o644); err != nil { //nolint:gosec // G306: node host script the launcher execs; non-sensitive, conventionally 0644.
		return "", fmt.Errorf("hostfiles.WriteHost: write %s: %w", hostPath, err)
	}

	launcher, err := hostFS.ReadFile(LauncherName)
	if err != nil {
		return "", fmt.Errorf("hostfiles.WriteHost: read embedded %s: %w", LauncherName, err)
	}
	launcher = stampLauncher(launcher, env)
	launcherPath := filepath.Join(dir, LauncherName)
	if err := os.WriteFile(launcherPath, launcher, 0o755); err != nil { //nolint:gosec // G306: native-messaging launcher must be executable by the browser.
		return "", fmt.Errorf("hostfiles.WriteHost: write %s: %w", launcherPath, err)
	}
	return launcherPath, nil
}

// stampLauncher substitutes the env markers in the launcher template. Each
// marker is replaced exactly once (n=1) — the template carries one of each.
// Values are escaped for the double-quoted shell context they land in.
func stampLauncher(tmpl []byte, env Env) []byte {
	observerBin := env.ObserverBin
	if observerBin == "" {
		observerBin = "observer"
	}
	nodeBin := env.NodeBin
	if nodeBin == "" {
		nodeBin = "node"
	}
	out := bytes.Replace(tmpl, []byte(observerBinMarker), []byte(shellEscapeDoubleQuoted(observerBin)), 1)
	out = bytes.Replace(out, []byte(observerConfigMarker), []byte(shellEscapeDoubleQuoted(env.ObserverConfig)), 1)
	out = bytes.Replace(out, []byte(nodeBinMarker), []byte(shellEscapeDoubleQuoted(nodeBin)), 1)
	return out
}

// shellEscapeDoubleQuoted escapes the characters that would terminate or
// alter a POSIX double-quoted string literal: backslash, double-quote, dollar
// (parameter/command expansion) and backtick (legacy command substitution).
// The caller substitutes the result INSIDE a "..." pair in the launcher, so
// the value is preserved literally even for paths with spaces or `$`.
func shellEscapeDoubleQuoted(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\', '"', '$', '`':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Files returns the embedded filenames in deterministic order — used by tests
// and by the install-status output of `observer init --browser`.
func Files() []string {
	return []string{HostScriptName, LauncherName}
}
