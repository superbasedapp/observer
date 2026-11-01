package hermesplugin

import (
	"bytes"
	"encoding/binary"
	"io/fs"
	"path"
	"regexp"
	"strings"
)

// IsInstalledFile reports whether data is exactly the plugin file rel
// (a path inside the plugin directory, slash-separated) as WritePlugin
// writes it for one of bins: plugin.yaml byte for byte, __init__.py with
// the OBSERVER_BIN default set to one of bins. A file the plugin does not
// ship (a __pycache__ entry, anything added beside it), an edited file, or
// one rendered for another binary is not. The repository trust check
// (docs/security.md SECP-5) uses it so the plugin directory counts as
// Observer's own only while it holds what Observer wrote. An empty bin is
// never accepted: the bare "observer" PATH default is a shape, not a
// binary.
func IsInstalledFile(rel string, data []byte, bins []string) bool {
	want, err := fs.ReadFile(pluginFS, rel)
	if err != nil {
		return false
	}
	if rel != "__init__.py" {
		return bytes.Equal(data, want)
	}
	for _, b := range bins {
		if b == "" {
			continue
		}
		if bytes.Equal(data, bytes.Replace(want, []byte(observerBinPlaceholder), []byte(escapePythonStringContents(b)), 1)) {
			return true
		}
	}
	return false
}

// LooksLikePluginFile reports whether data, the file at rel inside the plugin
// directory, reads as one WritePlugin wrote in any version: it starts with
// the first line of the embedded file (the manifest's name line, the
// bridge's docstring header). A file the plugin does not ship never does.
// Unlike IsInstalledFile it accepts an older render or another binary, so an
// upgrade rewrites Observer's own plugin; the writer's foreign-file guard
// (hook.RegisterHermes, FU-207) refuses anything else without --force.
func LooksLikePluginFile(rel string, data []byte) bool {
	want, err := fs.ReadFile(pluginFS, rel)
	if err != nil {
		return false
	}
	first, _, _ := bytes.Cut(want, []byte("\n"))
	first = bytes.TrimRight(first, "\r")
	return len(first) > 0 && bytes.HasPrefix(data, first)
}

// observerBinDefault matches the OBSERVER_BIN default WritePlugin bakes into
// __init__.py.
var observerBinDefault = regexp.MustCompile(`OBSERVER_BIN = os\.environ\.get\("OBSERVER_BIN", "((?:[^"\\]|\\.)*)"\)`)

// ObserverBinDefault returns the binary an __init__.py runs when OBSERVER_BIN
// is unset (the default WritePlugin baked in), and whether it holds one.
func ObserverBinDefault(data []byte) (string, bool) {
	m := observerBinDefault.FindSubmatch(data)
	if m == nil {
		return "", false
	}
	return unescapePythonStringContents(string(m[1])), true
}

// unescapePythonStringContents reverses escapePythonStringContents.
func unescapePythonStringContents(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// IsBytecodeOf reports whether data, the file at rel inside the plugin
// directory (slash-separated), is the bytecode CPython compiled from source,
// the plugin's __init__.py as it stood: a __pycache__/__init__.<tag>.pyc
// whose header (PEP 552) is the timestamp form and records source's size.
// Hermes imports the plugin, so CPython writes it beside Observer's file;
// it is Observer's to remove with that file (FU-212). A hash-based pyc, or
// one whose recorded size is another source's, is not.
func IsBytecodeOf(rel string, data, source []byte) bool {
	dir, name := path.Split(rel)
	if dir != "__pycache__/" || !strings.HasPrefix(name, "__init__.") || !strings.HasSuffix(name, ".pyc") {
		return false
	}
	if len(data) < 16 || binary.LittleEndian.Uint32(data[4:8]) != 0 {
		return false
	}
	return binary.LittleEndian.Uint32(data[12:16]) == uint32(len(source)) //nolint:gosec // G115: the pyc header keeps the size mod 2^32
}
