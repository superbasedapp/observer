//go:build unix

package hook

import (
	"os/user"
	"path/filepath"
	"runtime"
)

// claudeManagedPrefsDomain is Claude Code's macOS managed-preferences
// domain (managed-settings page: "the com.anthropic.claudecode managed
// preferences domain"); MDM places the device-wide plist in
// ibmBobManagedPrefsDir, and a per-user one under <user>/.
const claudeManagedPrefsDomain = "com.anthropic.claudecode"

// claudeOSPolicy returns this OS's MDM source (macOS: the managed-
// preferences plist, converted with plutil; other unix: none) and its GOOS.
// Unix has no HKCU source.
func claudeOSPolicy() (mdm, hkcu ClaudePolicySource, goos string) {
	goos = runtime.GOOS
	if goos != "darwin" {
		return ClaudePolicySource{}, ClaudePolicySource{}, goos
	}
	paths := []string{filepath.Join(ibmBobManagedPrefsDir, claudeManagedPrefsDomain+".plist")}
	if u, err := user.Current(); err == nil && u.Username != "" {
		paths = append(paths, filepath.Join(ibmBobManagedPrefsDir, u.Username, claudeManagedPrefsDomain+".plist"))
	}
	for _, p := range paths {
		if s := readClaudePolicyPlist(p); s.Found {
			return s, ClaudePolicySource{}, goos
		}
	}
	return ClaudePolicySource{}, ClaudePolicySource{}, goos
}

// readClaudePolicyPlist reads one managed-preferences plist as the MDM
// source (the same top-level keys as managed-settings.json).
func readClaudePolicyPlist(p string) ClaudePolicySource {
	s := ClaudePolicySource{Kind: ClaudeSourceMDM, Location: p}
	data, found, err := readClaudePolicyFile(p)
	if !found {
		return s
	}
	s.Found = true
	if err != nil {
		s.Problem = err.Error()
		return s
	}
	if data, err = plistToJSON(data); err != nil {
		s.Problem = "could not be converted from a property list"
		return s
	}
	d, err := ParseClaudePolicyDocument(data)
	if err != nil {
		s.Problem = "is not a JSON object"
		return s
	}
	s.Doc = d
	return s
}
