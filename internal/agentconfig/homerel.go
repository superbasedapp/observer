package agentconfig

import (
	"path"
	"strings"
)

// homeRelProbe is the placeholder home HomeRelativeDir resolves under.
const homeRelProbe = "/agentconfig-home-probe"

// HomeRelativeDir returns the directory of catalogued artifact id relative
// to a user home on goos, slash-separated (".codeium/windsurf" for the
// Cascade hooks file, "AppData/Roaming/devin" for the Devin CLI config on
// Windows), with no relocation variable applied. A cross-OS writer, which
// cannot read the other side's environment, joins it onto the foreign home
// it found instead of hard-coding the vendor's directory (surface-gap
// Wave 7). ok is false when the artifact has no user path on goos.
func HomeRelativeDir(id, goos string) (string, bool) {
	got, err := ResolveArtifact(id, PathEnv{
		GOOS: goos, Home: homeRelProbe,
		Getenv: func(string) string { return "" },
		IsAbs:  func(p string) bool { return strings.HasPrefix(p, "/") },
	})
	if err != nil || got.Path == "" {
		return "", false
	}
	full := strings.ReplaceAll(got.Path, `\`, "/")
	if got.Status != PathDirectory {
		full = path.Dir(full)
	}
	rel, ok := strings.CutPrefix(strings.TrimSuffix(full, "/"), homeRelProbe+"/")
	if !ok || rel == "" {
		return "", false
	}
	return rel, true
}
