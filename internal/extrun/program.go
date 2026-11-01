package extrun

import (
	"strings"
)

// fileCheck is one row of the executable check table. The first row whose
// refuse function returns true decides; detail is the plain sentence.
type fileCheck struct {
	reason RefuseReason
	refuse func(goos, path string, f FileFacts, allowSymlink bool) bool
	detail string
}

// windowsScriptExts are the extensions Windows starts through an
// interpreter (cmd.exe for batch files), where argument quoting is not the
// program's own. They are refused on Windows.
var windowsScriptExts = []string{".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh"}

// fileChecks is walked top-down for the executable and every companion.
var fileChecks = []fileCheck{
	{
		RefuseNotAbsolute, func(goos, p string, _ FileFacts, _ bool) bool { return !IsAbs(goos, p) },
		"the path is not absolute; the runner never looks a name up on PATH",
	},
	{
		RefuseNotFound, func(_, _ string, f FileFacts, _ bool) bool { return !f.Exists },
		"nothing is at the path",
	},
	{
		RefuseSymlink, func(_, _ string, f FileFacts, allow bool) bool { return f.Symlink && !allow },
		"the path is a symlink and the request does not allow one",
	},
	{
		RefuseNotRegular, func(_, _ string, f FileFacts, _ bool) bool { return !f.Regular || f.Real == "" },
		"the path does not resolve to a regular file",
	},
	{RefuseScriptShim, func(goos, _ string, f FileFacts, _ bool) bool {
		if goos != "windows" {
			return false
		}
		low := strings.ToLower(f.Real)
		for _, ext := range windowsScriptExts {
			if strings.HasSuffix(low, ext) {
				return true
			}
		}
		return false
	}, "the path is a Windows script or batch file, which runs through an interpreter"},
}

// CheckFile walks the check table for one path. It returns RefuseNone and
// the path to run and hash (the final target, f.Real) when every row passes.
func CheckFile(goos, path string, f FileFacts, allowSymlink bool) (RefuseReason, string, string) {
	for _, c := range fileChecks {
		if c.refuse(goos, path, f, allowSymlink) {
			return c.reason, c.detail, ""
		}
	}
	return RefuseNone, "", f.Real
}

// resolvableVerdicts are the toolresolve verdicts whose Bin can run.
var resolvableVerdicts = map[string]bool{
	"ok":          true,
	"ok_off_path": true,
	"shadowed":    true,
}

// baseName returns the last element of p, split on both separators so a
// Windows path classifies the same on any host.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
