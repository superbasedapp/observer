package shellwrap

import (
	"strings"
)

// Windows Documents-folder resolution for the PowerShell profile paths.
//
// The profiles live under the user's Documents folder, which is frequently
// NOT %USERPROFILE%\Documents: OneDrive's "back up your folders" moves it to
// %USERPROFILE%\OneDrive\Documents (or "OneDrive - <Org>\Documents"), and a
// managed machine may redirect it to another drive or a network share.
// PowerShell itself asks the shell for the known folder, so the planner must
// too - otherwise it would write a block into a profile PowerShell never runs.

// DocumentsSource names the rung of the ladder that produced the folder.
type DocumentsSource string

// Documents-folder sources, in ladder order.
const (
	// DocumentsKnownFolder: SHGetKnownFolderPath(FOLDERID_Documents).
	DocumentsKnownFolder DocumentsSource = "known-folder"
	// DocumentsShellFolders: HKCU\Software\Microsoft\Windows\CurrentVersion\
	// Explorer\User Shell Folders\Personal (REG_EXPAND_SZ, expanded here).
	DocumentsShellFolders DocumentsSource = "user-shell-folders"
	// DocumentsHomeDefault: <home>\Documents (home = %USERPROFILE%).
	DocumentsHomeDefault DocumentsSource = "home-default"
)

// DocumentsLookup is the injected view of the OS. Every func may be nil (the
// rung is skipped) or fail (the next rung is tried). The pure package calls
// them only when an earlier rung produced nothing usable.
type DocumentsLookup struct {
	// KnownFolder returns the known-folder API's Documents path.
	KnownFolder func() (string, error)
	// ShellFolder returns the raw, UNEXPANDED registry value (it may carry
	// %USERPROFILE% and similar references).
	ShellFolder func() (string, error)
	// Getenv expands %NAME% references in ShellFolder's value.
	Getenv func(string) string
	// Home is the user's home directory (%USERPROFILE%); the last rung.
	Home string
}

// documentsRung is one row of the ladder, walked top-down: the first rung
// that yields an absolute, script-safe Windows path wins.
type documentsRung struct {
	source DocumentsSource
	get    func(l DocumentsLookup) string
}

var documentsLadder = []documentsRung{
	{DocumentsKnownFolder, func(l DocumentsLookup) string {
		if l.KnownFolder == nil {
			return ""
		}
		p, err := l.KnownFolder()
		if err != nil {
			return ""
		}
		return p
	}},
	{DocumentsShellFolders, func(l DocumentsLookup) string {
		if l.ShellFolder == nil {
			return ""
		}
		raw, err := l.ShellFolder()
		if err != nil {
			return ""
		}
		p, ok := expandWindowsEnv(raw, l.Getenv)
		if !ok {
			return ""
		}
		return p
	}},
	{DocumentsHomeDefault, func(l DocumentsLookup) string {
		if strings.TrimSpace(l.Home) == "" {
			return ""
		}
		return strings.TrimRight(l.Home, `\/`) + `\Documents`
	}},
}

// ResolveDocumentsDir walks the ladder: the known-folder API, then the User
// Shell Folders registry value (with %VAR% references expanded), then
// <home>\Documents. ok=false only when every rung failed (no home either).
func ResolveDocumentsDir(l DocumentsLookup) (string, DocumentsSource, bool) {
	for _, r := range documentsLadder {
		p := cleanWindowsDir(r.get(l))
		if p == "" || !isAbsWindowsPath(p) || checkPath(p) != nil {
			continue
		}
		return p, r.source, true
	}
	return "", "", false
}

// cleanWindowsDir trims surrounding whitespace and trailing separators
// (keeping a drive root's "C:\").
func cleanWindowsDir(p string) string {
	p = strings.TrimSpace(p)
	for len(p) > 3 && (strings.HasSuffix(p, `\`) || strings.HasSuffix(p, "/")) {
		p = p[:len(p)-1]
	}
	return p
}

// isAbsWindowsPath accepts a drive-absolute path (C:\...) or a UNC path
// (\\server\share\...). A drive-relative "C:foo" or a rooted "\foo" is not
// absolute on Windows and is refused.
func isAbsWindowsPath(p string) bool {
	if len(p) >= 3 && isDriveLetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	if strings.HasPrefix(p, `\\`) {
		rest := strings.TrimPrefix(p, `\\`)
		i := strings.IndexByte(rest, '\\')
		return i > 0 && i < len(rest)-1
	}
	return false
}

func isDriveLetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// expandWindowsEnv expands %NAME% references the way ExpandEnvironmentStrings
// does. ok=false when a reference is unterminated or names an unset (empty)
// variable: a half-expanded path would point somewhere PowerShell never looks.
func expandWindowsEnv(s string, getenv func(string) string) (string, bool) {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			b.WriteString(s)
			return b.String(), true
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			return "", false
		}
		name := s[i+1 : i+1+j]
		if name == "" || getenv == nil {
			return "", false
		}
		v := getenv(name)
		if v == "" {
			return "", false
		}
		b.WriteString(s[:i])
		b.WriteString(v)
		s = s[i+1+j+1:]
	}
}
