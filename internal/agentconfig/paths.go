package agentconfig

import (
	"strings"
)

// Path resolution (phase P4): a FileRow's per-OS path, with its tokens
// expanded for one machine. Pure: the caller supplies the OS, home, project
// root and environment; nothing here touches the file system.

// PathEnv is the machine a path is resolved for.
type PathEnv struct {
	// GOOS is "linux", "darwin" or "windows" (anything else resolves as
	// linux).
	GOOS string
	// Home is the user's home directory (absolute).
	Home string
	// Project is the project root, "" when no project is selected.
	Project string
	// Getenv reads an environment variable; nil reads nothing.
	Getenv func(string) string
	// SystemRoot, when set, is prefixed to every absolute path that is not
	// under Home or Project (managed / system files). Tests set it so a
	// resolution never names the real /etc or C:\Program Files.
	SystemRoot string
	// Relocate applies the row's relocation rules (fileRelocations,
	// relocate.go) before token expansion. Off by default so an existing
	// caller keeps resolving the
	// documented default path; a writer that names an artifact resolves
	// with it on (ResolveArtifact).
	Relocate bool
	// IsAbs, when set, decides whether an environment value is an absolute
	// path. nil (every production caller) judges by GOOS's path syntax: a
	// drive or UNC path for windows, a leading "/" elsewhere. That is the
	// FU-143 ruling: a relocation value is judged by the syntax of the OS
	// whose row is resolved, so a Windows row resolved on Linux accepts
	// C:\x and refuses /x, and the reverse. In production GOOS is the
	// running OS and this equals filepath.IsAbs; the two differ only where a
	// caller pins another OS (tests, cross-OS tables). Only a unit test that
	// models another rule sets it.
	IsAbs func(string) bool
}

// PathStatus says whether a row resolved to one concrete file.
type PathStatus string

// The closed PathStatus vocabulary.
const (
	// PathResolved: Path names one concrete file.
	PathResolved PathStatus = "resolved"
	// PathNoOS: the tool has no such file on this OS.
	PathNoOS PathStatus = "no_os"
	// PathNeedsProject: a project-scope row with no project selected.
	PathNeedsProject PathStatus = "needs_project"
	// PathDirectory: the vendor documents a directory, not a file name.
	PathDirectory PathStatus = "directory"
	// PathGlob: the row is a glob (instruction / skill / agent rows); the
	// boundary lists its matches.
	PathGlob PathStatus = "glob"
	// PathRelocationUnresolved: a relocation variable (RelocatedBy) holds a
	// relative value the tool reads against its own working directory, so
	// the file has no path Observer can name. Path is empty; a writer must
	// not fall back to the default location (relocate.go, FU-31).
	PathRelocationUnresolved PathStatus = "relocation_unresolved"
	// PathEnvUnset: the row's path is rooted at a variable-only token (an
	// extra config directory the tool reads only when the variable names
	// one, such as $OPENCODE_CONFIG_DIR) and the variable is unset or not
	// an absolute path, so the tool reads no such file. Path is empty.
	PathEnvUnset PathStatus = "env_unset"
)

// ResolvedPath is one row's resolution.
type ResolvedPath struct {
	Status PathStatus
	// Path is the expanded path (also set for PathGlob and PathDirectory,
	// expanded as far as the tokens go).
	Path string
	// RelocatedBy names the environment variable that moved the file, ""
	// when none did.
	RelocatedBy string
	// RelocationIgnored lists each set variable that was refused, as
	// "<ENV>:<reason>" (RelocIgnore).
	RelocationIgnored []string
}

func (e PathEnv) windows() bool { return e.GOOS == "windows" }

func (e PathEnv) env(name string) string {
	if e.Getenv == nil {
		return ""
	}
	return e.Getenv(name)
}

// rawPath picks the row's path for the env's OS.
func (e PathEnv) rawPath(p OSPaths) string {
	switch e.GOOS {
	case "windows":
		return p.Windows
	case "darwin":
		return p.Darwin
	}
	return p.Linux
}

// Join joins segments with the env's separator.
func (e PathEnv) Join(parts ...string) string {
	sep := "/"
	if e.windows() {
		sep = `\`
	}
	var b strings.Builder
	for i, p := range parts {
		if p == "" {
			continue
		}
		if i > 0 && b.Len() > 0 {
			s := b.String()
			if !strings.HasSuffix(s, "/") && !strings.HasSuffix(s, `\`) {
				b.WriteString(sep)
			}
			p = strings.TrimLeft(p, `/\`)
		}
		b.WriteString(p)
	}
	return e.native(b.String())
}

// native converts separators to the env's OS.
func (e PathEnv) native(p string) string {
	if e.windows() {
		return strings.ReplaceAll(p, "/", `\`)
	}
	return strings.ReplaceAll(p, `\`, "/")
}

// tokenRule expands one leading path token.
type tokenRule struct {
	Token string
	// Expand returns the replacement for the token; "" leaves the path
	// unresolvable.
	Expand func(e PathEnv) string
	// Env, when set, makes the token variable-only: it is the variable's
	// absolute value or nothing (no default), and a row rooted at it
	// resolves to PathEnvUnset while the variable is unset. Such a row is a
	// location the tool adds when the variable is set, never a relocation
	// of another row.
	Env string
}

// envSigil is the prefix of a variable token in the table ("$XDG_..."). A
// named constant so the token is not read as a dollar figure by the
// no-bare-USD check (cmd/observer/no_bare_usd_test.go).
const envSigil = "$"

// envOnlyToken is a variable-only tokenRule for env.
func envOnlyToken(env string) tokenRule {
	return tokenRule{Token: envSigil + env, Env: env, Expand: func(e PathEnv) string {
		if v := e.env(env); v != "" && e.isAbs(v) {
			return v
		}
		return ""
	}}
}

// pathTokens is the closed token table (OSPaths doc comment). A profile or
// XDG variable holding a relative value is ignored and the derived default
// used, as the XDG spec and Windows' own profile resolution do.
//
//nolint:gosec // G101: Token is a path placeholder (%LOCALAPPDATA%, $XDG_DATA_HOME), never a credential.
var pathTokens = []tokenRule{
	{Token: "<project>", Expand: func(e PathEnv) string { return e.Project }},
	{Token: "~", Expand: func(e PathEnv) string { return e.Home }},
	{Token: "%USERPROFILE%", Expand: func(e PathEnv) string { return e.Home }},
	{Token: "%APPDATA%", Expand: func(e PathEnv) string {
		if v := e.env("APPDATA"); v != "" && e.isAbs(v) {
			return v
		}
		return e.Join(e.Home, "AppData", "Roaming")
	}},
	{Token: "%LOCALAPPDATA%", Expand: func(e PathEnv) string {
		if v := e.env("LOCALAPPDATA"); v != "" && e.isAbs(v) {
			return v
		}
		return e.Join(e.Home, "AppData", "Local")
	}},
	{Token: "%ProgramData%", Expand: func(e PathEnv) string {
		if v := e.env("ProgramData"); v != "" {
			return e.system(v)
		}
		return e.system(`C:\ProgramData`)
	}},
	{Token: "%ProgramFiles%", Expand: func(e PathEnv) string {
		if v := e.env("ProgramFiles"); v != "" {
			return e.system(v)
		}
		return e.system(`C:\Program Files`)
	}},
	{Token: "$XDG_CONFIG_HOME", Expand: func(e PathEnv) string {
		if v := e.env("XDG_CONFIG_HOME"); v != "" && e.isAbs(v) {
			return v
		}
		return e.Join(e.Home, ".config")
	}},
	{Token: "$XDG_DATA_HOME", Expand: func(e PathEnv) string {
		if v := e.env("XDG_DATA_HOME"); v != "" && e.isAbs(v) {
			return v
		}
		return e.Join(e.Home, ".local", "share")
	}},
	// OpenCode's extra config directory (FU-103, MAC-4): opencode loads
	// $OPENCODE_CONFIG_DIR/opencode.json in addition to the global file.
	envOnlyToken("OPENCODE_CONFIG_DIR"),
}

// envOnlyTokenOf returns the variable-only token raw starts with.
func envOnlyTokenOf(raw string) (tokenRule, bool) {
	for _, t := range pathTokens {
		if t.Env != "" && (raw == t.Token || strings.HasPrefix(raw, t.Token+"/") || strings.HasPrefix(raw, t.Token+`\`)) {
			return t, true
		}
	}
	return tokenRule{}, false
}

// pathTokenVariables lists the variables of the variable-only tokens.
func pathTokenVariables() []string {
	var out []string
	for _, t := range pathTokens {
		if t.Env != "" {
			out = append(out, t.Env)
		}
	}
	return out
}

// system re-roots an absolute system path under SystemRoot when set.
func (e PathEnv) system(p string) string {
	if e.SystemRoot == "" {
		return p
	}
	rel := p
	if len(rel) >= 2 && rel[1] == ':' { // drive letter
		rel = rel[2:]
	}
	return e.Join(e.SystemRoot, rel)
}

// ResolvePath expands a row's path for the env. With e.Relocate set, the
// row's relocation rules are applied first (relocate.go).
func ResolvePath(f FileRow, e PathEnv) ResolvedPath {
	raw := e.rawPath(f.Paths)
	if raw == "" {
		return ResolvedPath{Status: PathNoOS}
	}
	var rel relocation
	if e.Relocate {
		rel = e.relocate(f, raw)
	}
	if rel.unresolved != "" {
		return ResolvedPath{Status: PathRelocationUnresolved, RelocatedBy: rel.unresolved, RelocationIgnored: rel.ignored}
	}
	res := e.resolveRaw(raw, rel)
	res.RelocatedBy, res.RelocationIgnored = rel.env, rel.ignored
	return res
}

// resolveRaw expands raw, or takes the relocated path when a relocation
// applied (already absolute and native, so never re-rooted under
// SystemRoot), and classifies the result.
func (e PathEnv) resolveRaw(raw string, rel relocation) ResolvedPath {
	expanded, ok := rel.path, rel.applied
	if !ok {
		expanded, ok = e.expand(raw)
	}
	if !ok {
		if strings.HasPrefix(raw, "<project>") {
			return ResolvedPath{Status: PathNeedsProject}
		}
		if _, envOnly := envOnlyTokenOf(raw); envOnly {
			return ResolvedPath{Status: PathEnvUnset}
		}
		return ResolvedPath{Status: PathNoOS}
	}
	switch {
	case strings.ContainsAny(raw, "*?["):
		return ResolvedPath{Status: PathGlob, Path: expanded}
	case strings.HasSuffix(raw, "/") || strings.HasSuffix(raw, `\`):
		return ResolvedPath{Status: PathDirectory, Path: expanded}
	}
	return ResolvedPath{Status: PathResolved, Path: expanded}
}

// expand replaces the leading token (if any). A path with no token that is
// absolute is a system path (re-rooted under SystemRoot); a relative path
// with no token is project-relative (guidance rows store "CLAUDE.md").
func (e PathEnv) expand(raw string) (string, bool) {
	for _, t := range pathTokens {
		if raw == t.Token || strings.HasPrefix(raw, t.Token+"/") || strings.HasPrefix(raw, t.Token+`\`) {
			base := t.Expand(e)
			if base == "" {
				return "", false
			}
			rest := strings.TrimPrefix(raw, t.Token)
			return e.Join(base, rest), true
		}
	}
	if strings.HasPrefix(raw, "/") || (len(raw) >= 3 && raw[1] == ':' && (raw[2] == '\\' || raw[2] == '/')) {
		return e.native(e.system(raw)), true
	}
	if e.Project == "" {
		return "", false
	}
	return e.Join(e.Project, raw), true
}

// MatchGlob reports whether a slash-separated relative path matches a
// guidance-style glob: "*" matches within one segment, "**" matches zero or
// more segments, "?" one character. Both inputs use "/" separators.
func MatchGlob(pattern, rel string) bool {
	return matchSegs(strings.Split(pattern, "/"), strings.Split(rel, "/"))
}

func matchSegs(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			if len(pat) == 1 {
				return true
			}
			for i := 0; i <= len(segs); i++ {
				if matchSegs(pat[1:], segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 || !matchSeg(pat[0], segs[0]) {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0
}

// matchSeg matches one segment with * and ? wildcards.
func matchSeg(p, s string) bool {
	if p == "" {
		return s == ""
	}
	switch p[0] {
	case '*':
		for i := 0; i <= len(s); i++ {
			if matchSeg(p[1:], s[i:]) {
				return true
			}
		}
		return false
	case '?':
		return s != "" && matchSeg(p[1:], s[1:])
	}
	return s != "" && s[0] == p[0] && matchSeg(p[1:], s[1:])
}
