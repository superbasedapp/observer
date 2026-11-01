package pathnorm

import (
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Format records which layer of the pipeline triggered for a given
// input. The OUTERMOST detected format is reported — a `file://`
// URI that decodes to a Windows drive-letter path returns
// FormatFileURI, not FormatWindowsDrive. Callers who want the inner
// format must re-Normalize the intermediate string.
//
// Used for adapter telemetry and debugging when normalisation
// produces unexpected output.
type Format int

const (
	// FormatUnknown — pipeline ran but no layer matched. The output
	// equals the (trimmed) input.
	FormatUnknown Format = iota
	// FormatEmpty — input was empty or whitespace-only.
	FormatEmpty
	// FormatPOSIXAbsolute — input started with `/` and didn't match
	// any more-specific layer.
	FormatPOSIXAbsolute
	// FormatWSLMnt — input was already a canonical /mnt/<drive>/...
	// path (no rewrite applied, just classified).
	FormatWSLMnt
	// FormatWindowsDrive — input looked like `C:\foo`, `C:/foo`,
	// `c:\foo`, or the URI fsPath spelling `/c:/foo`, and was
	// rewritten to /mnt/c/foo on non-Windows.
	FormatWindowsDrive
	// FormatGitBashDrive — input started with `/c/`, `/d/`, etc.
	// (Git Bash drive prefix) and was rewritten to /mnt/c/, /mnt/d/,
	// etc. on non-Windows.
	FormatGitBashDrive
	// FormatFileURI — input started with `file://` (case-insensitive)
	// and the path component was percent-decoded.
	FormatFileURI
	// FormatUNCWSL — input was `\\wsl.localhost\<distro>\...` or
	// `\\wsl$\<distro>\...` and matched $WSL_DISTRO_NAME, so it was
	// rewritten to a regular POSIX path inside the current WSL.
	FormatUNCWSL
	// FormatUNCGeneric — input started with `\\` but didn't match the
	// WSL-specific UNC patterns. Passed through unchanged.
	FormatUNCGeneric
	// FormatExtendedLength — input started with the Windows extended-
	// length prefix `\\?\`. The prefix was stripped and the result
	// re-processed by subsequent layers.
	FormatExtendedLength
	// FormatTilde — input started with `~/` or was exactly `~`. The
	// tilde was expanded to $HOME on POSIX hosts.
	FormatTilde
	// FormatRelative — input didn't start with any absolute-path
	// marker. Could be `./foo`, `../bar`, or a bare filename.
	FormatRelative
	// FormatQuoted — input was surrounded by matched single or double
	// quotes. The inner content was re-processed by subsequent
	// layers; FormatQuoted is returned to signal that the surface
	// shape involved quoting.
	FormatQuoted
)

// String returns a stable lowercase label for each Format. Used by
// adapter telemetry — should remain ASCII + lowercase so existing
// log-grep patterns keep working.
func (f Format) String() string {
	switch f {
	case FormatEmpty:
		return "empty"
	case FormatPOSIXAbsolute:
		return "posix"
	case FormatWSLMnt:
		return "wsl-mnt"
	case FormatWindowsDrive:
		return "windows-drive"
	case FormatGitBashDrive:
		return "git-bash-drive"
	case FormatFileURI:
		return "file-uri"
	case FormatUNCWSL:
		return "unc-wsl"
	case FormatUNCGeneric:
		return "unc-generic"
	case FormatExtendedLength:
		return "extended-length"
	case FormatTilde:
		return "tilde"
	case FormatRelative:
		return "relative"
	case FormatQuoted:
		return "quoted"
	default:
		return "unknown"
	}
}

// Normalize converts p to a canonical path the current process can
// use for filesystem operations. NEVER returns an error — every
// layer has a pass-through fallback so unrecognised inputs end up
// the same as they would today.
//
// Most callers want this variant; reach for NormalizeWithFormat when
// you need to telemeter or branch on the detected source format.
func Normalize(p string) string {
	out, _ := NormalizeWithFormat(p)
	return out
}

// foreignFormats are the outermost formats NormalizeForeign accepts a
// rewrite for: shapes that can never name a native path on a POSIX
// host (a drive letter, a file URI, the `\\?\` prefix, a same-distro
// WSL UNC share). The native-looking rewrites (Git Bash `/c/`, `~`,
// surrounding quotes) are left out, because `/c/x` and `~x` are also
// legal POSIX directory names.
var foreignFormats = map[Format]bool{
	FormatWindowsDrive:   true,
	FormatFileURI:        true,
	FormatExtendedLength: true,
	FormatUNCWSL:         true,
}

// NormalizeForeign is the strict variant of Normalize for identity
// keys such as a project root: it rewrites p only when p is
// unmistakably a foreign or URI spelling (see foreignFormats) and
// returns every other input byte-for-byte unchanged, so a native path
// never changes identity. A rewritten result is lexically cleaned
// (trailing separator, `.` and `..` segments), so `C:\foo\` and
// `C:/foo` land on one key.
func NormalizeForeign(p string) string {
	out, format := NormalizeWithFormat(p)
	if !foreignFormats[format] || out == "" || out == p {
		return p
	}
	if runtime.GOOS == "windows" {
		return filepath.Clean(out)
	}
	return path.Clean(out)
}

// NormalizeWithFormat runs the same pipeline as Normalize and also
// returns the outermost detected Format. See package doc for the
// pipeline order.
func NormalizeWithFormat(p string) (string, Format) {
	if p == "" {
		return "", FormatEmpty
	}

	// Layer 1 — trim whitespace.
	p = strings.TrimSpace(p)
	if p == "" {
		return "", FormatEmpty
	}

	// Layer 2 — strip matched surrounding quotes. Record the format
	// only if at least one pair was stripped; the rest of the
	// pipeline classifies the inner content.
	format := FormatUnknown
	stripped, didStrip := stripMatchedQuotes(p)
	if didStrip {
		format = FormatQuoted
		p = stripped
		if p == "" {
			return "", FormatEmpty
		}
	}

	// Layer 3 — file:// URI.
	if isFileURI(p) {
		if decoded, ok := decodeFileURIPath(p); ok {
			p = decoded
			if format == FormatUnknown {
				format = FormatFileURI
			}
		}
	}

	// Layer 4 — Windows extended-length prefix `\\?\`. Strip and
	// continue; the inner is typically a regular drive-letter path
	// that the next layers will catch.
	if strings.HasPrefix(p, `\\?\`) {
		p = p[4:]
		if format == FormatUnknown {
			format = FormatExtendedLength
		}
	}

	// Layer 5 — UNC-to-WSL rewrite. Best-effort: only rewrites when
	// the embedded distro name matches the running $WSL_DISTRO_NAME.
	if rewritten, ok := rewriteUNCtoWSL(p); ok {
		p = rewritten
		if format == FormatUnknown {
			format = FormatUNCWSL
		}
	}

	// Layer 6 — Git Bash drive prefix `/c/Users/...` → `/mnt/c/Users/...`
	// on non-Windows.
	if rewritten, ok := rewriteGitBashDrive(p); ok {
		p = rewritten
		if format == FormatUnknown {
			format = FormatGitBashDrive
		}
	}

	// Layer 7 — Windows drive-letter absolute → /mnt/<drive>/...
	// on non-Windows.
	//
	// 7a. Strip the spurious leading slash a URI fsPath carries in
	// front of the drive letter (`/c:/foo`). This is the same slash
	// decodeFileURIPath already removes inside a `file://` URI; it
	// also reaches us bare, because VS Code / Cursor hook payloads
	// hand out `Uri.fsPath`-shaped roots directly. Stripping it here
	// makes `/c:/programsx/foo` land on the SAME canonical
	// `/mnt/c/programsx/foo` as `C:\programsx\foo` and
	// `/mnt/c/programsx/foo`, instead of splitting project identity
	// across two spellings of one directory. The extra
	// looksLikeWindowsDriveAbsolute guard makes the strip
	// all-or-nothing: we never leave a half-transformed path behind
	// (it is redundant given the regex, and kept as a cheap
	// invariant).
	if stripped, ok := stripURIDriveSlash(p); ok && looksLikeWindowsDriveAbsolute(stripped) {
		p = stripped
	}
	if looksLikeWindowsDriveAbsolute(p) {
		p = windowsToWSLMnt(p)
		if format == FormatUnknown {
			format = FormatWindowsDrive
		}
	}

	// Layer 8 — tilde expansion. Bounded — only `~/` and bare `~`.
	// We deliberately do NOT expand `~user/...` (requires user DB
	// lookup) or `$VAR/...` (security risk: env may contain
	// secrets).
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if p == "~" {
				p = home
			} else {
				p = home + p[1:]
			}
			if format == FormatUnknown {
				format = FormatTilde
			}
		}
	}

	// Layer 9 — classify the (possibly transformed) result if no
	// earlier layer claimed ownership.
	if format == FormatUnknown {
		format = classify(p)
	}

	return p, format
}

// stripMatchedQuotes peels off matched ASCII single-quote or
// double-quote pairs from both ends of s. Iterates so nested wrapping
// (`'"…"'`) is fully unwrapped. Aborts if the result would be empty.
// Returns the unwrapped string and whether at least one pair was
// removed.
//
// Conservative — does NOT interpret escape sequences inside the
// quoted region (those were already JSON-unescaped by json.Unmarshal
// before the string reached us). A path containing a LITERAL outer
// quote pair (rare: filenames like `'foo.txt'`) would be incorrectly
// stripped; this trade-off is intentional because the common case in
// observer data is paths that arrived double-quoted by an upstream
// tool's shell-evaluator.
func stripMatchedQuotes(s string) (string, bool) {
	stripped := false
	for len(s) >= 2 {
		first := s[0]
		last := s[len(s)-1]
		if first != last {
			break
		}
		if first != '\'' && first != '"' {
			break
		}
		inner := s[1 : len(s)-1]
		if strings.TrimSpace(inner) == "" {
			// Don't strip if the result would be empty/whitespace —
			// could be an intentional empty-string sentinel.
			break
		}
		s = inner
		stripped = true
	}
	return s, stripped
}

// isFileURI reports whether s starts with a case-insensitive `file:`
// scheme followed by a slash: the authority form `file://...` and the
// RFC 8089 authority-less form `file:/C:/...` alike.
func isFileURI(s string) bool {
	if len(s) < 6 {
		return false
	}
	return strings.EqualFold(s[:5], "file:") && s[5] == '/'
}

// decodeDriveAuthorityURI handles the malformed `file://C:\foo` shape:
// a caller that builds a URI by prefixing `file://` to a bare Windows
// path puts the drive letter where the authority belongs, which
// url.Parse rejects (`\foo` is not a port). The remainder is the path.
// Live, the antigravity-cli launch-workspace fallback produced it, and
// the unparsed URI reached filepath.Abs, which joined it onto the
// daemon's cwd as `/home/<user>/file:/C:\...`.
func decodeDriveAuthorityURI(uri string) (string, bool) {
	if len(uri) < 7 || !strings.EqualFold(uri[:7], "file://") {
		return "", false
	}
	rest := uri[7:]
	if !looksLikeWindowsDriveAbsolute(rest) {
		return "", false
	}
	if decoded, err := url.PathUnescape(rest); err == nil {
		return decoded, true
	}
	return rest, true
}

// windowsDrivePathRE matches a leading `/X:/` (forward-slash drive
// letter) — used inside file:// URIs to strip the leading slash that
// appears between `file://` and `D:/foo`.
var windowsDrivePathRE = regexp.MustCompile(`^/[A-Za-z]:/`)

// decodeFileURIPath parses uri as a file:// URI, percent-decodes the
// path component, and strips the leading slash before a drive letter
// (`/D:/foo` → `D:/foo`). Returns (path, true) on success.
func decodeFileURIPath(uri string) (string, bool) {
	if p, ok := decodeDriveAuthorityURI(uri); ok {
		return p, true
	}
	u, err := url.Parse(uri)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(u.Scheme, "file") {
		return "", false
	}
	p, err := url.PathUnescape(u.Path)
	if err != nil {
		return "", false
	}
	if windowsDrivePathRE.MatchString(p) {
		p = p[1:]
	}
	return p, true
}

// rewriteUNCtoWSL detects `\\wsl.localhost\<distro>\<rest>` or
// `\\wsl$\<distro>\<rest>` and rewrites to `/<rest>` (forward-slash
// normalised) when the distro matches the running observer's
// $WSL_DISTRO_NAME on a Linux host. Returns the rewritten path and
// true on success.
//
// Best-effort: when the distro doesn't match (foreign WSL instance,
// or running outside WSL entirely), returns the input and false so
// the pipeline classifies it as FormatUNCGeneric.
func rewriteUNCtoWSL(p string) (string, bool) {
	if runtime.GOOS != "linux" {
		return p, false
	}
	currentDistro := os.Getenv("WSL_DISTRO_NAME")
	if currentDistro == "" {
		return p, false
	}

	var rest string
	switch {
	case strings.HasPrefix(p, `\\wsl.localhost\`):
		rest = p[len(`\\wsl.localhost\`):]
	case strings.HasPrefix(p, `\\wsl$\`):
		rest = p[len(`\\wsl$\`):]
	default:
		return p, false
	}

	sep := strings.IndexAny(rest, `\/`)
	if sep < 0 {
		// `\\wsl.localhost\Ubuntu` alone (no trailing path) — drops
		// to root if distro matches.
		if strings.EqualFold(rest, currentDistro) {
			return "/", true
		}
		return p, false
	}
	distro := rest[:sep]
	inner := rest[sep+1:]
	if !strings.EqualFold(distro, currentDistro) {
		return p, false
	}
	inner = strings.ReplaceAll(inner, `\`, "/")
	return "/" + inner, true
}

// gitBashDriveRE matches a leading `/<letter>/` (Git Bash drive
// prefix). Letter is one ASCII char; followed by `/` so the pattern
// doesn't false-match a single-letter directory like `/c` alone.
var gitBashDriveRE = regexp.MustCompile(`^/[a-zA-Z]/`)

// rewriteGitBashDrive converts `/c/Users/foo` to `/mnt/c/Users/foo`
// on non-Windows hosts. Drive letter lowercased to match the
// /mnt/<lower> convention WSL2 uses.
//
// On Windows, `/c/foo` is unusual enough that we leave it alone
// (a future Windows-specific layer could handle it, but no caller
// has needed it yet).
func rewriteGitBashDrive(p string) (string, bool) {
	if runtime.GOOS == "windows" {
		return p, false
	}
	if !gitBashDriveRE.MatchString(p) {
		return p, false
	}
	drive := strings.ToLower(string(p[1]))
	return "/mnt/" + drive + p[2:], true
}

// uriDriveSlashRE matches a leading `/` followed by a drive-letter
// absolute path — `/c:/foo`, `/C:/foo`, `/c:\foo`. Anchored, exactly
// one ASCII letter, a literal colon, then a separator, so the shapes
// that merely LOOK similar never match: `/cache/foo` (letter run > 1,
// no colon), `/c/foo` (Git Bash — owned by layer 6), bare `/c`,
// `/c:` with no separator, `/cc:/foo`, `/1:/foo`, `//c:/foo`.
//
// Detection is deliberately LEXICAL. filepath.IsAbs is host-only —
// on a Linux/WSL host `C:\foo` reads as a relative path — so a
// host-aware predicate would silently stop recognising foreign shapes
// depending on where observer runs.
var uriDriveSlashRE = regexp.MustCompile(`^/[A-Za-z]:[\\/]`)

// stripURIDriveSlash removes the leading slash of a `/<drive>:/...`
// URI fsPath so the drive-letter layer can claim it. Returns the
// input and false when the shape doesn't match.
//
// Host-independent by design: it is a spelling fix, not an OS
// translation, so it runs on Windows too (where `/c:/foo` becomes the
// natively-usable `c:/foo` and windowsToWSLMnt then passes it
// through). No distinct Format is reported — the result IS a Windows
// drive path and is classified FormatWindowsDrive, mirroring how the
// identical slash-strip inside decodeFileURIPath reports the format
// of its OUTER layer rather than minting one of its own.
func stripURIDriveSlash(p string) (string, bool) {
	if !uriDriveSlashRE.MatchString(p) {
		return p, false
	}
	return p[1:], true
}

// looksLikeWindowsDriveAbsolute reports whether p starts with a
// drive-letter absolute path (`C:\`, `C:/`, `c:\`, `c:/`). Mirrors
// the original crossmount.looksLikeWindowsPath logic.
func looksLikeWindowsDriveAbsolute(p string) bool {
	if len(p) < 3 {
		return false
	}
	c := p[0]
	if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		return false
	}
	if p[1] != ':' {
		return false
	}
	return p[2] == '\\' || p[2] == '/'
}

// windowsToWSLMnt converts `C:\Users\foo` to `/mnt/c/Users/foo` on
// non-Windows. Drive letter lowercased; backslashes converted to
// forward slashes. On Windows, returns the input unchanged
// (filepath.Abs handles drive letters natively).
func windowsToWSLMnt(p string) string {
	if runtime.GOOS == "windows" {
		return p
	}
	drive := strings.ToLower(string(p[0]))
	rest := strings.ReplaceAll(p[3:], "\\", "/")
	return "/mnt/" + drive + "/" + rest
}

// classify assigns a Format to a string that no earlier layer
// claimed. Pure inspection — no transformation.
func classify(p string) Format {
	switch {
	case p == "":
		return FormatEmpty
	case strings.HasPrefix(p, "/mnt/"):
		return FormatWSLMnt
	case strings.HasPrefix(p, `\\`):
		return FormatUNCGeneric
	case strings.HasPrefix(p, "/"):
		return FormatPOSIXAbsolute
	default:
		return FormatRelative
	}
}
