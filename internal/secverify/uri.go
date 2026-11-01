package secverify

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"
)

// MaxPathBytes caps a project-relative path (security plan 4.5.3).
const MaxPathBytes = 512

// ErrPathRefused is returned for a path verify will not put in a report.
var ErrPathRefused = errors.New("secverify: path refused")

// ValidRelPath reports whether p is a clean project-relative path: valid
// UTF-8, at most MaxPathBytes, no control character, no backslash, not
// absolute, no drive letter, no empty, "." or ".." segment.
func ValidRelPath(p string) error {
	switch {
	case p == "":
		return fmt.Errorf("%w: empty", ErrPathRefused)
	case len(p) > MaxPathBytes:
		return fmt.Errorf("%w: over %d bytes", ErrPathRefused, MaxPathBytes)
	case !utf8.ValidString(p):
		return fmt.Errorf("%w: not valid UTF-8", ErrPathRefused)
	case strings.HasPrefix(p, "/"):
		return fmt.Errorf("%w: absolute", ErrPathRefused)
	case strings.ContainsRune(p, '\\'):
		return fmt.Errorf("%w: backslash", ErrPathRefused)
	case len(p) >= 2 && p[1] == ':':
		return fmt.Errorf("%w: drive letter", ErrPathRefused)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return fmt.Errorf("%w: control character", ErrPathRefused)
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("%w: empty, . or .. segment", ErrPathRefused)
		}
	}
	return nil
}

// ProjectRelPath turns what a detector reports into a project-relative
// path, or refuses it. root is the project root as an absolute path with
// forward slashes ("/home/runner/work/x" or "C:/work/x"). The accepted
// inputs are a relative path, an absolute path under root, and a file: URI
// (empty or "localhost" host) whose path is under root; an absolute file://
// prefix under the root is stripped so no local path reaches a report
// (JSP-8, JSP-12). Every other scheme, a host, a path outside root and a
// path that fails ValidRelPath are refused.
func ProjectRelPath(root, p string) (string, error) {
	if len(p) >= 5 && strings.EqualFold(p[:5], "file:") {
		u, err := url.Parse(p)
		if err != nil {
			return "", fmt.Errorf("%w: unreadable URI", ErrPathRefused)
		}
		if u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
			return "", fmt.Errorf("%w: file URI with a host", ErrPathRefused)
		}
		if u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" {
			return "", fmt.Errorf("%w: file URI with extra parts", ErrPathRefused)
		}
		p = u.Path
		// file:///C:/x arrives as "/C:/x".
		if len(p) >= 3 && p[0] == '/' && isDrivePath(p[1:]) {
			p = p[1:]
		}
		if !strings.HasPrefix(p, "/") && !isDrivePath(p) {
			return "", fmt.Errorf("%w: relative file URI", ErrPathRefused)
		}
	}
	if strings.HasPrefix(p, "/") || isDrivePath(p) {
		rel, ok := underRoot(root, p)
		if !ok {
			return "", fmt.Errorf("%w: outside the project root", ErrPathRefused)
		}
		p = rel
	}
	if strings.Contains(p, "://") {
		// Any other URI (https://, ssh://) is remote; "ab:c.txt" without
		// "//" is a legal relative file name and falls through.
		return "", fmt.Errorf("%w: remote URI", ErrPathRefused)
	}
	if err := ValidRelPath(p); err != nil {
		return "", err
	}
	return p, nil
}

func isDrivePath(p string) bool {
	return len(p) >= 3 && p[1] == ':' && p[2] == '/' &&
		((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z'))
}

// underRoot returns p relative to root when p is lexically inside it. A
// drive letter compares without case; everything else is exact.
func underRoot(root, p string) (string, bool) {
	if root == "" || strings.Contains(p, "\\") {
		return "", false
	}
	root = strings.TrimSuffix(path.Clean(root), "/")
	cp := path.Clean(p)
	if cp != p && cp+"/" != p {
		// A path that cleaning changes held "." or ".." segments.
		return "", false
	}
	if isDrivePath(root) && isDrivePath(cp) {
		if !strings.EqualFold(root[:1], cp[:1]) {
			return "", false
		}
		root, cp = root[1:], cp[1:]
	}
	if !strings.HasPrefix(cp, root+"/") {
		return "", false
	}
	return cp[len(root)+1:], true
}

// RelURI renders a project-relative path as a SARIF artifactLocation.uri
// relative to %SRCROOT%: each segment percent-encoded, slashes kept.
func RelURI(rel string) string {
	segs := strings.Split(rel, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// maxQuoted is the cap on a path quoted into human-facing text (the deny
// text convention of security plan 6.1).
const maxQuoted = 80

// QuotePath renders a repository path for a summary line: characters
// outside letters, digits, "/", ".", "_" and "-" become "?", the result is
// cut to 80 characters and wrapped in double quotes. A file name is text
// the repository controls, so it is never printed raw.
func QuotePath(p string) string {
	var b strings.Builder
	n := 0
	for _, r := range p {
		if n == maxQuoted {
			b.WriteString("...")
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '/', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
		n++
	}
	return `"` + b.String() + `"`
}

// clipSafe is QuotePath without the quotes and with a caller-chosen cap,
// for short tokens in error text.
func clipSafe(s string, max int) string {
	var b strings.Builder
	for i, r := range s {
		if i >= max {
			break
		}
		if r < 0x20 || r == 0x7f || r > 0x7e {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
