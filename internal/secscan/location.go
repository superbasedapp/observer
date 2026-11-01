package secscan

import (
	"net/url"
	"path"
	"strings"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// LocationReason is why a reported location was refused.
type LocationReason string

// The LocationReason values.
const (
	LocOK          LocationReason = ""
	LocEmpty       LocationReason = "empty"
	LocRemote      LocationReason = "remote_uri"
	LocOutsideRoot LocationReason = "outside_project_root"
	LocTraversal   LocationReason = "path_traversal"
	LocTooLong     LocationReason = "path_too_long"
	LocBadChars    LocationReason = "bad_characters"
	LocBadEncoding LocationReason = "bad_encoding"
)

// slashRoot is a project root in forward-slash form with no trailing
// slash, and whether it is a Windows drive path (compared without case).
func slashRoot(root string) (string, bool) {
	r := strings.ReplaceAll(root, `\`, "/")
	for len(r) > 1 && strings.HasSuffix(r, "/") {
		r = strings.TrimSuffix(r, "/")
	}
	return r, isDrive(r)
}

func isDrive(p string) bool {
	return len(p) >= 2 && p[1] == ':' && unicode.IsLetter(rune(p[0]))
}

// isScheme reports whether s is a URI scheme (RFC 3986: a letter, then
// letters, digits, "+", "-" or "."). A relative path such as "src/a:b.go"
// is not one, so it is not read as a remote URI.
func isScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return s != ""
}

// underRoot reports whether the cleaned path p is the cleaned root or lies
// under it. A drive root compares without case, with strings.EqualFold
// over the original bytes, so the root's byte length stays the length of
// the prefix it matched (case folding never changes how p is sliced).
func underRoot(p, root string, fold bool) bool {
	if len(p) < len(root) {
		return false
	}
	head := p[:len(root)]
	if fold {
		if !strings.EqualFold(head, root) {
			return false
		}
	} else if head != root {
		return false
	}
	return len(p) == len(root) || strings.HasSuffix(root, "/") || p[len(root)] == '/'
}

// NormalizeLocation turns a reported artifact URI into a project-relative
// path, or refuses it (section 4.5.3, revision 2.4 [JSP-8, JSP-12]): a
// remote URI is refused; a file: URI or an absolute path is accepted only
// under the project root and made relative (Bandit's file:/// for an
// absolute target, osv-scanner's absolute file:// locations); no "..";
// at most secfinding.MaxPath bytes; no control characters. A relative
// path is taken against the project root. Code that later opens a
// reported path opens it through os.Root, never directly.
func NormalizeLocation(uri, projectRoot string) (string, LocationReason) {
	u := strings.TrimSpace(uri)
	if u == "" {
		return "", LocEmpty
	}
	for _, r := range u {
		if unicode.IsControl(r) {
			return "", LocBadChars
		}
	}
	p := u
	if i := strings.Index(u, ":"); i > 1 && isScheme(u[:i]) {
		scheme := strings.ToLower(u[:i])
		if scheme != "file" {
			return "", LocRemote
		}
		rest := u[i+1:]
		if strings.HasPrefix(rest, "//") {
			rest = rest[2:]
			host, after, _ := strings.Cut(rest, "/")
			if host != "" && !strings.EqualFold(host, "localhost") {
				return "", LocRemote
			}
			rest = "/" + after
		}
		dec, err := url.PathUnescape(rest)
		if err != nil {
			return "", LocBadEncoding
		}
		p = dec
		// file:///C:/x is the drive path C:/x.
		if len(p) >= 3 && p[0] == '/' && isDrive(p[1:]) {
			p = p[1:]
		}
	} else if dec, err := url.PathUnescape(u); err == nil {
		p = dec
	} else {
		return "", LocBadEncoding
	}
	p = strings.ReplaceAll(p, `\`, "/")
	if strings.ContainsRune(p, 0) {
		return "", LocBadChars
	}
	if strings.HasPrefix(p, "/") || isDrive(p) {
		root, drive := slashRoot(projectRoot)
		if root == "" {
			return "", LocOutsideRoot
		}
		cp := path.Clean(p)
		cr := path.Clean(root)
		if !underRoot(cp, cr, drive) {
			return "", LocOutsideRoot
		}
		p = strings.TrimPrefix(cp[len(cr):], "/")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", LocTraversal
		}
	}
	p = path.Clean(p)
	if p == "." || p == "" {
		return "", LocEmpty
	}
	if len(p) > secfinding.MaxPath {
		return "", LocTooLong
	}
	return p, LocOK
}
