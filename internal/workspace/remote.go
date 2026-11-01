package workspace

import (
	"fmt"
	"regexp"
	"strings"
)

// transportHelperRE matches the <name> of git's <name>::<address> remote
// helper syntax (a URL scheme-like word: letters, digits, +, -, .).
var transportHelperRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+.-]*$`)

// ValidateRemoteURL is the RCE guard for a daemon-run `git clone <url>`
// (docs/plans/b9-sandboxed-terminals-implementation-plan-2026-08-08.md
// §4: SourceCloneRemote runs host-side with the operator's ambient git
// auth). It rejects the git-transport shapes known to grant arbitrary
// command execution or path/credential smuggling, allows only the three
// grounded remote shapes (https://, ssh://, scp-form user@host:path),
// and — when allowedHosts is non-empty — enforces a host allow-list.
//
// It never touches the filesystem or a subprocess. The caller is
// responsible for always placing "--" before the validated URL in the
// composed argv; Plan does this for every clone-remote Step it builds.
func ValidateRemoteURL(url string, allowedHosts []string) error {
	if url == "" {
		return fmt.Errorf("workspace.ValidateRemoteURL: empty URL")
	}
	if err := validateNoControlOrWhitespace("RemoteURL", url); err != nil {
		return err
	}
	if strings.HasPrefix(url, "-") {
		// Flag injection: a URL passed as a bare argv token that starts
		// with '-' could be parsed as an option instead of a positional
		// argument by a caller that forgets "--".
		return fmt.Errorf("workspace.ValidateRemoteURL: %q must not begin with '-'", url)
	}
	if strings.HasPrefix(url, "ext::") {
		// git's "ext::" transport execs an arbitrary shell command as the
		// "clone" — a real RCE, not a hardening nicety.
		return fmt.Errorf("workspace.ValidateRemoteURL: %q uses the ext:: transport (arbitrary command execution) and is refused", url)
	}
	if helper, _, ok := strings.Cut(url, "::"); ok && transportHelperRE.MatchString(helper) {
		// git reads <name>::<address> as "run git-remote-<name>" (fd::,
		// testgit::, any helper on PATH), the same shape as ext:: with a
		// different program (RB1 sweep finding S2).
		return fmt.Errorf("workspace.ValidateRemoteURL: %q names the git transport helper %q and is refused", url, helper)
	}
	if strings.HasPrefix(url, "file://") {
		// A "remote" that is actually a local path smuggles filesystem
		// access past the remote-clone gate.
		return fmt.Errorf("workspace.ValidateRemoteURL: %q uses file:// (local-path smuggling as a \"remote\") and is refused", url)
	}
	if strings.Contains(url, "--upload-pack=") || strings.Contains(url, "--receive-pack=") {
		// git-remote-http/ssh honor an embedded --upload-pack/
		// --receive-pack override to run an arbitrary program on the
		// remote side of the transport.
		return fmt.Errorf("workspace.ValidateRemoteURL: %q embeds an --upload-pack/--receive-pack override and is refused", url)
	}

	host, err := hostOf(url)
	if err != nil {
		return err
	}
	if host == "" {
		return fmt.Errorf("workspace.ValidateRemoteURL: %q has no host", url)
	}
	if len(allowedHosts) > 0 {
		ok := false
		for _, h := range allowedHosts {
			if strings.EqualFold(h, host) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("workspace.ValidateRemoteURL: host %q is not in remote_allowed_hosts", host)
		}
	}
	return nil
}

// hostOf extracts the host component from an https://, ssh://, or
// scp-form (user@host:path) git remote URL — the only three shapes
// ValidateRemoteURL allows through. Every other scheme (http://, git://,
// unknown) is refused rather than guessed at, matching the closed-
// vocabulary discipline used elsewhere in this codebase.
func hostOf(url string) (string, error) {
	switch {
	case strings.HasPrefix(url, "https://"):
		return hostFromURLForm(url, len("https://")), nil
	case strings.HasPrefix(url, "ssh://"):
		return hostFromURLForm(url, len("ssh://")), nil
	default:
		host, ok := hostFromSCPForm(url)
		if !ok {
			return "", fmt.Errorf("workspace.ValidateRemoteURL: %q is not a recognized https://, ssh://, or scp-form (user@host:path) remote", url)
		}
		return host, nil
	}
}

// hostFromURLForm extracts the host (stripping userinfo and port) from a
// URL-form remote once its scheme prefix length is known.
func hostFromURLForm(url string, prefixLen int) string {
	rest := url[prefixLen:]
	if slash := strings.Index(rest, "/"); slash >= 0 {
		rest = rest[:slash]
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	if colon := strings.Index(rest, ":"); colon >= 0 {
		rest = rest[:colon]
	}
	return rest
}

// hostFromSCPForm extracts the host from a bare scp-form remote
// ([user@]host:path), rejecting anything with an unrecognized scheme and
// a Windows drive-letter path (e.g. "C:\repo") that would otherwise look
// like a one-character "host" — filepath.IsAbs is host-OS-only, so a
// Windows-shaped absolute path reads as relative (and thus ambiguous)
// under WSL/Linux.
func hostFromSCPForm(url string) (string, bool) {
	if strings.Contains(url, "://") {
		return "", false
	}
	idx := strings.Index(url, ":")
	if idx <= 0 {
		return "", false
	}
	if strings.HasPrefix(url[idx+1:], `\`) {
		return "", false
	}
	hostPart := url[:idx]
	if at := strings.LastIndex(hostPart, "@"); at >= 0 {
		hostPart = hostPart[at+1:]
	}
	if hostPart == "" {
		return "", false
	}
	return hostPart, true
}

// repoLeafFromURL derives a candidate workspace directory name from a
// git remote URL's final path segment (URL-form or scp-form), stripping
// a trailing ".git" suffix. It returns "" when the URL has no path
// segment to derive a name from — mintDest rejects that as an invalid
// repoLeaf rather than fabricate one.
func repoLeafFromURL(u string) string {
	rest := u
	if idx := strings.Index(rest, "://"); idx >= 0 {
		rest = rest[idx+3:]
	}
	if slash := strings.Index(rest, "/"); slash >= 0 {
		rest = rest[slash+1:]
	} else if colon := strings.Index(rest, ":"); colon >= 0 {
		rest = rest[colon+1:]
	} else {
		// Neither a URL-form path nor an scp-form colon: there is no
		// path component to derive a name from.
		return ""
	}
	rest = strings.TrimRight(rest, "/")
	if slash := strings.LastIndex(rest, "/"); slash >= 0 {
		rest = rest[slash+1:]
	}
	rest = strings.TrimSuffix(rest, ".git")
	return rest
}
