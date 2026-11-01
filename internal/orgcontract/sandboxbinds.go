package orgcontract

import (
	"path"
	"strings"
)

// sandboxbinds.go is the sensitive-location rule for a WRITE bind the sandbox
// managed pull carries (orchestrator decision at the SBX-P1C merge,
// docs/security.md SBX-GOV-3). A per-node write bind is a remote lever out of
// the sandbox, so one that is, lies under, or holds (an ancestor of a
// denied location, which exposes it: orchestrator ruling P-050, the home
// directory itself, /, /home, a .git directory) a location below is refused
// by name: at publish lint (Validate, so the server never stores or serves it)
// and again on the node, with its real home and Observer directory, when it
// composes the body (cmd/observer/sandbox_managed.go). A read-only bind is not
// checked here. The rule is a closed table walked top down (CLAUDE.md #5).
//
// Ruling P-054 (the SBX-P2E merge, audit finding 7): the comparison is
// case-insensitive where the platform or the mount is (macOS, Windows, a WSL
// Windows drive mount /mnt/<letter>, and the org server, which cannot know a
// node's platform), and WSL's Windows mounts are equivalents of the POSIX
// locations: /mnt and /mnt/<letter> hold homes, /mnt/<letter>/Users holds
// homes, /mnt/<letter>/Users/<name> is a home (its denied entries, AppData
// among them, are the home table below), and /mnt/<letter>/Windows and
// /mnt/<letter>/Program Files* are system directories. A Windows drive
// spelling (C:/...) is checked as its /mnt/<letter> equivalent.

// SandboxRefusedSensitivePath is the refusal reason of such a bind.
const SandboxRefusedSensitivePath SandboxManagedRefusal = "sensitive_host_path"

// SandboxBindHost is what the rule knows about the host. The zero value is
// the org server's view: no real home, so the home-shaped spellings (~,
// /root, /home/<user>, /Users/<user>, /mnt/<letter>/Users/<user>) stand for
// a home, and paths compare case-insensitively (the server cannot know the
// node's platform).
type SandboxBindHost struct {
	// Home is the node's real home directory, slash-separated ("" when
	// unknown).
	Home string
	// Known says the host facts are the node's own. A path under
	// <home>/.config (other than .config/fish) is then allowed only when the
	// developer's own block already binds it read-write (LocalRWBinds);
	// without them (the server) such a path is left to the node to decide.
	Known bool
	// LocalRWBinds are the developer's own [terminal.sandbox].extra_rw_binds,
	// slash-separated.
	LocalRWBinds []string
	// CaseSensitive says the host compares paths case-sensitively (a node on
	// Linux). false (the zero value: the org server, a macOS or a Windows
	// node) compares case-insensitively. A path on a WSL Windows drive mount
	// (/mnt/<letter>) compares case-insensitively whatever this says.
	CaseSensitive bool
}

// sandboxSystemTops are the top-level system directories a write bind may
// never be or lie under (/lib* is matched by prefix, /var keeps /var/tmp).
var sandboxSystemTops = map[string]bool{
	"etc": true, "usr": true, "bin": true, "sbin": true, "boot": true,
	"dev": true, "proc": true, "sys": true, "var": true, "opt": true,
}

// sandboxWindowsSystemTops are the system directories of a Windows drive
// (seen from WSL at /mnt/<letter>): a name equal to, or for a "*" entry
// starting with, the entry (compared case-insensitively, as the drive is).
var sandboxWindowsSystemTops = []string{"windows", "program files*"}

// sandboxHomeSensitive are the home entries a write bind may never be or lie
// under. ".observer" is the default Observer directory; its workspaces tree
// is the one place under it a bind may show (the node's own observer-dir rule
// says the same for the configured directory). "AppData" is a Windows home's
// per-user configuration and credentials (ruling P-054).
var sandboxHomeSensitive = []string{
	".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv", ".config/fish",
	".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".local/bin",
	".npmrc", ".pypirc", ".netrc", ".gitconfig", ".git-credentials", ".observer",
	"AppData",
}

// sandboxBindPath is one path under check: the cleaned (and, when the
// comparison is case-insensitive, lowered) path and host.
type sandboxBindPath struct {
	p    string
	host SandboxBindHost
	fold bool
}

// k returns a table literal in the comparison's case.
func (v sandboxBindPath) k(s string) string {
	if v.fold {
		return strings.ToLower(s)
	}
	return s
}

// sandboxSensitiveRules is the closed rule table, walked top down.
var sandboxSensitiveRules = []struct {
	name  string
	match func(v sandboxBindPath) bool
}{
	{"the filesystem root", func(v sandboxBindPath) bool { return v.p == "/" }},
	{"a top-level system directory", func(v sandboxBindPath) bool {
		if !strings.HasPrefix(v.p, "/") {
			return false
		}
		top, _, _ := strings.Cut(strings.TrimPrefix(v.p, "/"), "/")
		if top == "var" {
			return !slashWithin(v.p, "/var/tmp")
		}
		return sandboxSystemTops[top] || strings.HasPrefix(top, "lib")
	}},
	{"a Windows system directory on a WSL drive mount", func(v sandboxBindPath) bool {
		drive, rest, ok := sandboxWSLDrive(v.p)
		if !ok || drive == "" || rest == "" {
			return false
		}
		top, _, _ := strings.Cut(rest, "/")
		for _, e := range sandboxWindowsSystemTops {
			if pre, star := strings.CutSuffix(e, "*"); star {
				if strings.HasPrefix(top, pre) {
					return true
				}
			} else if top == e {
				return true
			}
		}
		return false
	}},
	{"a git hooks or config path", func(v sandboxBindPath) bool {
		segs := strings.Split(v.p, "/")
		for i := 0; i+1 < len(segs); i++ {
			if segs[i] == ".git" && (segs[i+1] == "hooks" || segs[i+1] == "config") {
				return true
			}
		}
		return false
	}},
	{"a .git directory (it holds the hooks and config)", func(v sandboxBindPath) bool {
		return path.Base(v.p) == ".git"
	}},
	{"a home directory or a directory holding one", func(v sandboxBindPath) bool {
		return sandboxHoldsAHome(v)
	}},
	{"a directory holding a sensitive home entry", func(v sandboxBindPath) bool {
		for _, rel := range sandboxHomeRels(v) {
			for _, e := range sandboxHomeSensitive {
				if strings.HasPrefix(v.k(e), rel+"/") {
					return true
				}
			}
		}
		return false
	}},
	{"a sensitive home entry", func(v sandboxBindPath) bool {
		for _, rel := range sandboxHomeRels(v) {
			if sandboxHomeRelSensitive(v, rel) {
				return true
			}
		}
		return false
	}},
}

// sandboxWSLDrive reports whether p is /mnt itself (drive "", rest "") or on
// a WSL Windows drive mount /mnt/<letter> (drive the letter, rest the path
// below it, "" for the drive itself). The letter is matched in either case.
func sandboxWSLDrive(p string) (drive, rest string, ok bool) {
	if strings.EqualFold(p, "/mnt") {
		return "", "", true
	}
	if len(p) < len("/mnt/x") || !strings.EqualFold(p[:len("/mnt/")], "/mnt/") {
		return "", "", false
	}
	after := p[len("/mnt/"):]
	letter, below, _ := strings.Cut(after, "/")
	if len(letter) != 1 || !isASCIILetter(letter[0]) {
		return "", "", false
	}
	return letter, below, true
}

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// sandboxWindowsDriveAsWSL maps a Windows drive spelling (C:/..., checked
// after ToSlash) onto its WSL mount equivalent (/mnt/c/...), so one table
// covers both.
func sandboxWindowsDriveAsWSL(p string) string {
	if len(p) >= 2 && p[1] == ':' && isASCIILetter(p[0]) && (len(p) == 2 || p[2] == '/') {
		return path.Clean("/mnt/" + strings.ToLower(p[:1]) + "/" + p[2:])
	}
	return p
}

// sandboxHoldsAHome reports whether p is a home directory or holds one (a
// write bind of an ANCESTOR of a denied location exposes the denied entries
// under it, orchestrator ruling P-050): the node's real home and its
// parents, a home-shaped spelling (~, /root, /home/<user>, /Users/<user>,
// /mnt/<letter>/Users/<user>) and the directories that hold them (/home,
// /Users, /mnt, /mnt/<letter>, /mnt/<letter>/Users). "/" is the first row.
func sandboxHoldsAHome(v sandboxBindPath) bool {
	p := v.p
	if p == "~" || p == "/root" || p == "/home" || p == v.k("/Users") {
		return true
	}
	for _, base := range []string{"/home/", v.k("/Users/")} {
		if rest, ok := strings.CutPrefix(p, base); ok && rest != "" && !strings.Contains(rest, "/") {
			return true
		}
	}
	if drive, rest, ok := sandboxWSLDrive(p); ok {
		if drive == "" || rest == "" || rest == "users" {
			return true
		}
		if name, ok := strings.CutPrefix(rest, "users/"); ok && name != "" && !strings.Contains(name, "/") {
			return true
		}
	}
	if h := strings.TrimSpace(v.host.Home); h != "" {
		h = path.Clean(h)
		if p != "/" && slashWithin(h, p) {
			return true
		}
	}
	return false
}

// SandboxSensitiveWriteBind reports whether a write bind of p would expose a
// sensitive host location (the rule table above). p is slash-separated; a
// path that is not absolute is still checked when it is home-shaped (~/...),
// so the admin reads why rather than "not absolute".
func SandboxSensitiveWriteBind(p string, host SandboxBindHost) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	p = sandboxWindowsDriveAsWSL(path.Clean(p))
	_, _, onDrive := sandboxWSLDrive(p)
	v := sandboxBindPath{p: p, host: host, fold: !host.CaseSensitive || onDrive}
	if v.fold {
		v.p = strings.ToLower(v.p)
		if h := strings.TrimSpace(host.Home); h != "" {
			v.host.Home = strings.ToLower(sandboxWindowsDriveAsWSL(path.Clean(h)))
		}
		v.host.LocalRWBinds = nil
		for _, b := range host.LocalRWBinds {
			// The same drive spelling and case as p and the home, or a
			// Windows node's own bind ("C:/Users/u/.config/gh") never matches
			// the folded p ("/mnt/c/users/u/...") and the developer's
			// locally bound exception never applies (Windows 11 Pro rerun
			// 2026-10-25, D5 group 4).
			if b = strings.TrimSpace(b); b != "" {
				v.host.LocalRWBinds = append(v.host.LocalRWBinds, strings.ToLower(sandboxWindowsDriveAsWSL(path.Clean(b))))
			}
		}
	}
	for _, r := range sandboxSensitiveRules {
		if r.match(v) {
			return true
		}
	}
	return false
}

// sandboxHomeRels returns p relative to every home it lies under: the node's
// real home, and the home-shaped spellings (~, /root, /home/<user>,
// /Users/<user>, /mnt/<letter>/Users/<user>). The home directory itself
// yields nothing.
func sandboxHomeRels(v sandboxBindPath) []string {
	p := v.p
	var out []string
	add := func(home string) {
		if rel, ok := slashRel(p, home); ok && rel != "" {
			out = append(out, rel)
		}
	}
	if h := strings.TrimSpace(v.host.Home); h != "" {
		add(path.Clean(h))
	}
	add("~")
	add("/root")
	for _, base := range []string{"/home/", v.k("/Users/")} {
		if rest, ok := strings.CutPrefix(p, base); ok {
			if user, _, _ := strings.Cut(rest, "/"); user != "" {
				add(base + user)
			}
		}
	}
	if drive, rest, ok := sandboxWSLDrive(p); ok && drive != "" {
		if after, ok := strings.CutPrefix(rest, "users/"); ok {
			if user, _, _ := strings.Cut(after, "/"); user != "" {
				add("/mnt/" + drive + "/users/" + user)
			}
		}
	}
	return out
}

// sandboxHomeRelSensitive applies the home entries to one home-relative path.
func sandboxHomeRelSensitive(v sandboxBindPath, rel string) bool {
	for _, e := range sandboxHomeSensitive {
		if !slashWithin(rel, v.k(e)) {
			continue
		}
		if e == ".observer" && slashWithin(rel, ".observer/workspaces") {
			return false
		}
		return true
	}
	if rel == ".config" {
		return true
	}
	if slashWithin(rel, ".config") {
		if !v.host.Known {
			return false
		}
		for _, b := range v.host.LocalRWBinds {
			if b = strings.TrimSpace(b); b != "" && slashWithin(v.p, path.Clean(b)) {
				return false
			}
		}
		return true
	}
	return false
}

// slashWithin reports whether child is parent or lies under it.
func slashWithin(child, parent string) bool {
	if parent == "/" {
		return strings.HasPrefix(child, "/")
	}
	return child == parent || strings.HasPrefix(child, parent+"/")
}

// slashRel returns child relative to parent ("" when equal).
func slashRel(child, parent string) (string, bool) {
	if child == parent {
		return "", true
	}
	if rest, ok := strings.CutPrefix(child, parent+"/"); ok {
		return rest, true
	}
	return "", false
}
