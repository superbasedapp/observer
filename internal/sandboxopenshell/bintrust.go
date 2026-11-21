package sandboxopenshell

import (
	"strconv"
)

// bintrust.go is where Observer accepts OpenShell's two programs from
// (ledger row OSH-44). The managed gateway's openshell-gateway receives
// the key-encryption key and reads the CA key, and the openshell CLI
// holds the gateway's client certificate on every call, so a program
// planted where the resolver looks first (PATH, or a fallback dir such as
// a tool-state dir another sandbox backend binds read-write into a box)
// would run with them. Each is accepted only when its real file (every
// symlink resolved) is owned by root and writable by no one else, in a
// directory chain up to / that is owned by root and writable by no one
// else: the OpenShell package's /usr/bin, or a root-owned install such as
// /usr/local/bin. A copy in a dir the user (or a box running as the user)
// can write is refused, wherever the resolver found it. The program then
// runs from that checked real path, never re-resolved.

// VerdictBinaryUntrusted: an OpenShell program was found only where the
// user, or a box, could replace it.
const VerdictBinaryUntrusted = "openshell_binary_untrusted"

// TrustedPrograms are the programs this rule covers.
var TrustedPrograms = []string{Program, GatewayProgram}

// PathOwner is one path's owner and permission bits.
type PathOwner struct {
	Path string
	UID  int
	// Mode holds the permission bits (0o7777).
	Mode uint32
}

// BinaryTrustFacts are what the trust rule reads about one resolved
// program.
type BinaryTrustFacts struct {
	// Program is the program's name (named in a reason).
	Program string
	// Path is where the resolver found it; Real is that path with every
	// symlink resolved.
	Path, Real string
	// Read: the facts below were read (false: the file or a directory
	// could not be stat'ed).
	Read bool
	// Detail says what could not be read.
	Detail string
	// File is the real file; Dirs are its directory and every parent up
	// to / (nearest first).
	File PathOwner
	Dirs []PathOwner
}

// groupOtherWrite are the write bits of the group and of others.
const groupOtherWrite = 0o022

// trustRule is one row of the trust table, walked top-down.
type trustRule struct {
	id     string
	fails  func(f BinaryTrustFacts) (bool, string)
	reason func(f BinaryTrustFacts, what string) string
}

// trustRemedy is every refusal's remedy.
func trustRemedy(f BinaryTrustFacts) string {
	return "; Observer runs " + f.Program + " only from a root-owned location no user and no box can write, because it holds the gateway's keys (the OpenShell package installs it in /usr/bin): install the OpenShell package, or install the binary root-owned (for example `sudo install -o root -g root -m 0755 " + quoteOr(f.Real, f.Program) + " /usr/local/bin/`). If the package is installed already, this copy comes earlier on PATH and shadows it: remove " + quoteOr(f.Path, "the copy") + " or put /usr/bin before its directory on PATH"
}

// trustRules is the trust table (ledger row OSH-44).
var trustRules = []trustRule{
	{"T1 facts not read", func(f BinaryTrustFacts) (bool, string) { return !f.Read, "" }, func(f BinaryTrustFacts, _ string) string {
		return "could not check who owns " + f.Program + " at " + quoteOr(f.Path, "(no path)") + detailSuffix(f.Detail) + trustRemedy(f)
	}},
	{"T2 file not root's", func(f BinaryTrustFacts) (bool, string) { return f.File.UID != 0, "" }, func(f BinaryTrustFacts, _ string) string {
		return f.Program + " at " + quoteOr(f.Real, "(no path)") + " is owned by uid " + strconv.Itoa(f.File.UID) + ", not root" + trustRemedy(f)
	}},
	{"T3 file writable by others", func(f BinaryTrustFacts) (bool, string) { return f.File.Mode&groupOtherWrite != 0, "" }, func(f BinaryTrustFacts, _ string) string {
		return f.Program + " at " + quoteOr(f.Real, "(no path)") + " is writable by its group or by others (mode " + strconv.FormatUint(uint64(f.File.Mode&0o7777), 8) + ")" + trustRemedy(f)
	}},
	{"T4 a directory not root's or writable by others", func(f BinaryTrustFacts) (bool, string) {
		if len(f.Dirs) == 0 {
			return true, "(no directory read)"
		}
		for _, d := range f.Dirs {
			if d.UID != 0 || d.Mode&groupOtherWrite != 0 {
				return true, d.Path + " (uid " + strconv.Itoa(d.UID) + ", mode " + strconv.FormatUint(uint64(d.Mode&0o7777), 8) + ")"
			}
		}
		return false, ""
	}, func(f BinaryTrustFacts, what string) string {
		return f.Program + " at " + quoteOr(f.Real, "(no path)") + " is in a directory someone other than root can write: " + what + trustRemedy(f)
	}},
}

// BinaryTrust walks the trust table: "" when the program may run from
// f.Real, else VerdictBinaryUntrusted's reason.
func BinaryTrust(f BinaryTrustFacts) string {
	for _, r := range trustRules {
		if bad, what := r.fails(f); bad {
			return r.reason(f, what)
		}
	}
	return ""
}
