package sandbox

import (
	"errors"
	"regexp"
	"strings"
)

// canary.go names why the bwrap canary failed. The canary used to drop
// bwrap's stderr and always blame the two user-namespace sysctls, which was
// wrong on both live hosts of 2026-10-22: on InstaBox user namespaces work
// and bwrap says "Can't mount proc on /proc" (the platform binds a file
// over /proc/sys/kernel/random/boot_id), and on Daytona (a Sysbox system
// container) both sysctls are permissive and bwrap says "setting up uid
// map: Permission denied". The caller keeps bwrap's stderr in a
// CanaryFailure; the ordered table below reads it, first match wins.

// CanaryFailure is a canary's error together with bwrap's own stderr.
type CanaryFailure struct {
	Err    error
	Stderr string
}

// Error is the error with the scrubbed stderr.
func (c *CanaryFailure) Error() string {
	msg := ""
	if c.Err != nil {
		msg = c.Err.Error()
	}
	if s := ScrubCanaryStderr(c.Stderr); s != "" {
		if msg != "" {
			msg += ": "
		}
		msg += s
	}
	return msg
}

// Unwrap returns the process error.
func (c *CanaryFailure) Unwrap() error { return c.Err }

// canaryCause is one row of the classification table.
type canaryCause struct {
	// id names the cause in the reason.
	id string
	// match: any of these lower-case substrings of bwrap's stderr.
	match []string
	// reason is the refusal text; %s is bwrap's scrubbed stderr.
	reason string
	// sysctls: the user-namespace sysctls are relevant, so the ones that
	// read restrictive are named.
	sysctls bool
}

// canaryCauses is the table, walked top-down (CLAUDE.md rule 5).
var canaryCauses = []canaryCause{
	{
		id:    "proc_mount_denied",
		match: []string{"can't mount proc on /proc"},
		reason: "bwrap could not mount a fresh /proc inside the sandbox (%s). User namespaces work here, but this host's /proc is locked or has something " +
			"mounted over one of its entries (some cloud VMs bind a file over /proc/sys/kernel/random/boot_id), so the kernel refuses a new procfs in a user " +
			"namespace. Observer does not fall back to a read-only bind of the host's /proc: the sandbox would then see every host process's environment, " +
			"command line and open files, and could reach the host's files through /proc/<pid>/root, which undoes the sandbox. Run on a host whose /proc " +
			"is not overmounted, or use another backend",
	},
	{
		id:    "uid_map_denied",
		match: []string{"setting up uid map", "uid_map", "setting up gid map", "setgroups"},
		reason: "bwrap created a user namespace but could not write its uid map (%s): a container runtime or a security module forbids it here " +
			"(for example a Sysbox system container, or an AppArmor rule that restricts unprivileged user namespaces)",
		sysctls: true,
	},
	{
		id:      "setuid_bwrap_required",
		match:   []string{"must be installed setuid", "unexpected capabilities but not setuid"},
		reason:  "this kernel does not let an unprivileged process create bwrap's namespaces, and this bwrap is not setuid (%s): install the distribution's setuid bwrap, or allow unprivileged user namespaces",
		sysctls: true,
	},
	{
		id:      "userns_denied",
		match:   []string{"no permissions to creating new namespace", "creating new namespace failed", "unshare", "clone"},
		reason:  "bwrap could not create its user namespace (%s)",
		sysctls: true,
	},
}

// userns sysctls and the value that makes each restrictive.
var usernsSysctls = []struct{ key, restrictive string }{
	{"kernel.unprivileged_userns_clone", "0"},
	{"user.max_user_namespaces", "0"},
	{"kernel.apparmor_restrict_unprivileged_userns", "1"},
}

// CanaryReason is the refusal text for a failed canary: the cause the
// table names from bwrap's stderr, plus each user-namespace sysctl that
// reads restrictive where the cause is a namespace one (none is named on
// a guess).
func CanaryReason(err error, readSysctl func(string) (string, bool)) string {
	stderr := ""
	var cf *CanaryFailure
	if errors.As(err, &cf) {
		stderr = cf.Stderr
	}
	text := canaryErrorText(err)
	l := strings.ToLower(stderr)
	row := canaryCause{id: "unknown", reason: "bwrap's sandbox smoke test failed (%s)", sysctls: true}
	for _, c := range canaryCauses {
		if l != "" && canaryMatches(l, c.match) {
			row = c
			break
		}
	}
	reason := strings.Replace(row.reason, "%s", text, 1)
	if row.sysctls && readSysctl != nil {
		var bad []string
		for _, s := range usernsSysctls {
			if v, ok := readSysctl(s.key); ok && strings.TrimSpace(v) == s.restrictive {
				bad = append(bad, s.key+" = "+s.restrictive)
			}
		}
		if len(bad) > 0 {
			reason += "; restrictive here: " + strings.Join(bad, ", ")
		}
	}
	return reason + " [" + row.id + "]"
}

// canaryErrorText is the error's text with bwrap's stderr scrubbed.
func canaryErrorText(err error) string {
	if err == nil {
		return ""
	}
	var cf *CanaryFailure
	if errors.As(err, &cf) {
		return cf.Error()
	}
	return err.Error()
}

func canaryMatches(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// canaryPaths are the paths the canary's own plan names (and the uid and
// gid map files bwrap reports on); any other absolute path in bwrap's
// stderr is replaced, so a refusal never echoes a host path outside the
// plan.
var canaryPaths = map[string]bool{
	"/": true, "/proc": true, "/tmp": true, "/dev": true,
	"/proc/self/uid_map": true, "/proc/self/gid_map": true, "/proc/self/setgroups": true,
}

var absPathRE = regexp.MustCompile(`/[^\s:'"(),;]*`)

// maxCanaryStderr caps how much of bwrap's stderr a reason carries.
const maxCanaryStderr = 300

// ScrubCanaryStderr trims bwrap's stderr to its first lines and replaces
// every absolute path outside the canary's plan with <path>.
func ScrubCanaryStderr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > 3 {
		lines = lines[:3]
	}
	s = strings.Join(lines, " / ")
	s = absPathRE.ReplaceAllStringFunc(s, func(p string) string {
		if canaryPaths[p] {
			return p
		}
		return "<path>"
	})
	if len(s) > maxCanaryStderr {
		s = s[:maxCanaryStderr] + "..."
	}
	return s
}
