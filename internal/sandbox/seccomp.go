package sandbox

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// seccomp.go is the plan side of the seccomp filter of the lightweight rows
// (gap G16, lane N2). The planner names a profile; it never builds the
// program (internal/sandboxseccomp does, in the host helper, from the
// profile id this file carries). Two flags:
//
//   - bwrap's own `--seccomp <fd>`, emitted by BuildPlan when the request
//     names a profile, always with SeccompFD: the host helper puts the
//     program there;
//   - the host helper's `--seccomp-profile <id>`, emitted by Plan.HostArgv
//     (bwrap) or HostArgvWithSeccomp (the process_lite exec step, which
//     loads the program itself): the helper's child must be running under
//     the filter when the helper reads its /proc status back, or the run is
//     refused.

// SeccompFD is the descriptor bwrap reads the program from: fd 3 is the
// launcher's OOB channel and fd 4 the start gate (the host helper's
// ExtraFiles), so the program is the third extra file.
const SeccompFD = 5

const (
	// flagBwrapSeccomp is bwrap's flag (bubblewrap 0.1.x and later).
	flagBwrapSeccomp = "--seccomp"
	// flagSeccompProfile is the host helper's flag.
	flagSeccompProfile = "--seccomp-profile"
	// maxSeccompProfileLen bounds a profile id.
	maxSeccompProfileLen = 32
)

// validSeccompProfile reports whether p has the shape of a profile id: 1 to
// 32 lower-case letters, digits and underscores. Whether the id names a
// profile is the host helper's question (the assembler refuses an unknown
// one).
func validSeccompProfile(p string) bool {
	if p == "" || len(p) > maxSeccompProfileLen {
		return false
	}
	for _, r := range p {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// seccompArgs is BuildPlan's seccomp step: nothing for no profile, else
// bwrap's --seccomp on SeccompFD.
func seccompArgs(profile string) ([]string, error) {
	if profile == "" {
		return nil, nil
	}
	if !validSeccompProfile(profile) {
		return nil, fmt.Errorf("seccomp profile %q", profile)
	}
	return []string{flagBwrapSeccomp, strconv.Itoa(SeccompFD)}, nil
}

// HostArgvWithSeccomp inserts the host helper's --seccomp-profile before the
// "--" that ends a host argv (RelayHostArgv's), for a row whose child loads
// the filter itself (the process_lite exec step). An empty profile returns
// host unchanged.
func HostArgvWithSeccomp(host []string, profile string) ([]string, error) {
	if profile == "" {
		return host, nil
	}
	if !validSeccompProfile(profile) {
		return nil, fmt.Errorf("sandbox.HostArgvWithSeccomp: seccomp profile %q", profile)
	}
	i := slices.Index(host, HostVerb)
	if i < 0 || len(host) == 0 || host[len(host)-1] != argSep {
		return nil, fmt.Errorf("sandbox.HostArgvWithSeccomp: not a host helper argv")
	}
	if slices.Contains(host[i:], flagSeccompProfile) {
		return nil, fmt.Errorf("sandbox.HostArgvWithSeccomp: the argv already names a seccomp profile")
	}
	out := make([]string, 0, len(host)+2)
	out = append(out, host[:len(host)-1]...)
	return append(out, flagSeccompProfile, profile, argSep), nil
}

// ErrBwrapFlagUnknown is BwrapSeccompFD's answer for a token in flag
// position that is not in bwrapFlagArity: the scan cannot know how many
// operands follow it, so it cannot say whether --seccomp comes later.
var ErrBwrapFlagUnknown = errors.New("bwrap command has a flag the seccomp scan does not know")

// bwrapFlagArity is the number of operands each bwrap option takes
// (bubblewrap 0.4.0 to 0.11, bwrap(1)), so the scan skips operands instead
// of reading them as flags (audit N2-A11, lane FU4): a --setenv value or a
// bind path equal to "--seccomp" is an operand, never the flag. It holds
// every option the planner emits (TestBwrapFlagArityCoversPlanner) and the
// rest of bwrap's documented options; --args (more options from a
// descriptor the scan cannot read) is deliberately absent, so it counts as
// unknown.
var bwrapFlagArity = map[string]int{
	"--help": 0, "--version": 0, "--level-prefix": 0,
	"--unshare-all": 0, "--share-net": 0, "--unshare-user": 0, "--unshare-user-try": 0,
	"--unshare-ipc": 0, "--unshare-pid": 0, "--unshare-net": 0, "--unshare-uts": 0,
	"--unshare-cgroup": 0, "--unshare-cgroup-try": 0, "--disable-userns": 0,
	"--assert-userns-disabled": 0, "--clearenv": 0, "--new-session": 0,
	"--die-with-parent": 0, "--as-pid-1": 0,
	"--argv0": 1, "--userns": 1, "--userns2": 1, "--pidns": 1, "--uid": 1, "--gid": 1,
	"--hostname": 1, "--chdir": 1, "--unsetenv": 1, "--lock-file": 1, "--sync-fd": 1,
	"--remount-ro": 1, "--proc": 1, "--dev": 1, "--tmpfs": 1, "--mqueue": 1, "--dir": 1,
	flagBwrapSeccomp: 1, "--add-seccomp-fd": 1, "--exec-label": 1, "--file-label": 1,
	"--block-fd": 1, "--userns-block-fd": 1, "--info-fd": 1, "--json-status-fd": 1,
	"--cap-add": 1, "--cap-drop": 1, "--perms": 1, "--size": 1, "--overlay-src": 1,
	"--tmp-overlay": 1, "--ro-overlay": 1,
	"--setenv": 2, "--bind": 2, "--bind-try": 2, "--dev-bind": 2, "--dev-bind-try": 2,
	"--ro-bind": 2, "--ro-bind-try": 2, "--bind-fd": 2, "--ro-bind-fd": 2, "--file": 2,
	"--bind-data": 2, "--ro-bind-data": 2, "--symlink": 2, "--chmod": 2,
	"--overlay": 3,
}

// BwrapUnsharesPID reports whether a bwrap command (the bwrap path, its
// options, "--", the inner argv) gives the box a pid namespace of its own:
// --unshare-pid or --unshare-all among its options, walked with
// bwrapFlagArity like BwrapSeccompFD, so an operand that reads
// "--unshare-pid" is never taken for the flag. An option the table does not
// know is ErrBwrapFlagUnknown (the strace opt-in then refuses, fail closed).
func BwrapUnsharesPID(cmd []string) (bool, error) {
	for i := 1; i < len(cmd); i++ {
		tok := cmd[i]
		if tok == argSep || !strings.HasPrefix(tok, "-") {
			break
		}
		n, ok := bwrapFlagArity[tok]
		if !ok {
			return false, fmt.Errorf("%w: %q", ErrBwrapFlagUnknown, tok)
		}
		if tok == flagUnsharePid || tok == "--unshare-all" {
			return true, nil
		}
		i += n
	}
	return false, nil
}

// BwrapSeccompFD reads bwrap's --seccomp from a bwrap command (the host
// helper's child: the bwrap path, its options, "--", the inner argv): the
// descriptor and whether the flag is there. The options are walked with
// bwrapFlagArity, so an operand is never taken for a flag; the walk ends at
// "--" or at the first token that is not an option (bwrap's own end of
// options). An option the table does not know is ErrBwrapFlagUnknown; a
// malformed descriptor is an error.
func BwrapSeccompFD(cmd []string) (int, bool, error) {
	if len(cmd) == 0 {
		return 0, false, nil
	}
	found, fd := false, 0
	for i := 1; i < len(cmd); i++ {
		tok := cmd[i]
		if tok == argSep || !strings.HasPrefix(tok, "-") {
			break
		}
		n, ok := bwrapFlagArity[tok]
		if !ok {
			return 0, false, fmt.Errorf("%w: %q", ErrBwrapFlagUnknown, tok)
		}
		if i+n >= len(cmd) {
			return 0, false, fmt.Errorf("bwrap %s needs %d operand(s)", tok, n)
		}
		if tok == flagBwrapSeccomp {
			if found {
				return 0, false, fmt.Errorf("bwrap command names --seccomp twice")
			}
			v, err := strconv.Atoi(cmd[i+1])
			if err != nil || v < 0 {
				return 0, false, fmt.Errorf("bwrap --seccomp descriptor %q", cmd[i+1])
			}
			found, fd = true, v
		}
		i += n
	}
	return fd, found, nil
}
