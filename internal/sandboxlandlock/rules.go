package sandboxlandlock

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// rules.go mirrors the run's bind plan into a Landlock ruleset (sandbox plan
// v2 section 4.1): every right the kernel handles is handled, so anything a
// rule does not allow is denied. Landlock rules only ALLOW, so the plan's
// read-only overlays inside a writable tree cannot be carved out (a known
// limit, disclosed in SBX-BE-17: hook drift detection, A10, is the control
// there), while everything outside the listed paths, the observer
// directory, the daemon's relay endpoint and the attach socket above all,
// is unreachable.

// Access bundles.
const (
	accessRead  = AccessFSReadFile | AccessFSReadDir
	accessRX    = accessRead | AccessFSExecute
	accessWrite = AccessFSWriteFile | AccessFSRemoveDir | AccessFSRemoveFile | AccessFSMakeDir | AccessFSMakeReg |
		AccessFSMakeSock | AccessFSMakeFifo | AccessFSMakeSym | AccessFSRefer | AccessFSTruncate
	accessRWX = accessRX | accessWrite
	// accessSocketDir lets the box list the run's socket dir and connect to
	// the sockets in it (ABI 9), nothing else.
	accessSocketDir = accessRead | AccessFSResolveUnix
	// accessTTY is a terminal device: read, write and ioctl (ABI 5).
	accessTTY = AccessFSReadFile | AccessFSWriteFile | AccessFSIoctlDev
	// accessDev is a plain character device (/dev/null and friends).
	accessDev = AccessFSReadFile | AccessFSWriteFile
)

// SystemReadExec are the system trees a launch reads and runs programs from
// (read and execute); a missing one is skipped by the cmd layer.
var SystemReadExec = []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/nix/store", "/snap"}

// SystemRead are the trees read but never executed: the system
// configuration, resolver state, and /proc (no PID namespace: the box sees
// the host's processes, disclosed in SBX-BE-17).
var SystemRead = []string{"/etc", "/run/systemd/resolve", "/proc", "/sys/fs/cgroup"}

// Devices are the device files a terminal launch needs.
var Devices = []PathRule{
	{Path: "/dev/null", Access: accessDev},
	{Path: "/dev/zero", Access: accessDev},
	{Path: "/dev/full", Access: accessDev},
	{Path: "/dev/random", Access: AccessFSReadFile},
	{Path: "/dev/urandom", Access: AccessFSReadFile},
	{Path: "/dev/tty", Access: accessTTY},
	{Path: "/dev/ptmx", Access: accessTTY},
	{Path: "/dev/pts", Access: accessTTY | AccessFSReadDir},
}

// PathRule is one path-beneath rule: Access is allowed on Path and, for a
// directory, everything beneath it.
type PathRule struct {
	Path   string
	Access uint64
	// Optional: a missing path is skipped (a system tree this host lacks);
	// a missing required path refuses the launch.
	Optional bool
}

// Ruleset is what the cmd layer applies.
type Ruleset struct {
	HandledFS  uint64
	HandledNet uint64
	Scoped     uint64
	Paths      []PathRule
	// Ports are the TCP ports connect and bind are allowed on (every port
	// but the denied ones); nil below ABI 4.
	Ports []PortRange
	// UDPUnrestricted is the disclosure that UDP is not restricted (below
	// ABI 10).
	UDPUnrestricted bool
}

// PlanInput is the run's bind plan as the cmd layer resolved it: every path
// absolute, clean and symlink-free.
type PlanInput struct {
	ABI       int
	Workspace string
	// StateRW and StateRO are the tool's state paths (bound read-write and
	// read-only by the bwrap plan).
	StateRW, StateRO []string
	// ToolBinDirs and RuntimeDirs are read and executed (the tool's binary
	// and its runtimes).
	ToolBinDirs, RuntimeDirs []string
	// ObserverBin is the observer binary (a file rule, read and execute);
	// ObserverRealDir its resolved install dir, when it differs.
	ObserverBin, ObserverRealDir string
	// SocketDir is the run's socket dir: listed and connected to, nothing
	// else. TempDir is the run's private temp dir (its TMPDIR).
	SocketDir, TempDir string
	// ExtraRO and ExtraRW are the operator's [terminal.sandbox] binds.
	ExtraRO, ExtraRW []string
	// ConfigRO is the launcher's read-only view of its configuration: the
	// daemon's config file and the observer-dir files every config load
	// reads (the governance sidecars, the org lock, the guard policies),
	// the set the bwrap and container rows bind read-only. Read only, the
	// one grant allowed inside ObserverDir; never the database, the keys or
	// a secret (the cmd layer composes it from that table, and a grant here
	// that carries any write or connect right is refused). Without it the
	// inner launcher could not read its config and exited 1 with no message
	// (Linux live check 2026-10-23, LIN-1 F3).
	ConfigRO []string
	// ObserverDir is ~/.observer: never granted, never contained by a grant.
	ObserverDir string
	// DaemonSockets are the daemon's relay endpoint and the attach socket:
	// no grant that carries the socket-connect right may hold them.
	DaemonSockets []string
	// DeniedPorts are Observer's own TCP ports: every listener of the
	// listener config a box has no business with (the dashboard, the OTLP
	// receiver, browser ingest and the rest), never the model proxy. There
	// is no operator setting for extra ports.
	DeniedPorts []int
}

func clean(p string) bool { return p != "" && path.IsAbs(p) && path.Clean(p) == p }

// within reports whether p is dir or beneath it.
func within(p, dir string) bool {
	return dir != "" && (p == dir || dir == "/" || strings.HasPrefix(p, dir+"/"))
}

// planRule is one validation row, walked top-down.
type planRule struct {
	name  string
	check func(in PlanInput, rs Ruleset) error
}

var planRules = []planRule{
	{"abi", func(in PlanInput, _ Ruleset) error {
		if in.ABI < MinABI {
			return fmt.Errorf("Landlock ABI %d is below the row's floor %d", in.ABI, MinABI)
		}
		return nil
	}},
	{"paths", func(_ PlanInput, rs Ruleset) error {
		for _, r := range rs.Paths {
			if !clean(r.Path) {
				return fmt.Errorf("grant %q is not a clean absolute path", r.Path)
			}
			if r.Path == "/" {
				return fmt.Errorf("a grant of the whole root is forbidden")
			}
		}
		return nil
	}},
	{"workspace", func(in PlanInput, _ Ruleset) error {
		if !clean(in.Workspace) {
			return fmt.Errorf("workspace %q is not a clean absolute path", in.Workspace)
		}
		return nil
	}},
	{"observer dir", func(in PlanInput, rs Ruleset) error {
		if in.ObserverDir == "" {
			return fmt.Errorf("the observer directory is not named, so no grant can be checked against it")
		}
		configView := map[string]bool{}
		for _, p := range in.ConfigRO {
			configView[p] = true
		}
		for _, r := range rs.Paths {
			if within(in.ObserverDir, r.Path) {
				return fmt.Errorf("grant %s would expose the whole observer directory (and observer.db)", r.Path)
			}
			if !within(r.Path, in.ObserverDir) || r.Path == in.ObserverBin {
				continue
			}
			// The launcher's config view is the one grant inside: read only.
			if configView[r.Path] && r.Access&^accessRead == 0 {
				continue
			}
			return fmt.Errorf("grant %s lies inside the observer directory", r.Path)
		}
		return nil
	}},
	{"daemon sockets", func(in PlanInput, rs Ruleset) error {
		for _, r := range rs.Paths {
			if r.Access&AccessFSResolveUnix == 0 {
				continue
			}
			for _, s := range in.DaemonSockets {
				if within(s, r.Path) {
					return fmt.Errorf("grant %s would let the box connect to the daemon's socket %s", r.Path, s)
				}
			}
		}
		return nil
	}},
	{"socket dir", func(in PlanInput, _ Ruleset) error {
		if !clean(in.SocketDir) || !clean(in.TempDir) {
			return fmt.Errorf("the run's socket dir %q and temp dir %q must be clean absolute paths", in.SocketDir, in.TempDir)
		}
		if within(in.SocketDir, in.TempDir) || within(in.TempDir, in.SocketDir) {
			return fmt.Errorf("the run's socket dir and temp dir overlap")
		}
		return nil
	}},
}

// BuildRuleset composes the ruleset from the plan and validates it. Every
// access is masked to what the ABI handles.
func BuildRuleset(in PlanInput) (Ruleset, error) {
	f := FeaturesFor(in.ABI)
	rs := Ruleset{HandledFS: f.FS, HandledNet: f.Net, Scoped: f.Scoped, UDPUnrestricted: !f.UDP}
	seen := map[string]int{}
	add := func(p string, access uint64, optional bool) {
		if p == "" {
			return
		}
		access &= f.FS
		if i, ok := seen[p]; ok {
			rs.Paths[i].Access |= access
			rs.Paths[i].Optional = rs.Paths[i].Optional && optional
			return
		}
		seen[p] = len(rs.Paths)
		rs.Paths = append(rs.Paths, PathRule{Path: p, Access: access, Optional: optional})
	}
	for _, p := range SystemReadExec {
		add(p, accessRX, true)
	}
	for _, p := range SystemRead {
		add(p, accessRead, true)
	}
	for _, d := range Devices {
		add(d.Path, d.Access, true)
	}
	add(in.Workspace, accessRWX, false)
	for _, p := range in.StateRW {
		add(p, accessRWX, true)
	}
	for _, p := range in.StateRO {
		add(p, accessRead, true)
	}
	for _, p := range append(append([]string(nil), in.ToolBinDirs...), in.RuntimeDirs...) {
		add(p, accessRX, true)
	}
	add(in.ObserverBin, accessRX&^AccessFSReadDir, false)
	if in.ObserverRealDir != "" && !within(in.ObserverRealDir, in.ObserverDir) {
		add(in.ObserverRealDir, accessRX, true)
	}
	add(in.TempDir, accessRWX, false)
	add(in.SocketDir, accessSocketDir, false)
	for _, p := range in.ExtraRO {
		add(p, accessRead, true)
	}
	for _, p := range in.ConfigRO {
		add(p, accessRead, true)
	}
	for _, p := range in.ExtraRW {
		add(p, accessRWX, true)
	}
	sort.SliceStable(rs.Paths, func(i, j int) bool { return rs.Paths[i].Path < rs.Paths[j].Path })
	if f.Net != 0 {
		ports, err := AllowedPorts(in.DeniedPorts)
		if err != nil {
			return Ruleset{}, err
		}
		rs.Ports = ports
	}
	for _, r := range planRules {
		if err := r.check(in, rs); err != nil {
			return Ruleset{}, fmt.Errorf("sandboxlandlock: plan (%s): %w", r.name, err)
		}
	}
	return rs, nil
}

// Allowed reports the access the ruleset grants on p (the union of every
// rule whose path is p or above it), for tests and the self-test's
// expectations.
func (rs Ruleset) Allowed(p string) uint64 {
	var a uint64
	for _, r := range rs.Paths {
		if within(p, r.Path) {
			a |= r.Access
		}
	}
	return a
}
