//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// terminal_sandbox_openshell_gateway_linux.go is the Linux half of the
// managed gateway's driver: the filesystem facts (statfs and the dir's
// mountinfo row) the refusal tables read, the runtime dir check, the
// loopback port check, the lifecycle lock, and the interactive create's
// environment for a managed target.

// openShellGatewayHost returns the Linux host facts.
func openShellGatewayHost() openShellGatewayHostT {
	return openShellGatewayHostT{
		RuntimeDir: func() string { return os.Getenv("XDG_RUNTIME_DIR") },
		StateFS: func(dir string) (sandboxopenshell.Tri, string) {
			return sandboxopenshell.GatewayStateFS(openShellFSFacts(openShellNearestExisting(dir)))
		},
		RuntimeFS: func(dir string) (sandboxopenshell.Tri, string) {
			return sandboxopenshell.GatewayRuntimeFS(openShellDirFacts(dir), os.Getuid())
		},
		PortFree:     openShellPortFree,
		Lock:         openShellFlock,
		Rand:         rand.Reader,
		DockerAccess: openShellManagerDockerAccess,
		DockerHost:   openShellUnitDockerHost,
	}
}

// openShellDockerSocket is the default Docker engine socket.
const openShellDockerSocket = "/var/run/docker.sock"

// openShellDockerFacts are what the docker access rows read (audit
// findings O2-A8, O2-V2, O2-W3 and O2-W4).
type openShellDockerFacts struct {
	// EnvContext is DOCKER_CONTEXT; ConfigContext is the currentContext
	// name of the docker CLI's config.json (`docker context use`; the name
	// only, nothing else of that file is kept).
	EnvContext, ConfigContext string
	// DockerHost is this launch's own DOCKER_HOST ("" for none): the
	// engine its runtime canary drives.
	DockerHost string
	// UnitDockerHost is the DOCKER_HOST the private gateway's unit is given
	// ("" for none), from its one owner (dockerHostFor), never this
	// launch's own environment; UnitOwner names that owner
	// (openShellEngineOwner*).
	UnitDockerHost string
	UnitOwner      string
	// SameEngineFile: this launch's engine socket and the unit's name
	// different paths but stat to the same file (a symlink such as
	// /var/run to /run; audit finding OC-A6).
	SameEngineFile bool
	// SockFound: the unit's engine socket (UnitDockerHost's unix path, or
	// the default) was stat'ed; SockUID, SockGID and SockMode are its
	// owner, group and permission bits.
	SockFound        bool
	SockUID, SockGID int
	SockMode         uint32
	// SockACL is the socket's POSIX access ACL (nil: it has none);
	// SockACLUnread: it may have one, but it could not be read.
	SockACL       []openShellACLEntry
	SockACLUnread bool
	// UID is this user; ManagerGroups the user manager's groups (nil when
	// it was not found).
	UID           int
	ManagerGroups []int
}

// openShellDockerHostPath returns the local socket path of a unix://
// DOCKER_HOST ("" and false for any other scheme or a relative path).
func openShellDockerHostPath(h string) (string, bool) {
	p, ok := strings.CutPrefix(h, "unix://")
	if !ok || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return "", false
	}
	return p, true
}

// openShellEngineSocket is the engine socket a DOCKER_HOST value drives:
// the default socket for none, the path of a local unix one; false for
// any other value.
func openShellEngineSocket(h string) (string, bool) {
	if h == "" {
		return openShellDockerSocket, true
	}
	return openShellDockerHostPath(h)
}

// openShellSchemeRE is the shape of a URL scheme a refusal may name.
var openShellSchemeRE = regexp.MustCompile(`^[a-z][a-z0-9+.-]{0,15}$`)

// openShellDockerHostShape names a DOCKER_HOST value's shape for a refusal
// and never the value itself (audit finding O2-W3): its scheme when it has
// one that looks like a scheme, else only that it has none.
func openShellDockerHostShape(h string) string {
	scheme, _, ok := strings.Cut(h, "://")
	switch {
	case !ok:
		return "an address with no scheme"
	case !openShellSchemeRE.MatchString(scheme):
		return "an address with an unrecognised scheme"
	}
	return "a " + strconv.Quote(scheme) + " engine"
}

// openShellLocalDockerHost reports whether this launch's DOCKER_HOST names
// a local unix socket: the docker CLI then ignores DOCKER_CONTEXT and the
// selected context (DOCKER_HOST wins over both), so neither refuses.
func openShellLocalDockerHost(f openShellDockerFacts) bool {
	_, ok := openShellDockerHostPath(f.DockerHost)
	return ok
}

// openShellDockerRows is the docker access table, first matching row
// wins: a context the unit cannot follow, a non-local engine and a launch
// whose engine is not the unit's refuse; an engine socket the user manager
// can open by owner, by its mode, by its group or by an ACL entry passes;
// an unreadable fact is unknown (which does not refuse).
var openShellDockerRows = []struct {
	id    string
	match func(f openShellDockerFacts) bool
	tri   sandboxopenshell.Tri
	why   func(f openShellDockerFacts) string
}{
	{
		"D1 a docker context in the environment", func(f openShellDockerFacts) bool {
			return f.EnvContext != "" && f.EnvContext != "default" && !openShellLocalDockerHost(f)
		}, sandboxopenshell.TriNo,
		func(f openShellDockerFacts) string {
			return "a docker context (" + strconv.Quote(f.EnvContext) + ", DOCKER_CONTEXT) is in use, which the private gateway's unit does not follow; set DOCKER_HOST to that context's local socket instead"
		},
	},
	{
		"D2 a docker context selected with docker context use", func(f openShellDockerFacts) bool {
			return f.EnvContext == "" && f.ConfigContext != "" && f.ConfigContext != "default" && !openShellLocalDockerHost(f)
		}, sandboxopenshell.TriNo,
		func(f openShellDockerFacts) string {
			return "a docker context (" + strconv.Quote(f.ConfigContext) + ", selected with `docker context use`) is in use, which the private gateway's unit does not follow; run `docker context use default`, or set DOCKER_HOST to that context's local socket"
		},
	},
	{
		"D3 a DOCKER_HOST that is not a local unix socket", func(f openShellDockerFacts) bool {
			return f.DockerHost != "" && !openShellLocalDockerHost(f)
		}, sandboxopenshell.TriNo,
		func(f openShellDockerFacts) string {
			return "DOCKER_HOST names " + openShellDockerHostShape(f.DockerHost) + ", not a local unix socket; the private gateway's boxes bind this machine's paths, so only a local engine is taken"
		},
	},
	{
		"D3a this launch drives another engine than the gateway's unit", func(f openShellDockerFacts) bool {
			mine, ok1 := openShellEngineSocket(f.DockerHost)
			unit, ok2 := openShellEngineSocket(f.UnitDockerHost)
			return ok1 && ok2 && mine != unit && !f.SameEngineFile
		}, sandboxopenshell.TriNo,
		openShellD3aReason,
	},
	{"D4 the engine socket was not read", func(f openShellDockerFacts) bool { return !f.SockFound }, sandboxopenshell.TriUnknown, nil},
	{"D5 the user owns the socket", func(f openShellDockerFacts) bool { return f.SockUID == f.UID }, sandboxopenshell.TriYes, nil},
	{"D6 anyone may open the socket", func(f openShellDockerFacts) bool { return f.SockMode&0o006 == 0o006 }, sandboxopenshell.TriYes, nil},
	{"D7 the user manager was not found", func(f openShellDockerFacts) bool { return f.ManagerGroups == nil }, sandboxopenshell.TriUnknown, nil},
	{"D8 the user manager holds the socket's group", func(f openShellDockerFacts) bool {
		// With an ACL the mode's group bits are its mask, not the group's
		// own permission: row D8a judges it instead.
		return f.SockACL == nil && !f.SockACLUnread && f.SockMode&0o060 == 0o060 && slices.Contains(f.ManagerGroups, f.SockGID)
	}, sandboxopenshell.TriYes, nil},
	{"D8a an ACL entry admits the user manager", func(f openShellDockerFacts) bool {
		return f.SockACL != nil && openShellACLAdmits(f.SockACL, f.UID, f.SockGID, f.ManagerGroups)
	}, sandboxopenshell.TriYes, nil},
	{"D8b the socket's ACL was not read", func(f openShellDockerFacts) bool { return f.SockACLUnread }, sandboxopenshell.TriUnknown, nil},
	{
		"D9 no way in", func(openShellDockerFacts) bool { return true }, sandboxopenshell.TriNo,
		func(openShellDockerFacts) string {
			return "your systemd user manager cannot open the Docker engine socket (not its owner, not in a group the socket admits, no ACL entry admits it, and the socket is not open to everyone)"
		},
	},
}

// openShellD3aReasons is row D3a's refusal per owner of the unit's engine
// (audit finding OC-A6): each names who chose that engine and how to get
// past it.
var openShellD3aReasons = map[string]string{
	openShellEngineOwnerDaemon:  "this launch's DOCKER_HOST names another engine socket than the one the daemon gives Observer's private gateway, so the runtime canary would test another engine than its boxes run on; launch with the daemon's DOCKER_HOST, or restart the daemon with this one",
	openShellEngineOwnerGateway: "this launch's DOCKER_HOST names another engine socket than the one Observer's private gateway was started with and still holds (no daemon runs for this state dir, and the gateway's unit is running or a run is recorded on it), so the runtime canary would test another engine than its boxes run on; launch with that DOCKER_HOST, or once no run uses the gateway stop its observer-openshell-gateway user unit so the next start takes this one, or start the daemon with this one",
}

// openShellD3aReason is row D3a's refusal for f's owner.
func openShellD3aReason(f openShellDockerFacts) string {
	if r, ok := openShellD3aReasons[f.UnitOwner]; ok {
		return r
	}
	return openShellD3aReasons[openShellEngineOwnerDaemon]
}

// openShellSameEngineFile reports whether two different engine socket
// paths stat to the same file; false when either cannot be stat'ed (the
// paths then compare as strings; audit finding OC-A6).
func openShellSameEngineFile(a, b string) bool {
	// G703 (fold audit H4): a and b are this launch's and the gateway's
	// DOCKER_HOST socket paths, the operator's own settings. Only their
	// metadata is read, to compare file identity; nothing is opened, read
	// or written. Following symlinks is the point (/var/run/docker.sock is
	// often one), so an os.Root, which refuses a link out of its dir, would
	// change the answer.
	fa, err := os.Stat(a) //nolint:gosec // G703: a metadata stat of the operator's own DOCKER_HOST socket path, symlinks followed on purpose
	if err != nil {
		return false
	}
	fb, err := os.Stat(b) //nolint:gosec // G703: a metadata stat of the operator's own DOCKER_HOST socket path, symlinks followed on purpose
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

// openShellDockerAccessFrom walks the docker access table.
func openShellDockerAccessFrom(f openShellDockerFacts) (sandboxopenshell.Tri, string) {
	for _, r := range openShellDockerRows {
		if r.match(f) {
			if r.why == nil {
				return r.tri, ""
			}
			return r.tri, r.why(f)
		}
	}
	return sandboxopenshell.TriUnknown, ""
}

// openShellACLEntry is one entry of a POSIX access ACL.
type openShellACLEntry struct {
	Tag  uint16
	Perm uint16
	ID   uint32
}

// The POSIX ACL tags and the xattr version (linux/posix_acl_xattr.h).
const (
	openShellACLUser     = 0x02
	openShellACLGroupObj = 0x04
	openShellACLGroup    = 0x08
	openShellACLMask     = 0x10
	openShellACLVersion  = 2
	// openShellACLRW is read and write, what connecting to a socket needs
	// (the same bits rows D6 and D8 ask of the mode).
	openShellACLRW = 0o6
)

// openShellParseACL decodes a system.posix_acl_access value: a little
// endian version 2 header, then 8-byte entries (tag, perm, id).
func openShellParseACL(b []byte) ([]openShellACLEntry, error) {
	if len(b) < 4 || (len(b)-4)%8 != 0 {
		return nil, errors.New("not a POSIX ACL value")
	}
	if v := binary.LittleEndian.Uint32(b[0:4]); v != openShellACLVersion {
		return nil, errors.New("an unknown POSIX ACL version")
	}
	// Each 8-byte entry is decoded whole by binary.Read (the length check
	// above makes the rest a whole number of entries), so no index into b
	// is computed per entry (gosec G602, tracker F-022).
	out := []openShellACLEntry{}
	r := bytes.NewReader(b[4:])
	for r.Len() > 0 {
		var e openShellACLEntry
		if err := binary.Read(r, binary.LittleEndian, &e); err != nil {
			return nil, errors.New("a truncated POSIX ACL entry")
		}
		out = append(out, e)
	}
	return out, nil
}

// openShellACLAdmits walks the POSIX access check for a process of uid in
// groups (the file's owner is row D5's, everyone else row D6's): a named
// user entry for uid decides alone; else the owning group's and the named
// group entries the process is in decide, admitting if any grants read
// and write; both are limited by the mask entry when there is one.
func openShellACLAdmits(acl []openShellACLEntry, uid, sockGID int, groups []int) bool {
	mask := uint16(0o7)
	for _, e := range acl {
		if e.Tag == openShellACLMask {
			mask = e.Perm
		}
	}
	grants := func(p uint16) bool { return p&mask&openShellACLRW == openShellACLRW }
	for _, e := range acl {
		if e.Tag == openShellACLUser && int(e.ID) == uid {
			return grants(e.Perm)
		}
	}
	for _, e := range acl {
		switch {
		case e.Tag == openShellACLGroupObj && slices.Contains(groups, sockGID) && grants(e.Perm):
			return true
		case e.Tag == openShellACLGroup && slices.Contains(groups, int(e.ID)) && grants(e.Perm):
			return true
		}
	}
	return false
}

// openShellSocketACL reads a socket's POSIX access ACL with the caller's
// own rights (reading the attribute needs no privilege beyond reaching the
// file): nil and false when it has none, unread true when it may have one
// that could not be read.
func openShellSocketACL(path string) (acl []openShellACLEntry, unread bool) {
	buf := make([]byte, 1024)
	n, err := unix.Getxattr(path, "system.posix_acl_access", buf)
	switch {
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.EOPNOTSUPP):
		return nil, false
	case err != nil:
		return nil, true
	}
	a, perr := openShellParseACL(buf[:n])
	if perr != nil {
		return nil, true
	}
	return a, false
}

// openShellDockerConfigContext reads the currentContext NAME of the docker
// CLI's config.json ($DOCKER_CONFIG or ~/.docker); "" when there is none
// or the file is not readable. Nothing else of the file is kept or logged.
func openShellDockerConfigContext() string {
	dir := os.Getenv("DOCKER_CONFIG")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".docker")
	}
	b, err := openShellReadOwned(filepath.Join(dir, "config.json"), 1<<20)
	if err != nil {
		return ""
	}
	var w struct {
		CurrentContext string `json:"currentContext"`
	}
	if json.Unmarshal(b, &w) != nil {
		return ""
	}
	return strings.TrimSpace(w.CurrentContext)
}

// openShellManagerDockerAccess gathers the docker facts and walks the
// table (lifecycle row G9): this launch's own docker environment, and the
// socket of the engine the unit is given (unit, from the one owner; audit
// findings O2-W4, OC-A6).
func openShellManagerDockerAccess(unit openShellUnitEngine) (sandboxopenshell.Tri, string) {
	f := openShellDockerFacts{EnvContext: os.Getenv("DOCKER_CONTEXT"), ConfigContext: openShellDockerConfigContext(), DockerHost: os.Getenv("DOCKER_HOST"), UnitDockerHost: unit.DockerHost, UnitOwner: unit.Owner, UID: os.Getuid()}
	sock, ok := openShellEngineSocket(unit.DockerHost)
	if !ok {
		sock = openShellDockerSocket
	}
	if mine, ok := openShellEngineSocket(f.DockerHost); ok && mine != sock {
		f.SameEngineFile = openShellSameEngineFile(mine, sock)
	}
	if fi, err := os.Stat(sock); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			f.SockFound, f.SockUID, f.SockGID, f.SockMode = true, int(st.Uid), int(st.Gid), uint32(fi.Mode().Perm())
			f.SockACL, f.SockACLUnread = openShellSocketACL(sock)
		}
	}
	if _, groups, ok := openShellUserManagerGroups(f.UID); ok {
		f.ManagerGroups = append([]int{}, groups...)
	}
	return openShellDockerAccessFrom(f)
}

// openShellUnitDockerHost is this process's own DOCKER_HOST when it names
// a local unix socket, else "" (a non-local one refuses at row G9). The
// unit is given the one owner's value (dockerHostFor).
func openShellUnitDockerHost() string {
	h := os.Getenv("DOCKER_HOST")
	if _, ok := openShellDockerHostPath(h); ok {
		return h
	}
	return ""
}

// openShellUserManagerGroups finds this user's systemd user manager
// ("systemd --user", owned by uid) in /proc and returns its pid and its
// primary and supplementary groups (from /proc/<pid>/status; no
// environment is read).
func openShellUserManagerGroups(uid int) (int, []int, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, nil, false
	}
	for _, ent := range entries {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", ent.Name(), "comm")) //nolint:gosec // G304: a fixed /proc file
		if err != nil || strings.TrimSpace(string(comm)) != "systemd" {
			continue
		}
		cmd, _ := os.ReadFile(filepath.Join("/proc", ent.Name(), "cmdline")) //nolint:gosec // G304: a fixed /proc file
		if !strings.Contains(string(cmd), "--user") {
			continue
		}
		status, err := os.ReadFile(filepath.Join("/proc", ent.Name(), "status")) //nolint:gosec // G304: a fixed /proc file
		if err != nil {
			continue
		}
		owner, groups := -1, []int(nil)
		for _, line := range strings.Split(string(status), "\n") {
			k, v, found := strings.Cut(line, ":")
			if !found {
				continue
			}
			fields := strings.Fields(v)
			switch k {
			case "Uid":
				if len(fields) > 0 {
					owner, _ = strconv.Atoi(fields[0])
				}
			case "Gid":
				if len(fields) > 0 {
					if g, err := strconv.Atoi(fields[0]); err == nil {
						groups = append(groups, g)
					}
				}
			case "Groups":
				for _, f := range fields {
					if g, err := strconv.Atoi(f); err == nil {
						groups = append(groups, g)
					}
				}
			}
		}
		if owner == uid {
			return pid, groups, true
		}
	}
	return 0, nil, false
}

// openShellNearestExisting is dir, or its nearest existing parent (the
// state dir is made on the first start, on the filesystem its parent is
// on).
func openShellNearestExisting(dir string) string {
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil || d == "/" || d == "." { //nolint:gosec // G703: a stat of the row's own state dir and its parents, nothing opened
			return d
		}
	}
}

// openShellFSFacts reads statfs and the mountinfo row the dir is on.
func openShellFSFacts(dir string) sandboxopenshell.FSFacts {
	var f sandboxopenshell.FSFacts
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err == nil {
		f.Magic = int64(st.Type) //nolint:unconvert // Statfs_t.Type is int64 on amd64 and int32 elsewhere
	}
	f.MountType, f.MountSource = openShellMountOf(dir)
	return f
}

// openShellMountOf finds the mountinfo row whose mount point is the
// longest prefix of dir (resolved), and returns its type and source.
func openShellMountOf(dir string) (string, string) {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", ""
	}
	fh, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", ""
	}
	defer func() { _ = fh.Close() }()
	best, typ, src := -1, "", ""
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		mp, t, s, ok := openShellParseMountinfo(sc.Text())
		if !ok {
			continue
		}
		if (real == mp || mp == "/" || strings.HasPrefix(real, mp+"/")) && len(mp) >= best {
			best, typ, src = len(mp), t, s
		}
	}
	return typ, src
}

// openShellParseMountinfo reads one /proc/self/mountinfo line: the mount
// point (field 5, octal escapes decoded), and after the " - " separator
// the filesystem type and the mount source.
func openShellParseMountinfo(line string) (mountPoint, fsType, source string, ok bool) {
	pre, post, found := strings.Cut(line, " - ")
	if !found {
		return "", "", "", false
	}
	f := strings.Fields(pre)
	g := strings.Fields(post)
	if len(f) < 5 || len(g) < 2 {
		return "", "", "", false
	}
	return openShellUnescapeMount(f[4]), g[0], openShellUnescapeMount(g[1]), true
}

// openShellUnescapeMount decodes mountinfo's \NNN octal escapes.
func openShellUnescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// openShellDirFacts reads the runtime dir without following a link.
func openShellDirFacts(dir string) sandboxopenshell.DirFacts {
	var d sandboxopenshell.DirFacts
	if dir == "" || !filepath.IsAbs(dir) {
		return d
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return d
	}
	d.Exists = true
	d.IsLink = fi.Mode()&fs.ModeSymlink != 0
	d.IsDir = fi.IsDir()
	d.Mode = uint32(fi.Mode().Perm())
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		d.OwnerUID = int(st.Uid)
	} else {
		d.OwnerUID = -1
	}
	if !d.IsLink {
		d.FS = openShellFSFacts(dir)
	}
	return d
}

// openShellPortFree reports whether 127.0.0.1:port can be bound now.
func openShellPortFree(port int) bool {
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// openShellFlock takes an exclusive lock on path (blocking).
func openShellFlock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G304: the lifecycle lock under the row's own state dir
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil { //nolint:gosec // G115: a file descriptor
		_ = f.Close()
		if errors.Is(err, unix.EINTR) {
			return nil, errors.New("interrupted while waiting for the lifecycle lock")
		}
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}

// openShellCLIEnvFor is the interactive create's environment for a
// target (the host helper): the runner's list plus the terminal's, with a
// managed target's private registry in place of the user's own.
func openShellCLIEnvFor(environ []string, t sandboxopenshell.Target) []string {
	env := openShellCLIEnv(environ)
	extra, ok := sandboxopenshell.TargetEnv(t)
	if !ok || len(extra) == 0 {
		return env
	}
	env = slices.DeleteFunc(env, func(kv string) bool {
		return strings.HasPrefix(kv, "XDG_CONFIG_HOME=") || strings.HasPrefix(kv, "OPENSHELL_GATEWAY=")
	})
	return append(env, extra...)
}
