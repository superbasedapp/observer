package sandboxoci

import (
	"fmt"
	"path"
	"strings"
)

// socket.go holds the engine socket rules of section 4.6 (Codex F17,
// acceptance A9): by default only a local unix socket is driven; the path
// and every parent are read no-follow and none may be a symlink; the socket
// is owned by the user (rootless) or by root with group access the user
// already holds (rootful, behind allow_rootful); a TCP, SSH or other remote
// DOCKER_HOST is refused; and the daemon's own report of its mode must agree
// with the owner, so a substituted socket is refused rather than driven.

// EndpointEnv is what endpoint resolution reads from the environment.
type EndpointEnv struct {
	// DockerHost and ContainerHost are $DOCKER_HOST and $CONTAINER_HOST.
	DockerHost    string
	ContainerHost string
	// RuntimeDir is $XDG_RUNTIME_DIR.
	RuntimeDir string
	// Exists reports whether a path exists (lstat, no follow).
	Exists func(p string) bool
}

// Candidates are the default socket paths in preference order: rootless
// first (rootless engines are preferred, D-746 Q29), then rootful. /run, not
// /var/run, because /var/run is a symlink on most distributions and a
// symlinked parent is refused.
func Candidates(runtimeDir string) []string {
	var out []string
	if cleanAbs(runtimeDir) {
		out = append(out, path.Join(runtimeDir, "docker.sock"), path.Join(runtimeDir, "podman", "podman.sock"))
	}
	return append(out, "/run/docker.sock", "/run/podman/podman.sock")
}

// parseEndpoint reads one endpoint value: unix:///abs or /abs is a path,
// any other scheme is refused.
func parseEndpoint(src, v string) (string, Verdict) {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "/") {
		if !cleanAbs(v) {
			return "", refuse(VerdictSocketUntrusted, src+" "+quote(v)+" is not a clean absolute path")
		}
		return v, pass()
	}
	scheme, rest, ok := strings.Cut(v, "://")
	if !ok {
		return "", refuse(VerdictSocketUntrusted, src+" "+quote(v)+" is not a unix socket endpoint")
	}
	if scheme != "unix" {
		return "", refuse(VerdictSocketUntrusted, src+" names a "+scheme+" endpoint; only a local unix socket is driven, never a TCP, SSH or remote engine")
	}
	if !cleanAbs(rest) {
		return "", refuse(VerdictSocketUntrusted, src+" "+quote(v)+" is not a clean absolute socket path")
	}
	return rest, pass()
}

// ResolveEndpoint picks the socket: the configured
// [terminal.sandbox.oci].socket, else $DOCKER_HOST, else $CONTAINER_HOST,
// else the first default candidate that exists.
func ResolveEndpoint(configured string, env EndpointEnv) (string, Verdict) {
	switch {
	case strings.TrimSpace(configured) != "":
		return parseEndpoint("[terminal.sandbox.oci].socket", configured)
	case strings.TrimSpace(env.DockerHost) != "":
		return parseEndpoint("DOCKER_HOST", env.DockerHost)
	case strings.TrimSpace(env.ContainerHost) != "":
		return parseEndpoint("CONTAINER_HOST", env.ContainerHost)
	}
	for _, c := range Candidates(env.RuntimeDir) {
		if env.Exists != nil && env.Exists(c) {
			return c, pass()
		}
	}
	return "", refuse(VerdictEngineUnreachable, "no Docker or Podman socket was found (looked at "+strings.Join(Candidates(env.RuntimeDir), ", ")+"); start rootless Docker or `systemctl --user start podman.socket`, or set [terminal.sandbox.oci].socket")
}

// PathFact is one component of the socket path as lstat saw it.
type PathFact struct {
	Path    string
	Symlink bool
	UID     uint32
	// Mode is the permission and sticky bits (mode & 0o7777).
	Mode uint32
}

// SocketFacts are the no-follow facts of the socket and its parents.
type SocketFacts struct {
	Path     string
	Exists   bool
	IsSocket bool
	UID, GID uint32
	Mode     uint32
	// Parents are the components from "/" down to the socket's directory.
	Parents []PathFact
}

// SocketOwner says who the socket's owner makes it: the user's own engine,
// or a root (rootful) engine.
type SocketOwner string

// The SocketOwner values.
const (
	OwnerUser SocketOwner = "user"
	OwnerRoot SocketOwner = "root"
)

// ValidateSocket applies the ownership and no-symlink rules. groups are the
// user's supplementary and primary gids.
func ValidateSocket(f SocketFacts, uid uint32, groups []uint32, allowRootful bool) (SocketOwner, Verdict) {
	for _, p := range f.Parents {
		if p.Symlink {
			return "", refuse(VerdictSocketUntrusted, "a parent of the engine socket, "+p.Path+", is a symlink")
		}
		if p.UID != 0 && p.UID != uid {
			return "", refuse(VerdictSocketUntrusted, fmt.Sprintf("a parent of the engine socket, %s, belongs to uid %d", p.Path, p.UID))
		}
		if p.Mode&0o002 != 0 && p.Mode&0o1000 == 0 {
			return "", refuse(VerdictSocketUntrusted, "a parent of the engine socket, "+p.Path+", is writable by anyone")
		}
	}
	if !f.Exists {
		return "", refuse(VerdictEngineUnreachable, "the engine socket "+f.Path+" does not exist")
	}
	if !f.IsSocket {
		return "", refuse(VerdictSocketUntrusted, f.Path+" is not a unix socket (a symlink or another file type is never followed)")
	}
	if f.Mode&0o002 != 0 {
		return "", refuse(VerdictSocketUntrusted, "the engine socket "+f.Path+" is writable by anyone")
	}
	switch {
	case f.UID == uid && uid != 0:
		return OwnerUser, pass()
	case f.UID == 0:
		if !allowRootful {
			return "", refuse(VerdictSocketUntrusted, "the engine socket "+f.Path+" belongs to root: a rootful engine socket is root-equivalent; set [terminal.sandbox.oci].allow_rootful = true to use it, or run rootless Docker or Podman")
		}
		if uid == 0 {
			return OwnerRoot, pass()
		}
		member := false
		for _, g := range groups {
			member = member || g == f.GID
		}
		if !member || f.Mode&0o060 != 0o060 {
			return "", refuse(VerdictSocketUntrusted, "the rootful engine socket "+f.Path+" is not group read-write for a group you are in")
		}
		return OwnerRoot, pass()
	}
	return "", refuse(VerdictSocketUntrusted, fmt.Sprintf("the engine socket %s belongs to uid %d, neither you nor root", f.Path, f.UID))
}

// CheckOwnerMode is the cross-check of the socket owner against the mode
// the daemon reports: a user-owned socket must answer as a rootless engine
// and a root-owned one as a rootful engine.
func CheckOwnerMode(owner SocketOwner, id Identity) Verdict {
	switch {
	case owner == OwnerUser && id.Mode != ModeRootless:
		return refuse(VerdictSocketUntrusted, "the socket belongs to you but the daemon on it reports a rootful engine")
	case owner == OwnerRoot && id.Mode != ModeRootful:
		return refuse(VerdictSocketUntrusted, "the socket belongs to root but the daemon on it reports a rootless engine")
	}
	return pass()
}
