package sandboxapple

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// argv.go composes the `container` command lines (Apple's container CLI
// command reference, checked against `container run --help` of 1.6.0 on a
// bare-metal Mac, 2026-10-24): `container run -it` with no network, the
// workspace mounted, the protected paths inside the mounts made read-only by
// the guest (--read-only-path), the capture relay's tunnel published from
// the guest (--publish-socket), labels for the orphan sweep, memory and CPU
// limits, an explicit entrypoint and no progress output; plus the list,
// inspect, remove, status, version, help and image calls the driver makes.
// `container machine` is never composed and refused wherever an argv is
// checked (N10).

// The label keys every Observer container carries.
const (
	LabelRun     = "observer.run"
	LabelInstall = "observer.install"
)

// GuestSocketDir is the run's socket dir inside the container (the bwrap
// planner's guest path, so the in-image observer's hook client finds the
// launch record where it always looks). On this row it is not a mount: the
// in-image init makes it in the container's own filesystem and serves the
// relay, proxy and gateway sockets there over the tunnel (a host unix socket
// mounted with -v does not connect from the guest: EOPNOTSUPP, live
// 2026-10-23).
const GuestSocketDir = "/tmp/.observer-sandbox-net"

// GuestTunnelDir and GuestTunnelPath are where the in-image init listens for
// the host helper's tunnel connection, published to the host with
// --publish-socket: a root-only directory in the container's own filesystem,
// so the agent (dropped to the host user's uid) can neither connect to the
// listener nor replace it.
const (
	GuestTunnelDir  = "/run/observer-apple"
	GuestTunnelPath = GuestTunnelDir + "/mux.sock"
)

// TunnelSocketName is the host end of the tunnel in the run's socket dir
// (shorter than the relay socket's name, so it fits the same socket path
// budget).
const TunnelSocketName = "mux.sock"

// RelaySecretEnv names the per-run tunnel secret in the container's
// environment file (the only entry it holds; the launch environment travels
// inside the authenticated tunnel). The init removes it before it starts
// anything.
const RelaySecretEnv = "OBSERVER_APPLE_RELAY_SECRET"

// GuestObserverPath is where the image provides its linux/arm64 observer
// (the image contract: the host's macOS binary cannot run in the
// container's Linux VM).
const GuestObserverPath = "/usr/local/bin/observer"

// Mount is one -v mount.
type Mount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

// PublishSocket is one --publish-socket: a socket the guest listens on at
// Guest, reachable from the host at Host.
type PublishSocket struct {
	Host  string `json:"host"`
	Guest string `json:"guest"`
}

// RunPlan is the pure input of RunArgv.
type RunPlan struct {
	// CLI is the absolute path of the container CLI the probe resolved.
	CLI       string `json:"cli"`
	Name      string `json:"name"`
	RunID     string `json:"run_id"`
	InstallID string `json:"install_id"`
	Image     string `json:"image"`
	MemoryMiB int    `json:"memory_mib"`
	CPUs      int    `json:"cpus"`
	// UID and GID are the host user's: the in-image init drops to them
	// before it starts the guest helper (it runs as the container's root
	// only to link the host observer path, check its mounts and serve the
	// tunnel, inside the per-run VM).
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	WorkDir string `json:"work_dir"`
	// EnvFile is the run's environment file (--env-file), written 0600 by
	// the host helper: it holds only the tunnel secret, never on the argv
	// every local user can list.
	EnvFile string  `json:"env_file,omitempty"`
	Mounts  []Mount `json:"mounts"`
	// ReadOnlyPaths are paths inside the mounts the guest re-binds
	// read-only (--read-only-path): the protect table's read-only overlays
	// and placeholders and any read-only file under a mount. A file mounted
	// with -v under a directory that is itself a mount's source drops that
	// directory mount on 1.6.0 (live 2026-10-23, D-A3), so the row never
	// mounts one.
	ReadOnlyPaths []string `json:"read_only_paths,omitempty"`
	// PublishSockets are the guest sockets published to the host (the
	// capture relay's tunnel).
	PublishSockets []PublishSocket `json:"publish_sockets,omitempty"`
	// Env are NAME=value pairs for the container (never a secret by rule:
	// the plan file that carries them holds none).
	Env []string `json:"env,omitempty"`
	// Command is the container's main process (the in-image guest init):
	// Command[0] is the entrypoint, the rest its arguments.
	Command []string `json:"command"`
}

var (
	tokenRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	nameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	envKeyRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	// DigestRE is the image rule: pinned by digest, never a tag (the
	// config's own rule, restated so this package stays a leaf).
	DigestRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$`)
)

// ContainerName is the container name of a run: the install id and a
// digest of the run id (run ids are case-sensitive and may hold '_', which
// a container name may not), so a shared machine never confuses two
// installs' runs. The labels carry the exact ids.
func ContainerName(installID, runID string) string {
	sum := sha256.Sum256([]byte(runID))
	return strings.ToLower("observer-" + installID + "-" + hex.EncodeToString(sum[:8]))
}

// ValidToken reports whether s is a run or install id shape.
func ValidToken(s string) bool { return tokenRE.MatchString(s) }

// RunArgv composes `container run -it` for plan. It refuses (never weakens)
// a plan it cannot express: a bad name, label, image, limit, mount,
// read-only path, published socket or command. The entrypoint is always
// set (an image ENTRYPOINT would otherwise run the init as its arguments)
// and the CLI's progress output is off (its spinner would land in the
// agent's terminal).
func RunArgv(p RunPlan) ([]string, error) {
	if err := checkPlan(p); err != nil {
		return nil, fmt.Errorf("sandboxapple.RunArgv: %w", err)
	}
	out := []string{
		p.CLI, "run", "-it", "--rm",
		"--progress", "none",
		"--name", p.Name,
		"-l", LabelRun + "=" + p.RunID,
		"-l", LabelInstall + "=" + p.InstallID,
		"--network", "none",
		"--memory", strconv.Itoa(p.MemoryMiB) + "M",
		"--cpus", strconv.Itoa(p.CPUs),
		"-w", p.WorkDir,
		"--entrypoint", p.Command[0],
	}
	if p.EnvFile != "" {
		out = append(out, "--env-file", p.EnvFile)
	}
	for _, e := range p.Env {
		out = append(out, "-e", e)
	}
	for _, m := range p.Mounts {
		spec := m.Source + ":" + m.Target
		if m.ReadOnly {
			spec += ":ro"
		}
		out = append(out, "-v", spec)
	}
	for _, ro := range p.ReadOnlyPaths {
		out = append(out, "--read-only-path", ro)
	}
	for _, s := range p.PublishSockets {
		out = append(out, "--publish-socket", s.Host+":"+s.Guest)
	}
	out = append(out, p.Image)
	out = append(out, p.Command[1:]...)
	if err := CheckArgv(out); err != nil {
		return nil, err
	}
	return out, nil
}

func checkPlan(p RunPlan) error {
	switch {
	case !filepath.IsAbs(p.CLI) || filepath.Clean(p.CLI) != p.CLI:
		return fmt.Errorf("the container CLI %q must be an absolute, clean path", p.CLI)
	case !ValidToken(p.RunID) || !ValidToken(p.InstallID):
		return fmt.Errorf("run id %q or install id %q is not a token", p.RunID, p.InstallID)
	case !nameRE.MatchString(p.Name):
		return fmt.Errorf("container name %q", p.Name)
	case !DigestRE.MatchString(p.Image):
		return fmt.Errorf("image %q must be pinned by digest (name@sha256:<64 hex>)", p.Image)
	case p.MemoryMiB < 512 || p.MemoryMiB > 262144:
		return fmt.Errorf("memory %d MiB out of range", p.MemoryMiB)
	case p.CPUs < 1 || p.CPUs > 64:
		return fmt.Errorf("cpus %d out of range", p.CPUs)
	case p.UID < 0 || p.GID < 0:
		return fmt.Errorf("uid and gid must not be negative")
	case len(p.Command) == 0 || strings.HasPrefix(p.Command[0], "-"):
		return fmt.Errorf("the container command is empty or flag-shaped")
	}
	if err := checkPath("entrypoint", p.Command[0]); err != nil {
		return err
	}
	if err := checkPath("work dir", p.WorkDir); err != nil {
		return err
	}
	if p.EnvFile != "" {
		if err := checkPath("env file", p.EnvFile); err != nil {
			return err
		}
	}
	for _, e := range p.Env {
		k, v, ok := strings.Cut(e, "=")
		if !ok || !envKeyRE.MatchString(k) || controlIndex(v) >= 0 {
			return fmt.Errorf("environment entry %q is not NAME=value", e)
		}
	}
	return checkPlanMounts(p)
}

// checkPlanMounts is checkPlan's filesystem part: every mount, read-only
// path and published socket is a clean absolute path, none repeats, no
// mount is the whole root, a read-only path lies under a mount and a
// published socket does not.
func checkPlanMounts(p RunPlan) error {
	seen := map[string]bool{}
	for _, m := range p.Mounts {
		if err := checkPath("mount source", m.Source); err != nil {
			return err
		}
		if err := checkPath("mount target", m.Target); err != nil {
			return err
		}
		if seen[m.Target] {
			return fmt.Errorf("two mounts at %q", m.Target)
		}
		seen[m.Target] = true
		if m.Source == "/" || m.Target == "/" {
			return fmt.Errorf("a whole-root mount is forbidden")
		}
	}
	for _, ro := range p.ReadOnlyPaths {
		if err := checkPath("read-only path", ro); err != nil {
			return err
		}
		if seen[ro] {
			return fmt.Errorf("%q is both a mount and a read-only path, or a read-only path twice", ro)
		}
		seen[ro] = true
		if !withinMounts(ro, p.Mounts) {
			// Outside every mount the path is the image's own: making it
			// read-only protects nothing the plan asked for.
			return fmt.Errorf("read-only path %q is outside every mount", ro)
		}
	}
	for _, s := range p.PublishSockets {
		if err := checkPath("published socket host path", s.Host); err != nil {
			return err
		}
		if err := checkPath("published socket guest path", s.Guest); err != nil {
			return err
		}
		if withinMounts(s.Guest, p.Mounts) {
			return fmt.Errorf("published socket %q must be in the container's own filesystem, not under a mount", s.Guest)
		}
	}
	return nil
}

// withinMounts reports whether p is a mount target or inside one.
func withinMounts(p string, mounts []Mount) bool {
	for _, m := range mounts {
		if p == m.Target || strings.HasPrefix(p, strings.TrimSuffix(m.Target, "/")+"/") {
			return true
		}
	}
	return false
}

// checkPath guards a path that rides in a "-v source:target" spec: absolute,
// clean, no control character and no ':' (the spec's separator).
func checkPath(kind, p string) error {
	switch {
	case !filepath.IsAbs(p) || filepath.Clean(p) != p:
		return fmt.Errorf("%s %q must be absolute and clean", kind, p)
	case strings.Contains(p, ":"):
		return fmt.Errorf("%s %q contains ':', which the -v spec cannot carry", kind, p)
	case controlIndex(p) >= 0:
		return fmt.Errorf("%s %q contains a control character", kind, p)
	}
	return nil
}

func controlIndex(s string) int {
	for i, r := range s {
		if r < 0x20 || r == 0x7f {
			return i
		}
	}
	return -1
}

// CheckArgv refuses an argv the driver must never run: `container machine`
// in any position before the image (N10: a shared VM that mounts the home
// read-write is no per-run layer), and a run without --network none.
func CheckArgv(argv []string) error {
	if len(argv) < 2 {
		return fmt.Errorf("sandboxapple: an empty container command")
	}
	for _, a := range argv[1:] {
		if a == "machine" || a == "machines" {
			return fmt.Errorf("sandboxapple: `container machine` is refused (nesting rule N10: a shared VM that mounts the home read-write is no per-run boundary)")
		}
		if strings.Contains(a, "@sha256:") {
			break // the image: what follows is the container's own command
		}
	}
	if argv[1] == "run" && !(len(argv) == 3 && argv[2] == "--help") {
		net := ""
		for i := 2; i+1 < len(argv); i++ {
			if argv[i] == "--network" {
				net = argv[i+1]
			}
		}
		if net != "none" {
			return fmt.Errorf("sandboxapple: a container run without --network none is refused")
		}
	}
	return nil
}

// The fixed command lines of the driver's other calls.

// ListArgv lists every container as JSON.
func ListArgv(cli string) []string { return []string{cli, "ls", "--all", "--format", "json"} }

// InspectArgv describes one container as JSON.
func InspectArgv(cli, name string) []string { return []string{cli, "inspect", name} }

// RemoveArgv removes a container, stopping it first.
func RemoveArgv(cli, name string) []string { return []string{cli, "rm", "--force", name} }

// StatusArgv asks whether the container system service runs.
func StatusArgv(cli string) []string { return []string{cli, "system", "status"} }

// VersionArgv asks the CLI for its version.
func VersionArgv(cli string) []string { return []string{cli, "--version"} }

// RunHelpArgv asks the CLI for `container run`'s options (the probe's flag
// row).
func RunHelpArgv(cli string) []string { return []string{cli, "run", "--help"} }

// ImagesArgv lists the local images as JSON.
func ImagesArgv(cli string) []string { return []string{cli, "image", "list", "--format", "json"} }

// InitSpec is what the in-image init is told besides the command it runs.
type InitSpec struct {
	// HostBin is the host observer path the agent's hooks name.
	HostBin string
	// UID and GID are the host user's, the init drops to them.
	UID, GID int
	// Relay is the run id of the capture relay's tunnel; empty runs none.
	Relay string
	// Mounts must each be a mount point in the guest, ReadOnly each a
	// read-only one (the in-guest check; ExpectedGuestMounts derives both
	// from the run plan).
	Mounts, ReadOnly []string
}

// GuestCommand is the container's main process: the in-image observer's
// apple-init, which links the host's observer path to itself (so the hooks
// the agent's settings name resolve), checks its own mounts against the
// plan, serves the relay tunnel, drops to the host user's uid and gid and
// runs the guest helper argv, then the inner launch.
func GuestCommand(spec InitSpec, guest, inner []string) ([]string, error) {
	if err := checkPath("host observer binary", spec.HostBin); err != nil {
		return nil, err
	}
	if spec.UID < 0 || spec.GID < 0 {
		return nil, fmt.Errorf("sandboxapple.GuestCommand: uid and gid must not be negative")
	}
	if spec.Relay != "" && !ValidToken(spec.Relay) {
		return nil, fmt.Errorf("sandboxapple.GuestCommand: relay run id %q is not a token", spec.Relay)
	}
	if len(inner) == 0 {
		return nil, fmt.Errorf("sandboxapple.GuestCommand: the inner launch is empty")
	}
	in := append([]string(nil), inner...)
	if in[0] == spec.HostBin {
		// The host's macOS observer cannot run in the container.
		in[0] = GuestObserverPath
	}
	out := []string{GuestObserverPath, InitVerb, "--host-bin", spec.HostBin, "--uid", strconv.Itoa(spec.UID), "--gid", strconv.Itoa(spec.GID)}
	if spec.Relay != "" {
		out = append(out, "--relay", spec.Relay)
	}
	for _, m := range spec.Mounts {
		if err := checkPath("checked mount", m); err != nil {
			return nil, err
		}
		out = append(out, "--mount", m)
	}
	for _, m := range spec.ReadOnly {
		if err := checkPath("checked read-only path", m); err != nil {
			return nil, err
		}
		out = append(out, "--ro", m)
	}
	out = append(out, "--")
	out = append(out, guest...)
	return append(out, in...), nil
}

// ExpectedGuestMounts derives the in-guest check from a run plan: every
// read-write mount's target must be a mount point; every read-only mount's
// target and every read-only path must be a read-only one.
func ExpectedGuestMounts(p RunPlan) (mounts, ro []string) {
	for _, m := range p.Mounts {
		if m.ReadOnly {
			ro = append(ro, m.Target)
			continue
		}
		mounts = append(mounts, m.Target)
	}
	return mounts, append(ro, p.ReadOnlyPaths...)
}

// InitVerb is the in-image observer's init helper verb.
const InitVerb = "sandbox-apple-init"

// InitArgs is the parsed init command line.
type InitArgs struct {
	HostBin  string
	UID, GID int
	// Relay is the tunnel's run id (empty: no tunnel).
	Relay string
	// Mounts and ReadOnly are the in-guest check's paths.
	Mounts, ReadOnly []string
	Command          []string
}

// ParseInitArgs reads `--host-bin <path> --uid N --gid N [--relay <run>]
// [--mount <path>]... [--ro <path>]... -- <argv...>`.
func ParseInitArgs(args []string) (InitArgs, error) {
	usage := fmt.Errorf("usage: %s --host-bin <path> --uid N --gid N [--relay <run>] [--mount <path>]... [--ro <path>]... -- <command>", InitVerb)
	var a InitArgs
	seen := map[string]bool{}
	i := 0
	for ; i < len(args) && args[i] != "--"; i += 2 {
		if i+1 >= len(args) {
			return InitArgs{}, usage
		}
		f, v := args[i], args[i+1]
		switch f {
		case "--host-bin", "--uid", "--gid", "--relay":
			if seen[f] {
				return InitArgs{}, usage
			}
			seen[f] = true
		}
		switch f {
		case "--host-bin":
			if err := checkPath("host observer binary", v); err != nil {
				return InitArgs{}, err
			}
			a.HostBin = v
		case "--uid", "--gid":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return InitArgs{}, fmt.Errorf("%s: bad uid or gid", InitVerb)
			}
			if f == "--uid" {
				a.UID = n
			} else {
				a.GID = n
			}
		case "--relay":
			if !ValidToken(v) {
				return InitArgs{}, fmt.Errorf("%s: bad relay run id", InitVerb)
			}
			a.Relay = v
		case "--mount", "--ro":
			if err := checkPath("checked path", v); err != nil {
				return InitArgs{}, err
			}
			if f == "--mount" {
				a.Mounts = append(a.Mounts, v)
			} else {
				a.ReadOnly = append(a.ReadOnly, v)
			}
		default:
			return InitArgs{}, usage
		}
	}
	if i >= len(args) || !seen["--host-bin"] || !seen["--uid"] || !seen["--gid"] || len(args[i+1:]) == 0 {
		return InitArgs{}, usage
	}
	a.Command = args[i+1:]
	return a, nil
}
