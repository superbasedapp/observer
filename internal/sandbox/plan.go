package sandbox

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// bwrap flag vocabulary (0.4.0 floor). The literals live here so the exact
// spelling has one owner and no caller re-types them.
const (
	flagROBind        = "--ro-bind"
	flagROBindTry     = "--ro-bind-try"
	flagBind          = "--bind"
	flagBindTry       = "--bind-try"
	flagTmpfs         = "--tmpfs"
	flagProc          = "--proc"
	flagDev           = "--dev"
	flagChdir         = "--chdir"
	flagDieWithParent = "--die-with-parent"
	flagUnshareNet    = "--unshare-net"
	flagUnsharePid    = "--unshare-pid"
	// flagNewSession puts the program in a new terminal session (setsid),
	// so it cannot push keystrokes into the caller's terminal through the
	// TIOCSTI ioctl. bwrap has had it since 0.1.x; 0.4.0 has it.
	flagNewSession = "--new-session"
	flagUnsetenv   = "--unsetenv"
	flagSymlink    = "--symlink"
	// devNull is the source bound read-only over a secret FILE to hide it
	// (a file cannot be tmpfs-masked). bwrap binds it without device
	// access, so a read inside the sandbox fails outright: the secret is
	// never readable.
	devNull = "/dev/null"
	// argSep is bwrap's end-of-options marker; the inner argv follows it.
	argSep = "--"

	// homeModeReadonly omits the $HOME tmpfs (the whole-root ro-bind still
	// makes home read-only); anything else means tmpfs-blind the home.
	homeModeReadonly = "readonly"
	homeModeTmpfs    = "tmpfs"

	// workspacesLeaf is the managed-workspaces subdir under ~/.observer that is
	// tmpfs-blinded before this run's workspace is punched back in, so parallel
	// runs cannot reach each other's trees.
	workspacesLeaf = "workspaces"
)

// Request is the pure input to BuildPlan: every path the planner needs, already
// resolved by the cmd seam. HOME-relative fields (StateRW/StateRO/
// RuntimeLadder) are joined to Home inside the planner; the rest are absolute.
//
//   - Home          native home dir (absolute); tmpfs-blinded in "tmpfs" mode.
//   - ObserverDir   ~/.observer (absolute); bound rw — the observed-invariant.
//   - WorkspaceRoot the prepared workspace (absolute); bound rw, and --chdir'd.
//   - ObserverBin   os.Executable target (absolute); ro-bound so hooks resolve.
//   - ToolBinDirs   resolved tool bin dir + its real symlink-target dir (abs).
//   - StateRW       HOME-relative dirs/files the tool must WRITE (bind-try).
//   - StateRO       HOME-relative dirs the tool only reads (ro-bind-try).
//   - RuntimeLadder HOME-relative runtime probe dirs to ro-bind-try (nvm, etc).
//   - MaskPaths     absolute foreign-OS mounts to tmpfs-mask (A1, e.g. /mnt/c).
//   - HomeMode      "tmpfs" (default) | "readonly".
//   - ExtraRO       absolute config escape-hatch ro binds.
//   - ExtraRW       absolute config escape-hatch rw binds (EXPANDS authority).
type Request struct {
	Home          string
	ObserverDir   string
	WorkspaceRoot string
	ObserverBin   string
	ToolBinDirs   []string
	StateRW       []string
	StateRO       []string
	RuntimeLadder []string
	MaskPaths     []string
	HomeMode      string
	ExtraRO       []string
	ExtraRW       []string
	// Net selects the network tier (egress.go). Its Egress must be set;
	// resolve the configured value with ResolveEgress.
	Net NetRequest
	// Overlays are authority-SHRINKING mounts applied after every rw bind
	// (including ExtraRW), so no rw bind can re-open them: state a later
	// unsandboxed session executes is re-bound read-only, and secrets the
	// sandboxed process never needs are hidden (SR27-SBX-1). An overlay whose
	// Placeholder is set names a path that does not exist yet: the host
	// helper creates it before bwrap (so the sandboxed process cannot create
	// it first) and removes it afterwards when untouched.
	Overlays []Overlay
	// Pins are existing paths inside a read-write bind (the workspace or an
	// ExtraRW entry) bound onto themselves, keeping their writability, right
	// after the ExtraRW binds (SBX-WORKTREE-SOURCE audit finding 4): a mount
	// point cannot be renamed or replaced (EBUSY), so a box cannot move a
	// repository folder or its .git aside and plant a replacement that the
	// protective overlays over .git/hooks and .git/config would no longer
	// cover. A pin outside every read-write bind is refused (it would make a
	// read-only path writable); a missing one is skipped (--bind-try).
	Pins []string
	// SocketSweeps rebuild the SocketSweepDirs (e.g. /run) as a tmpfs that
	// re-binds every entry the cmd seam kept, dropping every socket and FIFO
	// directly inside (bwrap 0.4.0 cannot mount over a socket, so a socket
	// is hidden by rebuilding its parent without it). Applied right after
	// MaskPaths, before HostMasks.
	SocketSweeps []DirRebuild
	// HostMasks hide host UNIX-socket and platform-interop directories that
	// the read-only root bind would otherwise expose (HostSocketPaths,
	// resolved and existence-checked by the cmd seam): hide_dir or hide_file
	// only, never a placeholder. Applied after SocketSweeps, before the
	// punch-backs, like the foreign-OS masks.
	HostMasks []Overlay
	// HostMaskKeep are absolute files a HostMask would hide but the
	// sandboxed process still needs read-only (the resolver config
	// /etc/resolv.conf points into /mnt/wsl on WSL). Re-bound read-only
	// right after HostMasks.
	HostMaskKeep []string
	// Relay, when its RunID is set, routes the run's capture through the
	// capture relay (sandbox plan section 5.2, lane sbx-p2): ObserverDir is
	// a tmpfs inside the box instead of a read-write bind (the node DB is
	// absent; only the read-only overlays the cmd seam lists show through),
	// the per-run socket dir is always bound read-only at GuestSocketDir,
	// and the host helper always runs (it serves the relay socket).
	Relay RelayRequest
	// ResolvePath, when set, resolves every symlink in an absolute path
	// (the cmd seam passes filepath.EvalSymlinks, falling back to the path
	// itself). The relay's bind check runs on the written and the resolved
	// spelling, so a bind named through a link cannot show the observer dir
	// in a box. nil checks the written spelling only.
	ResolvePath func(string) string
}

// RelayRequest is the relay input of a plan.
type RelayRequest struct {
	// RunID is the run's id (the run record's key); empty plans no relay.
	RunID string
	// HostObserverDir is the observer directory on the host, where the
	// helper reads the run record and dials the daemon (never visible in
	// the box).
	HostObserverDir string
}

// Enabled reports whether the plan routes capture through the relay.
func (r RelayRequest) Enabled() bool { return r.RunID != "" }

// DirRebuild is one SocketSweeps row: Path is replaced by an empty tmpfs and
// each Keep entry is put back (a read-only bind of the host entry, or the
// same symlink).
type DirRebuild struct {
	Path string
	Keep []RebuildEntry
}

// RebuildEntry is one entry put back into a rebuilt directory. Name is a
// single path component. A non-empty Symlink recreates the entry as a
// symlink to that target; otherwise the host entry is bound read-only.
type RebuildEntry struct {
	Name    string
	Symlink string
}

// OverlayKind is the closed vocabulary of protective overlays.
type OverlayKind string

const (
	// OverlayReadOnly re-binds an existing path read-only (ro-bind-try, a
	// missing path is skipped). A read-only file mount also refuses rename
	// and unlink (EBUSY), so the file cannot be replaced either.
	OverlayReadOnly OverlayKind = "ro"
	// OverlayHideDir masks a directory with an empty tmpfs.
	OverlayHideDir OverlayKind = "hide_dir"
	// OverlayHideFile binds /dev/null read-only over an existing file.
	OverlayHideFile OverlayKind = "hide_file"
)

// Placeholder marks an overlay whose path does not exist at launch.
type Placeholder string

const (
	// PlaceholderNone is an overlay over an existing path.
	PlaceholderNone Placeholder = ""
	// PlaceholderFile: the host helper creates a regular file (with
	// PlaceholderContent) before bwrap and removes it afterwards if it is
	// still the one it created, unchanged.
	PlaceholderFile Placeholder = "file"
	// PlaceholderDir: the host helper creates an empty directory before
	// bwrap and removes it afterwards if it is still the one it created and
	// still empty.
	PlaceholderDir Placeholder = "dir"
)

// Overlay is one protective mount. Path is absolute.
type Overlay struct {
	Path        string
	Kind        OverlayKind
	Placeholder Placeholder
}

// ProtectedPath is one row of a protected-path table: a path relative to
// some root, and whether it is a directory (which decides the placeholder
// shape when the path is missing at launch).
type ProtectedPath struct {
	Rel string
	Dir bool
}

// WorkspaceExecState lists workspace-relative paths that steer which config
// the host's git reads or which program it runs, but a normal diff review
// never shows (the repository config drives core.fsmonitor / core.hooksPath /
// aliases / uploadpack.packObjectsHook; the hooks dir runs on the next host
// commit; commondir and config.worktree redirect git at another config and
// hooks; info/attributes names filter and diff drivers; objects/info/alternates
// redirects git at a planted object store). Every one is proven with real git
// (docs/sandboxed-terminals.md "Git-dir execution paths"); the live Mac D1
// escape planted .git/commondir, which was not on this table and so was not
// protected (ledger SBX-BE-21). The cmd seam turns each into a read-only
// overlay under the workspace root; a missing one under a writable bind
// becomes a read-only placeholder its box can neither replace nor create
// (.git always holds objects/info and info after an init, so each file lands
// as a file placeholder, never an over-broad directory). commondir's
// placeholder is "." (PlaceholderContent): an empty commondir is fatal to git
// while "." points the common dir back at the git dir itself, which is a
// non-worktree repository's own layout, so the box's own git still works.
// Linked-worktree (.git/worktrees/*) and submodule (.git/modules/*) git dirs
// carry the same paths. A live workspace's own linked-worktree git dirs get
// these rows, relative to each git dir, and are pinned (lane LEFT-SBX,
// ledger SBX-BE-21 residual closed); an org write bind's repositories get
// them for their own .git, their linked-worktree and their submodule git
// dirs (sandbox_orgbind_git.go); and for the copy-return and worktree-return
// paths the return-step scan catches them recursively (internal/workspace
// ScanGitDirExecRisk). Adding a path is adding a row: every driver and the
// org-bind rows read this one table.
var WorkspaceExecState = []ProtectedPath{
	{Rel: ".git/config"},
	{Rel: ".git/hooks", Dir: true},
	{Rel: ".git/commondir"},
	{Rel: ".git/config.worktree"},
	{Rel: ".git/info/attributes"},
	{Rel: ".git/objects/info/alternates"},
}

// GitDirExecParents returns the folders between the git dir gitDir and each
// WorkspaceExecState path inside it (for the table today: info, objects and
// objects/info), parents first. A read-only overlay is a mount on the path
// itself, and a mount moves with its parent folder when that folder is
// renamed: inside the box `mv .git/info .git/info-moved`, then a fresh
// `.git/info/attributes`, succeeded on every row and the host's git read it
// (Linux live re-check 3, 2026-10-23, D2). So every row that pins the .git
// also pins each of these folders onto itself (EBUSY on a rename), by the
// same nearest-bind rule; the list is derived from the table, so a new row
// brings its own folders.
func GitDirExecParents(gitDir string) []string {
	var out []string
	seen := map[string]bool{}
	for _, pp := range WorkspaceExecState {
		rel := strings.TrimPrefix(filepath.ToSlash(pp.Rel), ".git/")
		parts := strings.Split(rel, "/")
		for i := 1; i < len(parts); i++ {
			p := strings.Join(parts[:i], "/")
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.Count(out[i], "/") < strings.Count(out[j], "/") })
	for i, p := range out {
		out[i] = filepath.Join(gitDir, filepath.FromSlash(p))
	}
	return out
}

// placeholderContents is the body a file placeholder is created with, keyed
// by extension: a JSON config reads as an empty object (what "no settings"
// means to a JSON reader, where an empty file is a parse error); every other
// file is empty (an empty TOML policy is "no policy").
var placeholderContents = map[string]string{
	".json": "{}\n",
}

// placeholderBasenames is the body a file placeholder is created with when
// its base name needs a specific neutral value rather than an empty file. A
// git commondir read as the empty string is fatal ("fatal: failed to read
// commondir"), so an empty placeholder would break the box's own git; "."
// points the common dir back at the git dir itself, which is exactly a
// non-worktree repository's own layout and reads as neutral (proven with real
// git on the host 2.25.1 and named by the live Mac 2.50.1 escape). A commondir
// placeholder the box can neither replace nor create therefore neither breaks
// the box nor lets it redirect the host's git at a planted config or hooks.
var placeholderBasenames = map[string]string{
	"commondir": ".\n",
}

// PlaceholderContent returns the body a file placeholder at path is created
// with (and must still hold for the helper to remove it afterwards). A base
// name in placeholderBasenames wins over the extension table.
func PlaceholderContent(path string) []byte {
	if c, ok := placeholderBasenames[filepath.Base(path)]; ok {
		return []byte(c)
	}
	return []byte(placeholderContents[strings.ToLower(filepath.Ext(path))])
}

// HostSocketPaths are host DIRECTORIES that carry UNIX sockets or platform
// interop a sandboxed process could otherwise reach through the read-only
// root bind (security ledger SR27-SBX-2): the per-user runtime dir (D-Bus
// session bus, systemd user manager, gpg-agent, ssh-agent, PipeWire,
// rootless container sockets), the WSL interop sockets (with binfmt
// WSLInterop a sandboxed process could otherwise run Windows binaries
// OUTSIDE the sandbox), the system bus, container engine, screen and
// tailscaled socket dirs, and the WSLg / cross-distro mounts. "{uid}" is the
// caller's numeric uid. The cmd seam resolves each through symlinks, keeps
// the ones that exist and hides each with an empty tmpfs. Socket FILES
// directly under /run (docker.sock, snapd.socket, ...) are dropped by the
// SocketSweepDirs rebuild instead. Adding a path is adding a row.
var HostSocketPaths = []string{
	"/run/user/{uid}",
	"/run/WSL",
	"/run/dbus",
	"/run/docker",
	"/run/containerd",
	"/run/podman",
	"/run/screen",
	"/run/tailscale",
	"/mnt/wslg",
	"/mnt/wsl",
}

// SocketSweepDirs are directories rebuilt without the sockets and FIFOs
// directly inside them (docker.sock, snapd.socket, and any socket a daemon
// drops there that this table does not name). A path that is a symlink on
// the host (/var/run -> /run) is skipped by the cmd seam.
var SocketSweepDirs = []string{"/run", "/var/run"}

// ExpandHostSocketPaths substitutes uid into HostSocketPaths.
func ExpandHostSocketPaths(uid int) []string {
	out := make([]string, 0, len(HostSocketPaths))
	for _, p := range HostSocketPaths {
		out = append(out, strings.ReplaceAll(p, "{uid}", strconv.Itoa(uid)))
	}
	return out
}

// GuestUnsetEnv lists environment variables removed from the sandboxed
// process (bwrap --unsetenv): each one points a client at a host socket or
// interop channel the host masks hide anyway (so a tool fails fast instead
// of timing out), or carries an Observer secret the sandboxed tool never
// needs. Adding a variable is adding a row.
var GuestUnsetEnv = []string{
	"WSL_INTEROP",
	"WSLENV",
	"DBUS_SESSION_BUS_ADDRESS",
	"DBUS_SYSTEM_BUS_ADDRESS",
	"SSH_AUTH_SOCK",
	"SSH_AGENT_PID",
	"GPG_AGENT_INFO",
	"DOCKER_HOST",
	"CONTAINER_HOST",
	"DISPLAY",
	"WAYLAND_DISPLAY",
	"XAUTHORITY",
	"PULSE_SERVER",
	"OBSERVER_LOC_EDITOR_TOKEN",
}

// Plan is the composed, validated bwrap argv (everything from `--ro-bind / /`
// through `--die-with-parent`, excluding the bwrap executable and the inner
// argv). HomeMode records the normalized home mode for display. Build it with
// BuildPlan; render the full launch argv with Argv.
type Plan struct {
	pre   []string
	guest []string
	net   NetRequest
	relay RelayRequest
	// placeholders are the overlays whose path the host helper must create
	// before bwrap runs (Plan.HostArgv carries them).
	placeholders []Overlay
	HomeMode     string
	// Egress is the resolved network tier row the plan was built for.
	Egress EgressProfile
}

// Placeholders returns the protected paths the host helper will create
// before bwrap and remove afterwards (a copy).
func (p Plan) Placeholders() []Overlay {
	return append([]Overlay(nil), p.placeholders...)
}

// Argv returns the exec argv AFTER the bwrap executable: the ordered bwrap
// flags, the `--` end-of-options marker, then the inner argv. The caller
// prepends the resolved bwrap path (the pure planner does not know it — it is
// not in Request). `--` is placed IMMEDIATELY before inner. It returns nil when
// inner is empty or inner[0] begins with '-' (a flag-shaped program name would
// be swallowed by bwrap as one of its own options).
func (p Plan) Argv(inner []string) []string {
	if len(inner) == 0 {
		return nil
	}
	if strings.HasPrefix(inner[0], "-") {
		return nil
	}
	out := make([]string, 0, len(p.pre)+1+len(p.guest)+len(inner))
	out = append(out, p.pre...)
	out = append(out, argSep)
	out = append(out, p.guest...)
	out = append(out, inner...)
	return out
}

// BuildPlan composes the ordered bwrap flag sequence (§3) from req. The order
// is load-bearing and mutation-proofed: the $HOME tmpfs precedes every
// under-home bind, and the ~/.observer/workspaces tmpfs precedes the workspace
// rw bind — otherwise a punch-back would be shadowed by a later blinding.
//
// It returns an error rather than emit an unsafe argv when any resolved bind
// path is not absolute, contains a ".." segment, begins with '-', contains a
// NUL / whitespace / control character, or is "/" for an rw bind (a whole-root
// rw bind is forbidden; `--ro-bind / /` is the only whole-root and it is
// read-only). HOME-relative inputs are additionally rejected if absolute, ".",
// empty, or "..".
func BuildPlan(req Request) (Plan, error) {
	var pre []string
	add := func(tokens ...string) { pre = append(pre, tokens...) }

	prof, netFlags, guest, err := planNet(req)
	if err != nil {
		return Plan{}, fmt.Errorf("sandbox.BuildPlan: network: %w", err)
	}

	// 1. Whole host root, read-only — gives /etc, /usr, runtimes, symlink
	//    targets for free. The single deliberate whole-root bind, and it is ro.
	//    A private PID namespace (with a fresh /proc) means no host process
	//    can be signalled, ptrace-probed or have its command line read from
	//    inside; bwrap's own init reaps the tree, and when it exits every
	//    process in the namespace is killed.
	add(flagROBind, "/", "/")
	add(flagUnsharePid)
	add(flagProc, "/proc")
	add(flagDev, "/dev") // fresh devtmpfs the TUIs need; stdio already open.
	add(flagTmpfs, "/tmp")
	// 1b. Network tier: a private namespace (loopback only) removes the
	//     host's 127.0.0.1 - and with it the daemon's dashboard - from reach.
	//     The per-run socket dir is bound read-only into the private /tmp so
	//     the guest can connect() (sockets ignore the ro flag) but nothing can
	//     unlink or replace them, and no other run's sockets are visible.
	add(netFlags...)

	// 2. Blind $HOME (removes ~/.ssh, ~/.aws, every other tool's creds and
	//    every other repo) BEFORE any under-home punch-back. Omitted in
	//    "readonly" mode, where the ro-bind / / already makes home read-only.
	homeMode := homeModeTmpfs
	if req.HomeMode == homeModeReadonly {
		homeMode = homeModeReadonly
	}
	if homeMode == homeModeTmpfs {
		if err := validateAbs(req.Home, false); err != nil {
			return Plan{}, fmt.Errorf("sandbox.BuildPlan: home: %w", err)
		}
		add(flagTmpfs, req.Home)
	}

	// 3. A1: mask foreign-OS mounts (/mnt/c-class) that ro-bind / / would leave
	//    readable — after the home tmpfs, BEFORE the punch-backs, so a tool or
	//    workspace path legitimately under a masked root is re-bound explicitly
	//    by the later ordered binds.
	for _, m := range req.MaskPaths {
		if err := validateAbs(m, false); err != nil {
			return Plan{}, fmt.Errorf("sandbox.BuildPlan: mask path: %w", err)
		}
		add(flagTmpfs, m)
	}
	// 3b. Host UNIX sockets and platform interop: sweep the socket files out
	//     of SocketSweepDirs, then hide the socket-bearing dirs
	//     (HostSocketPaths), at the same point as the foreign-OS masks.
	hostIso, err := hostIsolationArgs(req)
	if err != nil {
		return Plan{}, fmt.Errorf("sandbox.BuildPlan: %w", err)
	}
	pre = append(pre, hostIso...)

	// 4. Derived read-only binaries + runtimes (ro-bind-try, tolerate missing),
	//    deduped by absolute source path (the ladder legitimately overlaps a
	//    tool bin dir): tool bin dirs, observer bin, runtime ladder, StateRO.
	roArgs, err := roBinaryArgs(req)
	if err != nil {
		return Plan{}, err
	}
	pre = append(pre, roArgs...)

	// 5. ~/.observer. Without the relay it is bound rw (the observed-
	//    invariant: hook DB writes + inner launcher config read; mutation
	//    proof #3 pins it rw). With the relay (lane sbx-p2) it is a tmpfs:
	//    the node DB, every secret and every record of other runs are absent
	//    in the box; the read-only overlays (step 10) put back exactly the
	//    executed-state files the inner launcher reads.
	obsArgs, err := observerDirArgs(req)
	if err != nil {
		return Plan{}, fmt.Errorf("sandbox.BuildPlan: %w", err)
	}
	add(obsArgs...)

	// 6. Blind the managed-workspaces tree, THEN punch this run's workspace
	//    back in rw. The tmpfs MUST precede the workspace bind (mutation #2).
	wsParent := filepath.Join(req.ObserverDir, workspacesLeaf)
	add(flagTmpfs, wsParent)
	if err := validateAbs(req.WorkspaceRoot, true); err != nil {
		return Plan{}, fmt.Errorf("sandbox.BuildPlan: workspace root: %w", err)
	}
	add(flagBind, req.WorkspaceRoot, req.WorkspaceRoot)

	// 7. Per-tool writable state (bind-try, tolerate missing).
	for _, rel := range req.StateRW {
		p, err := joinHomeRel(req.Home, rel)
		if err != nil {
			return Plan{}, fmt.Errorf("sandbox.BuildPlan: state rw %q: %w", rel, err)
		}
		if err := validateAbs(p, true); err != nil {
			return Plan{}, fmt.Errorf("sandbox.BuildPlan: state rw %q: %w", rel, err)
		}
		add(flagBindTry, p, p)
	}

	// 8. Config escape hatches: ro first, then authority-EXPANDING rw.
	for _, p := range req.ExtraRO {
		if err := validateAbs(p, false); err != nil {
			return Plan{}, fmt.Errorf("sandbox.BuildPlan: extra ro bind: %w", err)
		}
		add(flagROBind, p, p)
	}
	for _, p := range req.ExtraRW {
		if err := validateAbs(p, true); err != nil {
			return Plan{}, fmt.Errorf("sandbox.BuildPlan: extra rw bind: %w", err)
		}
		add(flagBind, p, p)
	}

	// 8a. Pins: repository folders and their .git under a read-write bind,
	//     bound onto themselves so the box cannot rename them. Before the
	//     re-protections and overlays below, so a pin never re-opens one.
	pinRoots := append([]string{req.WorkspaceRoot}, req.ExtraRW...)
	for _, p := range req.Pins {
		if err := validateAbs(p, true); err != nil {
			return Plan{}, fmt.Errorf("sandbox.BuildPlan: pin: %w", err)
		}
		if !underAny(p, pinRoots) {
			return Plan{}, fmt.Errorf("sandbox.BuildPlan: pin %q lies outside every read-write bind", p)
		}
		add(flagBindTry, p, p)
	}

	// 8b. With the relay, a workspace that is a parent of the observer dir
	//     must not show it again (lane sbx-p2b).
	add(relayObserverReblind(req)...)

	// 9. Re-protect binaries that an rw bind above re-exposed writable (e.g.
	//    an observer or tool binary installed under ~/.observer or a tool
	//    state dir): a later unsandboxed session executes them. A dir that
	//    CONTAINS an rw target is skipped - re-binding it read-only would
	//    shadow that target.
	pre = append(pre, reprotectBins(req)...)

	// 10. Protective overlays LAST, so no rw bind (not even ExtraRW) can
	//     re-open them.
	ov, err := overlayArgs(req.Overlays)
	if err != nil {
		return Plan{}, fmt.Errorf("sandbox.BuildPlan: %w", err)
	}
	pre = append(pre, ov...)

	// 11. Drop the environment that points at host sockets / interop, or
	//     carries an Observer secret (GuestUnsetEnv).
	pre = append(pre, unsetEnvArgs()...)

	// 12. Enter the workspace and die with the daemon.
	add(flagChdir, req.WorkspaceRoot)
	add(flagDieWithParent)

	return Plan{pre: pre, guest: guest, net: req.Net, relay: req.Relay, placeholders: placeholdersOf(req.Overlays), HomeMode: homeMode, Egress: prof}, nil
}

// roBinaryArgs is BuildPlan's step 4: the derived read-only binaries and
// runtimes (ro-bind-try, tolerating missing), deduped by absolute source
// path: tool bin dirs, observer bin, runtime ladder, StateRO.
func roBinaryArgs(req Request) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	roTry := func(p string) error {
		if err := validateAbs(p, false); err != nil {
			return err
		}
		if seen[p] {
			return nil
		}
		seen[p] = true
		out = append(out, flagROBindTry, p, p)
		return nil
	}
	for _, d := range req.ToolBinDirs {
		if err := roTry(d); err != nil {
			return nil, fmt.Errorf("sandbox.BuildPlan: tool bin dir: %w", err)
		}
	}
	if req.ObserverBin != "" {
		if err := roTry(req.ObserverBin); err != nil {
			return nil, fmt.Errorf("sandbox.BuildPlan: observer bin: %w", err)
		}
	}
	for _, rel := range req.RuntimeLadder {
		p, err := joinHomeRel(req.Home, rel)
		if err != nil {
			return nil, fmt.Errorf("sandbox.BuildPlan: runtime ladder %q: %w", rel, err)
		}
		if err := roTry(p); err != nil {
			return nil, fmt.Errorf("sandbox.BuildPlan: runtime ladder %q: %w", rel, err)
		}
	}
	for _, rel := range req.StateRO {
		p, err := joinHomeRel(req.Home, rel)
		if err != nil {
			return nil, fmt.Errorf("sandbox.BuildPlan: state ro %q: %w", rel, err)
		}
		if err := roTry(p); err != nil {
			return nil, fmt.Errorf("sandbox.BuildPlan: state ro %q: %w", rel, err)
		}
	}
	return out, nil
}

// observerDirArgs renders step 5: a tmpfs over the observer dir with the
// relay, a read-write bind without it.
func observerDirArgs(req Request) ([]string, error) {
	if err := validateAbs(req.ObserverDir, true); err != nil {
		return nil, fmt.Errorf("observer dir: %w", err)
	}
	if !req.Relay.Enabled() {
		return []string{flagBind, req.ObserverDir, req.ObserverDir}, nil
	}
	if err := validateRelay(req); err != nil {
		return nil, fmt.Errorf("relay: %w", err)
	}
	if err := validateRelayBinds(req); err != nil {
		return nil, fmt.Errorf("relay: %w", err)
	}
	return []string{flagTmpfs, req.ObserverDir}, nil
}

// validateRelayBinds refuses a bind that would undo the observer dir's tmpfs
// in a relayed box (plans decision log P-026, lane sbx-p2b): a StateRW,
// ExtraRO or ExtraRW entry that is the observer dir, one of its parents, or
// a path inside it (other than the managed workspaces tree) would show the
// node database, the run records, their secrets and the daemon's link
// socket. Checked on the written and the resolved spelling.
func validateRelayBinds(req Request) error {
	check := func(kind, p string) error { return CheckObserverDirBind(kind, p, req.ObserverDir, req.ResolvePath) }
	for _, rel := range req.StateRW {
		p, err := joinHomeRel(req.Home, rel)
		if err != nil {
			continue // BuildPlan's own state rw check reports it
		}
		if err := check("state rw bind", p); err != nil {
			return err
		}
	}
	for _, p := range req.ExtraRO {
		if err := check("extra ro bind", p); err != nil {
			return err
		}
	}
	for _, p := range req.ExtraRW {
		if err := check("extra rw bind", p); err != nil {
			return err
		}
	}
	return nil
}

// CheckObserverDirBind is the relay's observer-dir rule for one bind of p
// (kind names it in the refusal): p, on its written and its resolved
// spelling (resolve may be nil), may not be the observer directory, one of
// its parents, or a path inside it outside the managed workspaces tree. It
// is the ONE owner of the rule: bwrap's validateRelayBinds and the oci-runc
// driver's bind check both call it (SBX-P3A merge finding F1).
func CheckObserverDirBind(kind, p, observerDir string, resolve func(string) string) error {
	for _, q := range spellingsOf(p, resolve) {
		for _, obs := range spellingsOf(observerDir, resolve) {
			if observerDirExposed(obs, q) {
				return fmt.Errorf("%s %q would show the observer directory %q inside the sandbox; the capture relay keeps it hidden", kind, p, observerDir)
			}
		}
	}
	return nil
}

// resolvedSpellings returns p and, when the request resolves paths and the
// resolved form differs, that form too.
func resolvedSpellings(req Request, p string) []string { return spellingsOf(p, req.ResolvePath) }

// spellingsOf returns p and, when resolve gives a different form, that form
// too.
func spellingsOf(p string, resolve func(string) string) []string {
	out := []string{filepath.Clean(p)}
	if resolve != nil {
		if r := resolve(p); r != "" && r != out[0] {
			out = append(out, filepath.Clean(r))
		}
	}
	return out
}

// observerDirExposed reports whether a bind of p shows any of the observer
// dir obs: p is obs or a parent of it, or p lies inside obs outside the
// managed workspaces tree.
func observerDirExposed(obs, p string) bool {
	if isWithin(obs, p) {
		return true
	}
	return isWithin(p, obs) && !isWithin(p, filepath.Join(obs, workspacesLeaf))
}

// relayObserverReblind renders step 8b: with the relay on, when the
// workspace (the one bind that may legitimately be a parent of the
// observer dir, a project at the home directory) shows the observer dir
// again, the dir is blinded once more after every rw bind, before the
// overlays put back the files the inner launcher reads.
func relayObserverReblind(req Request) []string {
	if !req.Relay.Enabled() {
		return nil
	}
	for _, q := range resolvedSpellings(req, req.WorkspaceRoot) {
		for _, obs := range resolvedSpellings(req, req.ObserverDir) {
			if isWithin(obs, q) {
				return []string{flagTmpfs, req.ObserverDir}
			}
		}
	}
	return nil
}

// validateRelay checks the relay fields: a run-id-shaped id, an absolute
// host observer dir and the per-run socket dir the relay socket lives in.
func validateRelay(req Request) error {
	if !validRunToken(req.Relay.RunID) {
		return fmt.Errorf("run id %q must be 1 to 64 of [A-Za-z0-9_-]", req.Relay.RunID)
	}
	if err := validateAbs(req.Relay.HostObserverDir, false); err != nil {
		return fmt.Errorf("host observer dir: %w", err)
	}
	if err := validateSockDir(req.Net.HostSocketDir); err != nil {
		return err
	}
	return nil
}

// validRunToken is the run id shape (sandboxrelay.ValidRunID's rule,
// restated so this pure package imports nothing).
func validRunToken(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// hostIsolationArgs renders step 3b: the SocketSweeps rebuilds, the
// HostMasks and the HostMaskKeep re-binds, in that order.
func hostIsolationArgs(req Request) ([]string, error) {
	var out []string
	for _, d := range req.SocketSweeps {
		sweep, err := sweepArgs(d)
		if err != nil {
			return nil, err
		}
		out = append(out, sweep...)
	}
	for _, m := range req.HostMasks {
		if m.Placeholder != PlaceholderNone || (m.Kind != OverlayHideDir && m.Kind != OverlayHideFile) {
			return nil, fmt.Errorf("host mask %q must be hide_dir or hide_file with no placeholder", m.Path)
		}
	}
	hm, err := overlayArgs(req.HostMasks)
	if err != nil {
		return nil, fmt.Errorf("host mask: %w", err)
	}
	out = append(out, hm...)
	for _, k := range req.HostMaskKeep {
		if err := validateAbs(k, false); err != nil {
			return nil, fmt.Errorf("host mask keep: %w", err)
		}
		out = append(out, flagROBindTry, k, k)
	}
	return out, nil
}

// sweepArgs renders one DirRebuild: a tmpfs over the directory, then each
// kept entry put back (read-only bind, or the same symlink).
func sweepArgs(d DirRebuild) ([]string, error) {
	if err := validateAbs(d.Path, true); err != nil {
		return nil, fmt.Errorf("socket sweep: %w", err)
	}
	out := []string{flagTmpfs, d.Path}
	for _, e := range d.Keep {
		if e.Name == "" || e.Name == "." || e.Name == ".." || strings.Contains(e.Name, "/") {
			return nil, fmt.Errorf("socket sweep %q: bad entry name %q", d.Path, e.Name)
		}
		p := d.Path + "/" + e.Name
		if err := validateAbs(p, false); err != nil {
			return nil, fmt.Errorf("socket sweep entry: %w", err)
		}
		if e.Symlink != "" {
			if strings.HasPrefix(e.Symlink, "-") || badCharIndex(e.Symlink) >= 0 {
				return nil, fmt.Errorf("socket sweep entry %q: bad symlink target %q", p, e.Symlink)
			}
			out = append(out, flagSymlink, e.Symlink, p)
			continue
		}
		out = append(out, flagROBind, p, p)
	}
	return out, nil
}

// joinHomeRel validates a HOME-relative input and joins it to home, then
// validates the resulting absolute path. The rel is rejected if absolute,
// empty, ".", contains a ".." segment, begins with '-', or carries a NUL /
// whitespace / control character — so it can neither escape home nor smuggle a
// flag.
func joinHomeRel(home, rel string) (string, error) {
	if err := validateRel(rel); err != nil {
		return "", err
	}
	p := filepath.Join(home, rel)
	if err := validateAbs(p, false); err != nil {
		return "", err
	}
	return p, nil
}

// validateRel guards a HOME-relative path before it is joined to home.
func validateRel(rel string) error {
	if rel == "" || rel == "." {
		return fmt.Errorf("empty HOME-relative path")
	}
	if filepath.IsAbs(rel) {
		return fmt.Errorf("%q must be HOME-relative, not absolute", rel)
	}
	if strings.HasPrefix(rel, "-") {
		return fmt.Errorf("%q must not begin with '-'", rel)
	}
	if hasDotDot(rel) {
		return fmt.Errorf("%q must not contain a '..' segment", rel)
	}
	if i := badCharIndex(rel); i >= 0 {
		return fmt.Errorf("%q contains a NUL, whitespace, or control character", rel)
	}
	return nil
}

// validateAbs guards a resolved bind path. rw marks a writable bind, for which
// the whole-root "/" is additionally forbidden.
func validateAbs(p string, rw bool) error {
	if p == "" {
		return fmt.Errorf("empty path")
	}
	if strings.HasPrefix(p, "-") {
		return fmt.Errorf("%q must not begin with '-'", p)
	}
	if i := badCharIndex(p); i >= 0 {
		return fmt.Errorf("%q contains a NUL, whitespace, or control character", p)
	}
	if hasDotDot(p) {
		return fmt.Errorf("%q must not contain a '..' segment", p)
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%q must be absolute", p)
	}
	if rw && filepath.Clean(p) == "/" {
		return fmt.Errorf("a whole-root rw bind (%q) is forbidden", p)
	}
	return nil
}

// planNet resolves the network tier: its row, the bwrap flags it adds right
// after the private /tmp, and the guest-helper prefix for the inner argv.
func planNet(req Request) (EgressProfile, []string, []string, error) {
	prof, err := resolveNet(req.Net)
	if err != nil {
		return EgressProfile{}, nil, nil, err
	}
	var flags, guest []string
	if prof.UnshareNet {
		flags = append(flags, flagUnshareNet)
	}
	if prof.ForwardProxy || prof.Gateway {
		if err := validateAbs(req.ObserverBin, false); err != nil {
			return EgressProfile{}, nil, nil, fmt.Errorf("the network helper needs the observer bin: %w", err)
		}
		flags = append(flags, flagROBind, req.Net.HostSocketDir, GuestSocketDir)
		guest = guestArgv(req.ObserverBin, prof, req.Net)
	} else if req.Relay.Enabled() {
		// The relay socket and the launch record live in the socket dir
		// whatever the tier forwards.
		if err := validateSockDir(req.Net.HostSocketDir); err != nil {
			return EgressProfile{}, nil, nil, err
		}
		flags = append(flags, flagROBind, req.Net.HostSocketDir, GuestSocketDir)
	}
	return prof, flags, guest, nil
}

// reprotectBins returns ro-bind-try flags for every tool bin dir / observer
// binary that lies under one of the plan's rw bind targets (and does not
// itself contain one), deduped.
func reprotectBins(req Request) []string {
	rwTargets := []string{req.WorkspaceRoot}
	if !req.Relay.Enabled() {
		rwTargets = append(rwTargets, req.ObserverDir)
	}
	for _, rel := range req.StateRW {
		rwTargets = append(rwTargets, filepath.Join(req.Home, rel))
	}
	rwTargets = append(rwTargets, req.ExtraRW...)
	bins := append([]string(nil), req.ToolBinDirs...)
	if req.ObserverBin != "" {
		bins = append(bins, req.ObserverBin)
	}
	var out []string
	seen := map[string]bool{}
	for _, b := range bins {
		if seen[b] || !underAny(b, rwTargets) || containsAny(b, rwTargets) {
			continue
		}
		seen[b] = true
		out = append(out, flagROBindTry, b, b)
	}
	return out
}

// unsetEnvArgs renders one --unsetenv per GuestUnsetEnv row.
func unsetEnvArgs() []string {
	out := make([]string, 0, 2*len(GuestUnsetEnv))
	for _, v := range GuestUnsetEnv {
		out = append(out, flagUnsetenv, v)
	}
	return out
}

// placeholdersOf returns the overlays whose path the host helper must create.
func placeholdersOf(overlays []Overlay) []Overlay {
	var out []Overlay
	for _, o := range overlays {
		if o.Placeholder != PlaceholderNone {
			out = append(out, o)
		}
	}
	return out
}

// overlayArgs renders the protective overlays, in order. A placeholder
// overlay is bound strictly (--ro-bind, never -try): the host helper has
// created the path, so a missing one is a failure, never a silent skip.
func overlayArgs(overlays []Overlay) ([]string, error) {
	var out []string
	for _, o := range overlays {
		if err := validateAbs(o.Path, true); err != nil {
			return nil, fmt.Errorf("overlay: %w", err)
		}
		switch o.Placeholder {
		case PlaceholderNone, PlaceholderFile, PlaceholderDir:
		default:
			return nil, fmt.Errorf("overlay %q: unknown placeholder %q", o.Path, o.Placeholder)
		}
		if (o.Kind == OverlayHideDir && o.Placeholder == PlaceholderFile) || (o.Kind == OverlayHideFile && o.Placeholder == PlaceholderDir) {
			return nil, fmt.Errorf("overlay %q: kind %q does not fit a %s placeholder", o.Path, o.Kind, o.Placeholder)
		}
		switch o.Kind {
		case OverlayReadOnly:
			if o.Placeholder != PlaceholderNone {
				out = append(out, flagROBind, o.Path, o.Path)
			} else {
				out = append(out, flagROBindTry, o.Path, o.Path)
			}
		case OverlayHideDir:
			out = append(out, flagTmpfs, o.Path)
		case OverlayHideFile:
			out = append(out, flagROBind, devNull, o.Path)
		default:
			return nil, fmt.Errorf("overlay %q: unknown kind %q", o.Path, o.Kind)
		}
	}
	return out, nil
}

// underAny reports whether p equals or lies under any of roots.
func underAny(p string, roots []string) bool {
	for _, r := range roots {
		if r != "" && isWithin(p, r) {
			return true
		}
	}
	return false
}

// containsAny reports whether any of targets equals or lies under p.
func containsAny(p string, targets []string) bool {
	for _, t := range targets {
		if t != "" && isWithin(t, p) {
			return true
		}
	}
	return false
}

// isWithin reports whether p equals root or is a descendant of it (clean,
// '/'-separated absolute paths).
func isWithin(p, root string) bool {
	p, root = filepath.Clean(p), filepath.Clean(root)
	if p == root || root == "/" {
		return true
	}
	return strings.HasPrefix(p, root+"/")
}

// hasDotDot reports whether any '/'-separated segment of p is "..".
func hasDotDot(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// badCharIndex returns the index of the first NUL, whitespace, or control
// character in s (space, tab, newline, and every rune <= 0x20 or == 0x7f), or
// -1 when none is present. Such characters break the single-argv-token contract
// and could smuggle a second flag past a naive forwarder.
func badCharIndex(s string) int {
	for i, r := range s {
		if r <= ' ' || r == 0x7f {
			return i
		}
	}
	return -1
}
