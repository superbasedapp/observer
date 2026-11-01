package sandboxsbpl

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// profile.go builds a Seatbelt profile from the bwrap plan's inputs (sandbox
// plan v2 section 13 P5, scope item 1). The profile mirrors what the bwrap
// argv builds, rule for rule:
//
//	bwrap                                   Seatbelt (this file)
//	--ro-bind / /                           (allow file-read*)
//	--tmpfs $HOME (home_mode tmpfs)         (deny file-read* (subpath HOME)), the home
//	                                        and the ancestors of each punch-back keep
//	                                        their metadata (the dir exists, unlisted)
//	--ro-bind-try state_ro, runtimes, bins  (allow file-read* (subpath X))
//	--bind workspace, state_rw, extra rw    (allow file-read* file-write* (subpath X))
//	relay: --tmpfs ~/.observer              (deny file-read* file-write* (subpath OBS)),
//	                                        re-hidden after a workspace that holds it
//	read-only overlays                      (deny file-write* (subpath X))
//	hidden overlays                         (deny file-read* file-write* (subpath X))
//	private /tmp                            a per-run TMPDIR, the only other writable dir
//	--unshare-net + forwards                deny every outbound connection except the
//	                                        run's relay socket and the tier's loopback
//	                                        ports (the proxy, the gateway)
//
// Seatbelt applies the LAST matching rule (the form every published profile
// relies on: an allow followed by a narrower deny), so the order of the
// sections below is load-bearing, as bwrap's flag order is. Paths never
// appear in the profile text: each is a (param "NAME") whose value rides on
// sandbox-exec's -D flag, so a path needs no quoting, the text is the same
// on every machine (golden tests) and an odd character in a path can never
// change the profile's structure.

// ProfileVersion moves when the shape of a generated profile changes.
const ProfileVersion = 1

// SandboxExecPath is Apple's sandbox-exec. Only this path is ever run: a
// sandbox-exec found on PATH could be anything.
const SandboxExecPath = "/usr/bin/sandbox-exec"

// EnvSocketDir names the run's socket directory to the hook client inside a
// Seatbelt box. Unlike bwrap and a container, the box shares the host's
// /tmp, so the box record cannot sit at the fixed guest path; the hook
// client honours this variable only together with the sandbox marker.
const EnvSocketDir = "OBSERVER_SANDBOX_SOCK_DIR"

// MaxUnixSocketPath is macOS's sun_path budget (104 bytes with the NUL).
const MaxUnixSocketPath = 103

// RelaySocketName is the relay socket's file name in the run's socket dir
// (internal/sandboxrelayd's RelaySocketName, restated so this package
// imports nothing of the relay).
const RelaySocketName = "relay.sock"

// WorkspacesLeaf is the managed-workspaces dir under the observer dir (the
// bwrap planner's workspacesLeaf): the one place inside it a workspace may
// be.
const WorkspacesLeaf = "workspaces"

// HomeMode values (the bwrap planner's home_mode spellings).
const (
	HomeModeTmpfs    = "tmpfs"
	HomeModeReadonly = "readonly"
)

// Net is the network input of a profile.
type Net struct {
	// Egress is the run's tier. The host tier is refused: Seatbelt shares
	// the host's network stack, so "host" would leave the daemon's
	// loopback dashboard reachable from the box.
	Egress sandbox.Egress
	// ProxyPort is the daemon's model proxy on 127.0.0.1 (proxy_only,
	// internet).
	ProxyPort int
	// GatewayPort is the run's egress gateway on 127.0.0.1 (internet): the
	// host helper binds it before it builds the profile.
	GatewayPort int
}

// Request is the pure input of Build. Every path is absolute, clean and
// resolved through symlinks (Seatbelt matches the resolved path: /tmp is
// /private/tmp, /var is /private/var). Canonicalize resolves a request with
// the filesystem at the cmd seam; Build refuses any path that is not in its
// resolved form (ReasonUnresolvedPath), so an allow can never fail closed on
// a spelling Seatbelt never sees and a deny can never fail open on one.
type Request struct {
	Home          string
	HomeMode      string
	ObserverDir   string
	WorkspaceRoot string
	ObserverBin   string
	// ObserverBinLink is the spelling the hooks run when it is a symlink to
	// ObserverBin: its own entry (parent resolved), readable so the link
	// resolves inside the box. Empty when the binary is not reached through
	// a link.
	ObserverBinLink string
	// ObserverRealDir is the directory holding the observer binary's real
	// file (an npm or VSIX install); readable. May be empty.
	ObserverRealDir string
	// TempDir is the run's private TMPDIR: created fresh by the host
	// helper, the box's only writable place besides the workspace and the
	// tool's state.
	TempDir string
	// SocketParent holds every run's socket dir; it is hidden, so a box
	// never reads another run's launch record.
	SocketParent string
	// SocketDir is this run's socket dir (under SocketParent): readable,
	// and its relay socket is the one unix socket the box may connect to.
	SocketDir string
	// TempRoots are the shared temp roots ($TMPDIR and /private/tmp):
	// neither readable nor writable, so a box never reads another run's
	// TMPDIR or launch files or anything else left there; the run's own
	// TempDir and SocketDir are granted after them.
	TempRoots     []string
	ToolBinDirs   []string
	StateRW       []string // HOME-relative
	StateRO       []string // HOME-relative
	RuntimeLadder []string // HOME-relative
	ExtraRO       []string
	ExtraRW       []string
	// Overlays are the protect table the bwrap planner reads (read-only
	// and hidden paths). A placeholder needs no host-side file here: a
	// denied write also refuses creating the path. A protected path that
	// resolves elsewhere is listed at its own entry AND at its target
	// (Canonicalize), so the deny holds for the target too.
	Overlays []sandbox.Overlay
	// LinkNodes are symlinks on a protected path's spelling (for example a
	// workspace .git that links to another directory), at their own entry:
	// their entry refuses writes, so the link cannot be replaced by a
	// directory the protect table does not name.
	LinkNodes []string
	// Pins are repository folders and their .git inside a read-write grant
	// (the bwrap planner's sandbox.Request.Pins, SBX-WORKTREE-SOURCE audit
	// finding 4, built for this driver in lane SHR-FOLLOWUPS): each, and
	// every entry above it inside the grant, refuses writes at its own
	// literal, the anchor shape, so the box can neither rename nor unlink a
	// .git to plant a replacement the protect table would no longer cover,
	// while what is inside stays writable. Resolved like every path here.
	Pins []string
	// TTY is the inherited PTY slave (/dev/ttysNNN), the one terminal the
	// box may read, write and ioctl; empty when the launch has none.
	TTY string
	Net Net
	// MachServices are extra mach global names (the Keychain services when
	// [terminal.sandbox.seatbelt].allow_keychain is on).
	MachServices []string
	// Resolve resolves every symlink in a path ("" when it cannot); Build
	// checks each path against it and the observer-dir bind rule reads it.
	// Build refuses a request without one. Never serialized.
	Resolve func(string) string `json:"-"`
}

// Param is one sandbox-exec -D parameter.
type Param struct {
	Name  string
	Value string
}

// Profile is a built profile.
type Profile struct {
	Text   string
	Params []Param
	Egress sandbox.EgressProfile
}

// ParamMap returns the parameters as a map.
func (p Profile) ParamMap() map[string]string {
	m := make(map[string]string, len(p.Params))
	for _, x := range p.Params {
		m[x.Name] = x.Value
	}
	return m
}

// Argv is the sandbox-exec command line: the profile, every parameter, then
// the inner argv. It returns nil for an empty inner argv or one whose
// program is flag-shaped (sandbox-exec would read it as its own option).
func (p Profile) Argv(sandboxExec string, inner []string) []string {
	if len(inner) == 0 || strings.HasPrefix(inner[0], "-") {
		return nil
	}
	out := []string{sandboxExec, "-p", p.Text}
	for _, x := range p.Params {
		out = append(out, "-D", x.Name+"="+x.Value)
	}
	return append(out, inner...)
}

// baseMachServices are the mach services every profile allows: the ones a
// command-line program needs to resolve users and groups, log, read
// notifications and validate TLS certificates. The list follows the base
// policies Chromium and the Codex CLI publish; each entry is a register
// item (MAC-3), and adding one is adding a row.
var baseMachServices = []string{
	"com.apple.system.opendirectoryd.libinfo",    // getpwuid, getgrgid (home, user name)
	"com.apple.system.opendirectoryd.membership", // group membership
	"com.apple.system.logger",                    // asl logging
	"com.apple.logd",                             // os_log
	"com.apple.system.notification_center",       // notify(3)
	"com.apple.trustd.agent",                     // certificate validation
	"com.apple.bsd.dirhelper",                    // confstr temp and cache dirs
	"com.apple.lsd.mapdb",                        // LaunchServices database reads
}

// NotifyShmName is the one POSIX shared-memory segment a box may read: the
// one notify(3) publishes.
const NotifyShmName = "apple.shm.notification_center"

// KeychainMachServices are the services a Keychain-backed login needs
// (register MAC-8): added only when the user allows the Keychain.
var KeychainMachServices = []string{
	"com.apple.SecurityServer",
	"com.apple.securityd.xpc",
}

// builder accumulates the profile.
type builder struct {
	lines  []string
	params []Param
	byKey  map[string]string
	counts map[string]int
}

func (b *builder) rule(s string) { b.lines = append(b.lines, s) }

func (b *builder) comment(s string) { b.lines = append(b.lines, "; "+s) }

// param returns the (param "NAME") expression for value, naming it with
// prefix plus an index (a fixed name when single); one value under one
// prefix is one parameter.
func (b *builder) param(prefix, value string, single bool) string {
	key := prefix + "\x00" + value
	if n, ok := b.byKey[key]; ok {
		return `(param "` + n + `")`
	}
	name := prefix
	if !single {
		name = prefix + strconv.Itoa(b.counts[prefix])
		b.counts[prefix]++
	}
	b.byKey[key] = name
	b.params = append(b.params, Param{Name: name, Value: value})
	return `(param "` + name + `")`
}

// Build composes the profile. It refuses (never weakens) a request it
// cannot express: the host tier, a path that is not absolute and clean, a
// bind that would show the observer directory, a relay socket path too long
// for macOS, a port out of range.
func Build(req Request) (Profile, error) {
	if err := validate(req); err != nil {
		return Profile{}, fmt.Errorf("sandboxsbpl.Build: %w", err)
	}
	if err := checkResolved(req); err != nil {
		return Profile{}, fmt.Errorf("sandboxsbpl.Build: %w", err)
	}
	prof, err := resolveTier(req.Net)
	if err != nil {
		return Profile{}, fmt.Errorf("sandboxsbpl.Build: %w", err)
	}
	b := &builder{byKey: map[string]string{}, counts: map[string]int{}}
	g := collectGrants(req)
	// The sections in their load-bearing order (last match wins).
	b.header(req)
	if req.HomeMode == "" || req.HomeMode == HomeModeTmpfs {
		b.blindHome(req, g)
	}
	b.sharedTemp(req)
	b.readOnly(g)
	b.observerAndWrites(req, g)
	b.socketDirs(req)
	b.protect(req, g)
	b.devices(req)
	b.network(req, prof)
	return Profile{Text: strings.Join(b.lines, "\n") + "\n", Params: b.params, Egress: prof}, nil
}

// resolveTier resolves and checks the run's tier against Seatbelt.
func resolveTier(n Net) (sandbox.EgressProfile, error) {
	if n.Egress == "" {
		// Never a silent default: the caller resolves the configured tier.
		return sandbox.EgressProfile{}, fmt.Errorf("the network tier is empty (resolve it with sandbox.ResolveEgress)")
	}
	prof, err := sandbox.ResolveEgress(string(n.Egress))
	if err != nil {
		return sandbox.EgressProfile{}, err
	}
	if !prof.UnshareNet {
		return sandbox.EgressProfile{}, fmt.Errorf("the %s tier is not offered on Seatbelt: the box shares the host network, so only internet, proxy_only and none keep the daemon's loopback ports out of reach", prof.Mode)
	}
	if prof.ForwardProxy && !validPort(n.ProxyPort) {
		return sandbox.EgressProfile{}, fmt.Errorf("proxy port %d out of range", n.ProxyPort)
	}
	if prof.Gateway && (!validPort(n.GatewayPort) || n.GatewayPort == n.ProxyPort) {
		return sandbox.EgressProfile{}, fmt.Errorf("gateway port %d out of range or equal to the proxy port", n.GatewayPort)
	}
	return prof, nil
}

// grant is one punch-back: its parameter prefix and its path.
type grant struct {
	prefix string
	path   string
}

// grants are the read-only and read-write punch-backs of a request.
type grants struct {
	ro, rw []grant
}

// collectGrants lists the punch-backs in the bwrap plan's order.
func collectGrants(req Request) grants {
	home := filepath.Clean(req.Home)
	var g grants
	for _, rel := range req.StateRO {
		g.ro = append(g.ro, grant{"RO", filepath.Join(home, rel)})
	}
	for _, rel := range req.RuntimeLadder {
		g.ro = append(g.ro, grant{"RO", filepath.Join(home, rel)})
	}
	for _, d := range req.ToolBinDirs {
		g.ro = append(g.ro, grant{"RO", filepath.Clean(d)})
	}
	for _, x := range req.ExtraRO {
		g.ro = append(g.ro, grant{"RO", filepath.Clean(x)})
	}
	g.rw = append(g.rw, grant{"WS", filepath.Clean(req.WorkspaceRoot)})
	for _, rel := range req.StateRW {
		g.rw = append(g.rw, grant{"RW", filepath.Join(home, rel)})
	}
	for _, x := range req.ExtraRW {
		g.rw = append(g.rw, grant{"RW", filepath.Clean(x)})
	}
	g.rw = append(g.rw, grant{"TMP", filepath.Clean(req.TempDir)})
	return g
}

// header writes the version, the default deny and the process, IPC and
// mach rules.
func (b *builder) header(req Request) {
	b.rule("(version 1)")
	b.comment(fmt.Sprintf("Observer Seatbelt profile v%d (internal/sandboxsbpl): built from the bwrap plan's tables", ProfileVersion))
	b.rule("(deny default)")
	b.comment("processes: exec and fork inherit this profile; signals and process info stay inside it")
	b.rule("(allow process-exec)")
	b.rule("(allow process-fork)")
	b.rule("(allow signal (target same-sandbox))")
	b.rule("(allow process-info* (target same-sandbox))")
	b.rule("(allow sysctl-read)")
	// POSIX shared memory: read only, and only the segment notify(3)
	// publishes (Chromium's policy form); no segment may be created,
	// written or unlinked. A tool that makes its own segments (Python's
	// multiprocessing.shared_memory) is refused here: register MAC-3.
	b.rule(`(allow ipc-posix-shm-read-data ipc-posix-shm-read-metadata (ipc-posix-name "` + NotifyShmName + `"))`)
	b.rule("(allow ipc-posix-sem)")
	b.rule("(allow user-preference-read)")
	mach := append(append([]string(nil), baseMachServices...), req.MachServices...)
	b.rule("(allow mach-lookup" + machFilters(mach) + ")")
	b.comment("files: the whole root reads, as bwrap's --ro-bind / /")
	b.rule("(allow file-read*)")
}

// blindHome hides the home (tmpfs mode) and keeps the metadata of the home
// and of every punch-back's ancestors inside it.
func (b *builder) blindHome(req Request, g grants) {
	home := filepath.Clean(req.Home)
	b.comment("home: blinded like bwrap's --tmpfs $HOME; it and the ancestors of each punch-back keep their metadata only")
	b.rule("(deny file-read* (subpath " + b.param("HOME", home, true) + "))")
	all := append(append([]grant(nil), g.ro...), g.rw...)
	all = append(all, grant{"BIN", filepath.Clean(req.ObserverBin)})
	if req.ObserverBinLink != "" {
		all = append(all, grant{"BINLINK", filepath.Clean(req.ObserverBinLink)})
	}
	seen := map[string]bool{}
	var anc []string
	for _, x := range all {
		for _, a := range ancestorsWithin(x.path, home) {
			if !seen[a] {
				seen[a] = true
				anc = append(anc, a)
			}
		}
	}
	sort.Strings(anc)
	for _, a := range anc {
		if a == home {
			b.rule("(allow file-read-metadata (literal " + b.param("HOME", home, true) + "))")
			continue
		}
		b.rule("(allow file-read-metadata (literal " + b.param("ANC", a, false) + "))")
	}
}

// sharedTemp hides the shared temp roots (the bwrap box's private /tmp):
// another run's TMPDIR and launch files and anything else left in $TMPDIR
// or /private/tmp are neither readable nor writable. It comes before every
// grant, so the run's own TMPDIR, its socket dir and a workspace or bind
// that lies in a temp root open again after it; the ancestors of the run's
// own dirs keep their metadata only.
func (b *builder) sharedTemp(req Request) {
	if len(req.TempRoots) == 0 {
		return
	}
	b.comment("shared temp: $TMPDIR and /private/tmp hidden (other runs' temp dirs, launch files); the run's own dirs are granted below")
	var anc []string
	seen := map[string]bool{}
	for _, root := range req.TempRoots {
		root = filepath.Clean(root)
		b.rule("(deny file-read* file-write* (subpath " + b.param("STMP", root, false) + "))")
		for _, own := range []string{req.TempDir, req.SocketDir} {
			for _, a := range ancestorsWithin(filepath.Clean(own), root) {
				if !seen[a] {
					seen[a] = true
					anc = append(anc, a)
				}
			}
		}
	}
	sort.Strings(anc)
	for _, a := range anc {
		b.rule("(allow file-read-metadata (literal " + b.param("TANC", a, false) + "))")
	}
}

// readOnly writes the read-only punch-backs.
func (b *builder) readOnly(g grants) {
	b.comment("read-only punch-backs: tool state, runtimes, tool binaries, extra read-only binds")
	for _, x := range g.ro {
		b.rule("(allow file-read* (subpath " + b.param(x.prefix, x.path, false) + "))")
	}
}

// observerAndWrites hides the observer dir, writes the read-write grants,
// hides the observer dir again behind a grant that holds it, and shows the
// read-only observer files and the observer binary.
func (b *builder) observerAndWrites(req Request, g grants) {
	obs := filepath.Clean(req.ObserverDir)
	b.comment("observer dir: hidden, as the capture relay's tmpfs over it")
	b.rule("(deny file-read* file-write* (subpath " + b.param("OBS", obs, true) + "))")
	b.comment("read-write: the workspace, tool state, extra read-write binds, the run's TMPDIR")
	for _, x := range g.rw {
		single := x.prefix == "WS" || x.prefix == "TMP"
		b.rule("(allow file-read* file-write* (subpath " + b.param(x.prefix, x.path, single) + "))")
	}
	for _, x := range g.rw {
		if within(obs, x.path) {
			// A workspace that holds the observer dir (a project at the
			// home) shows it again: hidden once more, as bwrap's step 8b.
			b.rule("(deny file-read* file-write* (subpath " + b.param("OBS", obs, true) + "))")
			break
		}
	}
	var obsRO []sandbox.Overlay
	for _, o := range req.Overlays {
		if o.Kind == sandbox.OverlayReadOnly && within(o.Path, obs) {
			obsRO = append(obsRO, o)
		}
	}
	if len(obsRO) > 0 {
		b.comment("observer files the inner launcher reads, shown read-only through the hidden dir")
		for _, o := range obsRO {
			b.rule("(allow file-read* (subpath " + b.param("PROT", filepath.Clean(o.Path), false) + "))")
		}
	}
	b.comment("the observer binary the hooks run")
	b.rule("(allow file-read* (literal " + b.param("BIN", filepath.Clean(req.ObserverBin), true) + "))")
	if req.ObserverBinLink != "" {
		b.rule("(allow file-read* (literal " + b.param("BINLINK", filepath.Clean(req.ObserverBinLink), true) + "))")
	}
	if req.ObserverRealDir != "" {
		b.rule("(allow file-read* (subpath " + b.param("BINDIR", filepath.Clean(req.ObserverRealDir), true) + "))")
	}
}

// socketDirs hides every run's socket dir and shows this run's.
func (b *builder) socketDirs(req Request) {
	b.comment("socket dirs: every run's hidden, this run's launch record readable")
	b.rule("(deny file-read* file-write* (subpath " + b.param("SOCKP", filepath.Clean(req.SocketParent), true) + "))")
	b.rule("(allow file-read* (subpath " + b.param("SOCK", filepath.Clean(req.SocketDir), true) + "))")
}

// protect writes the protect table after every grant, then its anchors.
func (b *builder) protect(req Request, g grants) {
	b.comment("protect table: read-only and hidden paths, after every grant so none re-opens them")
	for _, o := range req.Overlays {
		p := filepath.Clean(o.Path)
		switch o.Kind {
		case sandbox.OverlayReadOnly:
			b.rule("(deny file-write* (subpath " + b.param("PROT", p, false) + "))")
		case sandbox.OverlayHideDir, sandbox.OverlayHideFile:
			b.rule("(deny file-read* file-write* (subpath " + b.param("HIDE", p, false) + "))")
		}
	}
	anchors := protectAnchors(req, g)
	if len(anchors) == 0 {
		return
	}
	b.comment("anchors: the entries above a protected path inside a writable grant, and links on its spelling, refuse writes, so none can be renamed or replaced")
	for _, a := range anchors {
		b.rule("(deny file-write* (literal " + b.param("ANCHOR", a, false) + "))")
	}
}

// protectAnchors lists the entries a protected path hangs from that a box
// could otherwise rename or replace (Seatbelt matches paths, so a renamed
// .git would carry its hooks out from under the deny): every ancestor of a
// protected path strictly inside a read-write grant, and every link node on
// a protected path's spelling (Request.LinkNodes). Sorted, deduplicated.
func protectAnchors(req Request, g grants) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, o := range req.Overlays {
		p := filepath.Clean(o.Path)
		for _, rw := range g.rw {
			for _, a := range ancestorsWithin(p, rw.path) {
				if a != filepath.Clean(rw.path) {
					add(a)
				}
			}
		}
	}
	for _, l := range req.LinkNodes {
		add(filepath.Clean(l))
	}
	for _, pin := range req.Pins {
		p := filepath.Clean(pin)
		for _, rw := range g.rw {
			if !within(p, rw.path) || p == filepath.Clean(rw.path) {
				continue
			}
			add(p)
			for _, a := range ancestorsWithin(p, rw.path) {
				if a != filepath.Clean(rw.path) {
					add(a)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// devices writes the device rules and the inherited PTY's.
func (b *builder) devices(req Request) {
	b.comment("devices and the inherited PTY (file-ioctl: the terminal size and modes)")
	b.rule(`(allow file-write-data file-ioctl (literal "/dev/null"))`)
	b.rule(`(allow file-write-data file-ioctl (literal "/dev/dtracehelper"))`)
	b.rule(`(allow file-read* file-write-data file-ioctl (literal "/dev/tty"))`)
	if req.TTY != "" {
		b.rule("(allow file-read* file-write-data file-ioctl (literal " + b.param("TTY", req.TTY, true) + "))")
	}
}

// network writes the relay socket and the tier's loopback ports.
func (b *builder) network(req Request, prof sandbox.EgressProfile) {
	b.comment("network: the run's relay socket, then the tier's loopback ports; nothing else")
	relay := filepath.Join(filepath.Clean(req.SocketDir), RelaySocketName)
	b.rule("(allow network-outbound (remote unix-socket (path-literal " + b.param("RELAY", relay, true) + ")))")
	if prof.ForwardProxy {
		b.rule(fmt.Sprintf(`(allow network-outbound (remote ip "localhost:%d"))`, req.Net.ProxyPort))
	}
	if prof.Gateway {
		b.rule(fmt.Sprintf(`(allow network-outbound (remote ip "localhost:%d"))`, req.Net.GatewayPort))
	}
}

// machFilters renders the global-name filters of a mach-lookup rule.
func machFilters(names []string) string {
	var sb strings.Builder
	for _, n := range names {
		sb.WriteString("\n  (global-name \"" + n + "\")")
	}
	return sb.String()
}

// ancestorsWithin lists p's ancestors from root (included) down to p's
// parent, when p lies strictly inside root.
func ancestorsWithin(p, root string) []string {
	if !within(p, root) || p == root {
		return nil
	}
	var out []string
	for d := filepath.Dir(p); ; d = filepath.Dir(d) {
		out = append(out, d)
		if d == root || d == "/" {
			break
		}
	}
	return out
}

// within reports whether p equals root or lies inside it.
func within(p, root string) bool {
	p, root = filepath.Clean(p), filepath.Clean(root)
	if root == "/" || p == root {
		return true
	}
	return strings.HasPrefix(p, root+"/")
}

func validPort(p int) bool { return p > 0 && p <= 65535 }

// validate refuses a request the profile cannot express safely; each step
// is one family of checks.
func validate(req Request) error {
	for _, step := range []func(Request) error{validatePaths, validateLayout, validateBinds, validateExtras} {
		if err := step(req); err != nil {
			return err
		}
	}
	return nil
}

// validatePaths checks every absolute and home-relative path.
func validatePaths(req Request) error {
	abs := map[string]string{
		"home": req.Home, "observer dir": req.ObserverDir, "workspace": req.WorkspaceRoot,
		"observer binary": req.ObserverBin, "temp dir": req.TempDir,
		"socket parent": req.SocketParent, "socket dir": req.SocketDir,
	}
	if req.ObserverRealDir != "" {
		abs["observer binary dir"] = req.ObserverRealDir
	}
	for _, k := range sortedKeys(abs) {
		if err := checkAbs(k, abs[k]); err != nil {
			return err
		}
	}
	for _, rel := range append(append(append([]string(nil), req.StateRW...), req.StateRO...), req.RuntimeLadder...) {
		if err := checkRel(rel); err != nil {
			return err
		}
	}
	for _, list := range [][]string{req.ToolBinDirs, req.ExtraRO, req.ExtraRW} {
		for _, p := range list {
			if err := checkAbs("bind", p); err != nil {
				return err
			}
		}
	}
	for _, p := range req.TempRoots {
		if err := checkAbs("temp root", p); err != nil {
			return err
		}
		if p == "/" {
			return fmt.Errorf("a whole-root temp root is forbidden")
		}
	}
	for _, p := range req.LinkNodes {
		if err := checkAbs("link node", p); err != nil {
			return err
		}
	}
	for _, p := range req.Pins {
		if err := checkAbs("pin", p); err != nil {
			return err
		}
	}
	if req.ObserverBinLink != "" {
		if err := checkAbs("observer binary link", req.ObserverBinLink); err != nil {
			return err
		}
	}
	for _, o := range req.Overlays {
		if err := checkAbs("overlay", o.Path); err != nil {
			return err
		}
	}
	return nil
}

// validateLayout checks how the run's own directories sit together.
func validateLayout(req Request) error {
	if req.HomeMode != "" && req.HomeMode != HomeModeTmpfs && req.HomeMode != HomeModeReadonly {
		return fmt.Errorf("home mode %q not in {tmpfs, readonly}", req.HomeMode)
	}
	for _, kv := range []struct{ k, v string }{{"home", req.Home}, {"workspace", req.WorkspaceRoot}, {"temp dir", req.TempDir}} {
		if kv.v == "/" {
			return fmt.Errorf("a whole-root %s is forbidden", kv.k)
		}
	}
	if !within(req.SocketDir, req.SocketParent) || req.SocketDir == req.SocketParent {
		return fmt.Errorf("socket dir %q must lie inside the socket parent %q", req.SocketDir, req.SocketParent)
	}
	if relay := filepath.Join(req.SocketDir, RelaySocketName); len(relay) > MaxUnixSocketPath {
		return fmt.Errorf("relay socket path %q is too long for macOS (%d > %d bytes)", relay, len(relay), MaxUnixSocketPath)
	}
	for _, sep := range []struct{ k, v string }{{"temp dir", req.TempDir}, {"workspace", req.WorkspaceRoot}} {
		if within(sep.v, req.SocketParent) || within(req.SocketParent, sep.v) {
			return fmt.Errorf("%s %q overlaps the socket parent %q", sep.k, sep.v, req.SocketParent)
		}
	}
	if within(req.TempDir, req.ObserverDir) {
		return fmt.Errorf("temp dir %q lies inside the observer dir", req.TempDir)
	}
	if within(req.WorkspaceRoot, req.ObserverDir) && !within(req.WorkspaceRoot, filepath.Join(req.ObserverDir, WorkspacesLeaf)) {
		return fmt.Errorf("workspace %q lies inside the observer dir outside its managed workspaces tree", req.WorkspaceRoot)
	}
	return nil
}

// validateBinds applies the relay's observer-dir rule, the same function
// bwrap and the oci-runc driver call (one owner), and refuses a whole-root
// write.
func validateBinds(req Request) error {
	for _, p := range req.ExtraRW {
		if p == "/" {
			return fmt.Errorf("a whole-root read-write bind is forbidden")
		}
	}
	check := func(kind, p string) error {
		return sandbox.CheckObserverDirBind(kind, p, req.ObserverDir, req.Resolve)
	}
	for _, rel := range req.StateRW {
		if err := check("state rw bind", filepath.Join(req.Home, rel)); err != nil {
			return err
		}
	}
	for _, x := range req.ExtraRO {
		if err := check("extra ro bind", x); err != nil {
			return err
		}
	}
	for _, x := range req.ExtraRW {
		if err := check("extra rw bind", x); err != nil {
			return err
		}
	}
	return nil
}

// validateExtras checks the overlay kinds, the terminal and the mach
// services.
func validateExtras(req Request) error {
	for _, o := range req.Overlays {
		switch o.Kind {
		case sandbox.OverlayReadOnly, sandbox.OverlayHideDir, sandbox.OverlayHideFile:
		default:
			return fmt.Errorf("overlay %q has unknown kind %q", o.Path, o.Kind)
		}
	}
	if req.TTY != "" && !ValidTTYPath(req.TTY) {
		return fmt.Errorf("tty %q is not a /dev/ttysNNN terminal", req.TTY)
	}
	for _, n := range req.MachServices {
		if !validMachName(n) {
			return fmt.Errorf("mach service %q is not a plain reverse-DNS name", n)
		}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkAbs guards a path parameter: absolute, clean, no control character
// and no ".." segment. Spaces are fine (macOS paths carry them, and a
// parameter is one argv element).
func checkAbs(kind, p string) error {
	switch {
	case p == "":
		return fmt.Errorf("%s: empty path", kind)
	case !filepath.IsAbs(p):
		return fmt.Errorf("%s %q must be absolute", kind, p)
	case filepath.Clean(p) != p:
		return fmt.Errorf("%s %q must be clean", kind, p)
	case controlIndex(p) >= 0:
		return fmt.Errorf("%s %q contains a NUL or control character", kind, p)
	}
	return nil
}

// checkRel guards a HOME-relative path.
func checkRel(rel string) error {
	if rel == "" || rel == "." || filepath.IsAbs(rel) || controlIndex(rel) >= 0 {
		return fmt.Errorf("home-relative path %q must be relative, non-empty and plain", rel)
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == ".." {
			return fmt.Errorf("home-relative path %q must not contain '..'", rel)
		}
	}
	return nil
}

// controlIndex returns the index of the first NUL or control character.
func controlIndex(s string) int {
	for i, r := range s {
		if r < 0x20 || r == 0x7f {
			return i
		}
	}
	return -1
}

// ValidTTYPath reports whether p is a macOS pseudo-terminal slave path
// (/dev/ttys followed by three or more digits).
func ValidTTYPath(p string) bool {
	const pre = "/dev/ttys"
	if !strings.HasPrefix(p, pre) || len(p) < len(pre)+3 {
		return false
	}
	for _, c := range p[len(pre):] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// TTYName is the slave path of the macOS pseudo-terminal with minor number
// minor (the kernel names them ttys000, ttys001, ...).
func TTYName(minor uint32) string { return fmt.Sprintf("/dev/ttys%03d", minor) }

// validMachName accepts a reverse-DNS service name.
func validMachName(n string) bool {
	if n == "" || len(n) > 128 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || c == '@') {
			return false
		}
	}
	return true
}

// ReasonUnresolvedPath names Build's refusal of a path that is not in its
// resolved form, and Canonicalize's of one that cannot be resolved.
const ReasonUnresolvedPath = "unresolved_path"

// UnresolvedPathError is the named refusal of a path Seatbelt would never
// match as written: an allow on it would fail closed, a deny on it would
// fail open.
type UnresolvedPathError struct {
	// Kind names the request field ("workspace", "protected path", ...).
	Kind string
	// Path is the spelling in the request.
	Path string
	// Resolved is what it resolves to ("" when it cannot be resolved).
	Resolved string
	// Detail is an optional clause after the paths.
	Detail string
}

// Error renders the refusal with its reason first.
func (e *UnresolvedPathError) Error() string {
	msg := fmt.Sprintf("%s: %s %q", ReasonUnresolvedPath, e.Kind, e.Path)
	switch {
	case e.Path == "":
		msg = ReasonUnresolvedPath + ": " + e.Kind
	case e.Resolved == "":
		msg += " could not be resolved"
	default:
		msg += fmt.Sprintf(" resolves to %q", e.Resolved)
	}
	if e.Detail != "" {
		msg += "; " + e.Detail
	}
	return msg + " (Seatbelt matches resolved paths only, so the profile is built from them)"
}

// checkResolved refuses a request with a path that is not resolved: every
// granted or hidden path must be its own resolved form; a protected path
// and a link node need a resolved parent (the entry itself may be a link),
// and a protected path that resolves elsewhere must have its target
// protected with the same kind.
func checkResolved(req Request) error {
	res := req.Resolve
	if res == nil {
		return &UnresolvedPathError{Kind: "no path resolver was given, so no path could be checked"}
	}
	full := func(kind, p string) error {
		if r := res(p); r != p {
			return &UnresolvedPathError{Kind: kind, Path: p, Resolved: r}
		}
		return nil
	}
	node := func(kind, p string) error {
		return full(kind+" parent", filepath.Dir(p))
	}
	abs := map[string]string{
		"home": req.Home, "observer dir": req.ObserverDir, "workspace": req.WorkspaceRoot,
		"observer binary": req.ObserverBin, "temp dir": req.TempDir,
		"socket parent": req.SocketParent, "socket dir": req.SocketDir,
	}
	if req.ObserverRealDir != "" {
		abs["observer binary dir"] = req.ObserverRealDir
	}
	for _, k := range sortedKeys(abs) {
		if err := full(k, abs[k]); err != nil {
			return err
		}
	}
	home := filepath.Clean(req.Home)
	for _, l := range []struct {
		kind string
		rels []string
	}{{"tool state", req.StateRW}, {"tool state", req.StateRO}, {"runtime", req.RuntimeLadder}} {
		for _, rel := range l.rels {
			if err := full(l.kind, filepath.Join(home, rel)); err != nil {
				return err
			}
		}
	}
	for _, l := range []struct {
		kind  string
		paths []string
	}{{"tool binary dir", req.ToolBinDirs}, {"extra ro bind", req.ExtraRO}, {"extra rw bind", req.ExtraRW}, {"temp root", req.TempRoots}, {"pin", req.Pins}} {
		for _, p := range l.paths {
			if err := full(l.kind, p); err != nil {
				return err
			}
		}
	}
	if req.ObserverBinLink != "" {
		if err := node("observer binary link", req.ObserverBinLink); err != nil {
			return err
		}
		if r := res(req.ObserverBinLink); r != req.ObserverBin {
			return &UnresolvedPathError{Kind: "observer binary link", Path: req.ObserverBinLink, Resolved: r, Detail: "not the observer binary"}
		}
	}
	for _, l := range req.LinkNodes {
		if err := node("link node", l); err != nil {
			return err
		}
	}
	protected := map[sandbox.Overlay]bool{}
	for _, o := range req.Overlays {
		protected[sandbox.Overlay{Path: filepath.Clean(o.Path), Kind: o.Kind}] = true
	}
	for _, o := range req.Overlays {
		if err := node("protected path", o.Path); err != nil {
			return err
		}
		r := res(o.Path)
		if r == o.Path {
			continue
		}
		if r == "" || !protected[sandbox.Overlay{Path: r, Kind: o.Kind}] {
			return &UnresolvedPathError{Kind: "protected path", Path: o.Path, Resolved: r, Detail: "its target is not protected too"}
		}
	}
	return nil
}

// Canonicalize resolves every path of req with resolve (the cmd seam passes
// the filesystem's resolver; "" means it cannot resolve the path) into the
// form Build accepts:
//   - each granted path is replaced by its resolved form; a home-relative
//     tool-state path that resolves outside the home becomes an absolute
//     extra bind of the same access;
//   - the observer binary is its resolved file, and the spelling the hooks
//     run becomes ObserverBinLink when it is a link;
//   - each protected path is listed at its own entry (parent resolved) and,
//     when it is a link, at its target too, with the same kind;
//   - each symlink on a protected path's spelling is recorded in LinkNodes.
//
// It returns the named refusal when a path cannot be resolved, and sets
// Resolve so Build checks the result against the same resolver.
func Canonicalize(req Request, resolve func(string) string) (Request, error) {
	if resolve == nil {
		return Request{}, &UnresolvedPathError{Kind: "no path resolver was given, so no path could be resolved"}
	}
	one := func(kind, p string) (string, error) {
		if p == "" {
			return "", nil
		}
		r := resolve(p)
		if r == "" {
			return "", &UnresolvedPathError{Kind: kind, Path: p}
		}
		return r, nil
	}
	nodeOf := func(kind, p string) (string, error) {
		d, err := one(kind+" parent", filepath.Dir(p))
		if err != nil {
			return "", err
		}
		return filepath.Join(d, filepath.Base(p)), nil
	}
	out := req
	var err error
	for _, f := range []struct {
		kind string
		ptr  *string
	}{
		{"home", &out.Home},
		{"observer dir", &out.ObserverDir},
		{"workspace", &out.WorkspaceRoot},
		{"observer binary dir", &out.ObserverRealDir},
		{"temp dir", &out.TempDir},
		{"socket parent", &out.SocketParent},
		{"socket dir", &out.SocketDir},
	} {
		if *f.ptr, err = one(f.kind, *f.ptr); err != nil {
			return Request{}, err
		}
	}
	out.ObserverBinLink = ""
	if req.ObserverBin != "" {
		bin, err := one("observer binary", req.ObserverBin)
		if err != nil {
			return Request{}, err
		}
		link, err := nodeOf("observer binary", req.ObserverBin)
		if err != nil {
			return Request{}, err
		}
		out.ObserverBin = bin
		if link != bin {
			out.ObserverBinLink = link
		}
	}
	list := func(kind string, in []string) ([]string, error) {
		var res []string
		seen := map[string]bool{}
		for _, p := range in {
			r, err := one(kind, p)
			if err != nil {
				return nil, err
			}
			if !seen[r] {
				seen[r] = true
				res = append(res, r)
			}
		}
		return res, nil
	}
	for _, l := range []struct {
		kind string
		in   []string
		out  *[]string
	}{
		{"tool binary dir", req.ToolBinDirs, &out.ToolBinDirs},
		{"extra ro bind", req.ExtraRO, &out.ExtraRO},
		{"extra rw bind", req.ExtraRW, &out.ExtraRW},
		{"temp root", req.TempRoots, &out.TempRoots},
		{"pin", req.Pins, &out.Pins},
	} {
		if *l.out, err = list(l.kind, l.in); err != nil {
			return Request{}, err
		}
	}
	rels := func(kind string, in []string, moved *[]string) ([]string, error) {
		var res []string
		for _, rel := range in {
			r, err := one(kind, filepath.Join(req.Home, rel))
			if err != nil {
				return nil, err
			}
			if within(r, out.Home) && r != out.Home {
				res = append(res, strings.TrimPrefix(r, filepath.Clean(out.Home)+"/"))
				continue
			}
			if !slices.Contains(*moved, r) {
				*moved = append(*moved, r)
			}
		}
		return res, nil
	}
	if out.StateRW, err = rels("tool state", req.StateRW, &out.ExtraRW); err != nil {
		return Request{}, err
	}
	if out.StateRO, err = rels("tool state", req.StateRO, &out.ExtraRO); err != nil {
		return Request{}, err
	}
	if out.RuntimeLadder, err = rels("runtime", req.RuntimeLadder, &out.ExtraRO); err != nil {
		return Request{}, err
	}
	if out.Overlays, out.LinkNodes, err = canonicalOverlays(req.Overlays, one, nodeOf); err != nil {
		return Request{}, err
	}
	sort.Strings(out.LinkNodes)
	out.Resolve = resolve
	return out, nil
}

// canonicalOverlays is Canonicalize's protected-path step: each overlay at
// its node path and, when the path resolves elsewhere, at its target too,
// plus the link nodes among its ancestors.
func canonicalOverlays(in []sandbox.Overlay, one, nodeOf func(kind, p string) (string, error)) (overlays []sandbox.Overlay, links []string, err error) {
	seenO := map[sandbox.Overlay]bool{}
	addO := func(o sandbox.Overlay, p string) {
		o.Path = p
		k := sandbox.Overlay{Path: p, Kind: o.Kind}
		if !seenO[k] {
			seenO[k] = true
			overlays = append(overlays, o)
		}
	}
	seenL := map[string]bool{}
	for _, o := range in {
		n, err := nodeOf("protected path", o.Path)
		if err != nil {
			return nil, nil, err
		}
		t, err := one("protected path", o.Path)
		if err != nil {
			return nil, nil, err
		}
		addO(o, n)
		if t != n {
			addO(o, t)
		}
		for a := filepath.Dir(filepath.Clean(o.Path)); a != "/" && a != "."; a = filepath.Dir(a) {
			an, err := nodeOf("protected path", a)
			if err != nil {
				return nil, nil, err
			}
			if ar, err := one("protected path", a); err == nil && ar != an && !seenL[an] {
				seenL[an] = true
				links = append(links, an)
			}
		}
	}
	return overlays, links, nil
}
