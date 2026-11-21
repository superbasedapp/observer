package sandboxopenshell

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// The [terminal.sandbox].home_mode values the compiler reads ("" is tmpfs,
// the config default).
const (
	HomeTmpfs    = "tmpfs"
	HomeReadonly = "readonly"
	// HomeLayer (lane G4, the org-hosted row only): no home mount at all.
	// The home is the box image's own directory on the box's writable
	// layer, which survives a stop (a held box) and is deleted with the
	// box. The tmpfs home exists for a laptop box's host binds, which an
	// org box never has. Never a [terminal.sandbox].home_mode value.
	HomeLayer = "layer"
)

// HomeTmpfsMode is the tmpfs mode of the box's home, emitted on every tmpfs
// home: 01777 (the integer 1023, Docker's TmpfsOptions.Mode). Lane O0's
// first VM receipt (abdac8) failed R4 because, with binds nested under it,
// Docker leaves a tmpfs with no mode at 0755 owned by root, so the workload
// (uid 1000) cannot create files in its own home; the GO receipt (f04566)
// passed with this mode. A bare tmpfs with nothing under it already comes
// up 1777 root (OB-033 probe), so stating the mode every time gives the
// same measured result, removes the nested-or-not branch and does not rely
// on Docker's unpinned default (audit finding O1A-A2). Docker refuses the
// tmpfs options uid=, gid= and mode= as strings, so the integer mode is the
// only way, and the home is then root-owned 1777 with the sticky bit, not
// owned by the user (F-017 A4, disclosed as
// sandboxbackend.DiscloseSharedHomeTmpfs).
const HomeTmpfsMode = 0o1777

// Settings are the effective [terminal.sandbox] and
// [terminal.sandbox.openshell] values the compiler reads (rule W2). The
// driver copies them from the loaded config; the planner never reads it.
type Settings struct {
	// HomeMode is [terminal.sandbox].home_mode ("" or "tmpfs", "readonly").
	HomeMode string
	// Egress is the run's egress tier.
	Egress vocab.Tier
	// Driver is the gateway's compute driver, the key of
	// --driver-config-json ("" is docker).
	Driver string
}

// Bind is one entry of the run's bind plan as the cmd layer resolved it:
// every path absolute and symlink-free on the host, every protected path
// already turned into a read-only bind (the same protection table every
// driver uses). The compiler adds no bind the plan did not name, and it
// enforces the D3 mount scope (decision OB-040) itself rather than trusting
// the plan (checkBind): Source must be the run's workspace, its per-run
// socket dir or one of its named tool-state roots, or sit under one, or
// equal one of its exact bin paths (ErrScope); it must not reach a
// credential path of the home (ErrCredential, audit finding O1A-R1); under
// the observer dir only a read-only bind of an exact bin path is allowed
// (ErrObserverDir, O1A-R2); and Target must equal Source (same path, the
// shape lane O0 grounded in R1; ErrSamePath). The home itself is NOT a
// scope root: a subtree of the home enters the box only when a tool-state
// row names it. No entry of today's plan needs a different path
// (Observer's own binary is bound at its host path, as the bubblewrap row
// binds it), so there is no exception table; one would be a named row here
// with its reason.
type Bind struct {
	Source string
	Target string
	// ReadOnly: the box may not write it.
	ReadOnly bool
	// File: the source is a single file, not a directory.
	File bool
}

// Scope is the D3 mount scope of one run (decision OB-040): the host roots
// a bind source may be or sit under. Each is a clean absolute path, resolved
// like the bind sources, that is not a system root, not under a kernel or
// runtime tree (/proc, /sys, /dev, /run, /var/run, /boot), not the home or
// an ancestor of it, and does not reach a credential path of the home (rule
// K10, audit findings O1A-R1 and O1A-R3).
type Scope struct {
	// Workspace is the run's workspace, required. A bind may sit under it.
	Workspace string
	// SocketDir is the run's per-run socket dir (the capture relay and the
	// model proxy forward), required. A bind may sit under it.
	SocketDir string
	// ToolState are the tool's own state roots under the home, from the
	// registry's tool-state rows (integration.SandboxSpec StateRW and
	// StateRO, joined to the home): the only parts of the home a bind may
	// be or sit under (audit finding O1A-R1). A file row names the file.
	ToolState []string
	// BinPaths are the binaries and tool bin dirs the plan binds outside
	// the workspace and the tool state (Observer's own binary, the tool's
	// install dir), each named exactly: a bind source must EQUAL one,
	// nothing beneath an entry is admitted unless it is named too (audit
	// finding O1A-R3). They are also the only binds allowed under the
	// observer dir, read-only, and only when the bind is a regular file
	// (O1A-R2, O1B-A9).
	BinPaths []string
}

// Input is everything one compile reads.
type Input struct {
	Settings Settings
	// Home is the user's home path, the box's HOME (same path).
	Home string
	// UID and GID are the host user's; the workload runs as them, so
	// same-path writes carry the host owner (O0 R1). Root is refused.
	UID, GID int
	// ObserverDir is the host's ~/.observer: it never enters the box whole,
	// nothing under it is bound writable, and the only thing under it that
	// may be bound at all is an exact bin path, read-only (the box never
	// sees observer.db or the attach socket's dir; hooks go through the
	// relay). It must be spelled the way
	// the bind sources are, resolved the same way (absolute and
	// symlink-free): the observer-dir checks compare paths, so a bind named
	// through a link cannot show a dir named another way (audit finding
	// O1A-A4).
	ObserverDir string
	// ObserverDirResolved is the other spelling of the observer dir, when
	// the two differ (for example ~/.observer is a symlink to
	// /data/observer and ObserverDir keeps the link's path): every
	// observer-dir check runs against both. "" when there is one spelling.
	ObserverDirResolved string
	// Scope is the run's D3 mount scope: no bind source outside it. The
	// home is not in it; only the named tool-state roots of the home are.
	Scope Scope
	// Binds is the bind plan.
	Binds []Bind
	// Env is the run's environment (KEY=VALUE), without HOME, which the
	// compiler sets.
	Env []string
	// Net is what the network rule compiler reads (netrules.go, lane O3);
	// the proxy_only and none tiers read none of it.
	Net NetInput
	// BoxReadWrite are box-local directories the workload may write that
	// are no bind and no mount (lane G4, the org-hosted row: its fixed
	// workspace and run dir on the box's writable layer). Each must be
	// absolute and clean; they reach the policy's read_write list only,
	// never the driver config.
	BoxReadWrite []string
}

// Mount is one driver mount (an entry of --driver-config-json's mounts).
type Mount struct {
	// Type is "tmpfs" or "bind".
	Type   string
	Source string
	Target string
	// ReadOnly is stated on every bind (OpenShell's default is read-only,
	// so a writable bind must say read_only false).
	ReadOnly bool
	// Mode is a tmpfs mode (0: none given).
	Mode int
}

// mountJSON is the wire shape of a Mount (lane O0's render_driver_config):
// a tmpfs is {"type","target","mode"?}, a bind {"type","source","target",
// "read_only"}.
type mountJSON struct {
	Type     string `json:"type"`
	Source   string `json:"source,omitempty"`
	Target   string `json:"target"`
	ReadOnly *bool  `json:"read_only,omitempty"`
	Mode     int    `json:"mode,omitempty"`
}

// MarshalJSON renders the mount in OpenShell's driver-config shape.
func (m Mount) MarshalJSON() ([]byte, error) {
	w := mountJSON{Type: m.Type, Target: m.Target}
	switch m.Type {
	case mountBind:
		ro := m.ReadOnly
		w.Source, w.ReadOnly = m.Source, &ro
	case mountTmpfs:
		w.Mode = m.Mode
	}
	return json.Marshal(w)
}

// The mount types the compiler emits.
const (
	mountBind  = "bind"
	mountTmpfs = "tmpfs"
)

// MountTypeBind is the Type of a bind Mount (the driver checks that a
// placeholder it creates on the host has one, read-only).
const MountTypeBind = mountBind

// CopySync is a single file a tool rewrites in place by temp-and-rename,
// which a bind cannot carry: a rename onto a bind-mounted file fails (lane
// O0 R4 file_bind_rename, U-32 fallback (1)). The driver (lane O1B) copies
// Source into the box at Target before the agent starts and syncs it back
// to Source at Release. Directory binds rename fine and stay binds.
type CopySync struct {
	Source string
	Target string
}

// Plan is the compiled run.
type Plan struct {
	// PolicyYAML is the OpenShell policy document (version: 1) for
	// --policy.
	PolicyYAML []byte
	// DriverConfigJSON is the --driver-config-json value.
	DriverConfigJSON string
	// Mounts are the driver mounts in DriverConfigJSON, in order.
	Mounts []Mount
	// CopySync are the files copied in and synced back (never bound).
	CopySync []CopySync
	// Env is the run's environment, HOME first.
	Env []string
	// SharedHome: the box's home is a root-owned 1777 tmpfs with the sticky
	// bit (HomeTmpfsMode), which the run's posture discloses. True for every
	// tmpfs home, with or without mounts nested under it.
	SharedHome bool
	// Network are the compiled network rules in PolicyYAML (none on the
	// proxy_only and none tiers, netrules.go).
	Network []NetRule
}

// The compile refusals. Each names what the operator can change.
var (
	ErrRoot         = errors.New("sandboxopenshell: the workload never runs as root (OpenShell refuses run_as_user 0)")
	ErrTier         = errors.New("sandboxopenshell: egress tier not offered by the openshell row")
	ErrHomeMode     = errors.New("sandboxopenshell: unknown home_mode")
	ErrPath         = errors.New("sandboxopenshell: a path is not absolute and clean, or cannot be a mount path")
	ErrReserved     = errors.New("sandboxopenshell: a mount target overlaps an OpenShell control path")
	ErrDuplicate    = errors.New("sandboxopenshell: two mounts share a target")
	ErrObserverDir  = errors.New("sandboxopenshell: the observer dir would enter the box whole or writable")
	ErrScope        = errors.New("sandboxopenshell: outside the run's mount scope (bind sources only under the workspace, the per-run socket dir and the named tool-state roots, or equal to a named bin path)")
	ErrCredential   = errors.New("sandboxopenshell: a bind or scope root reaches a credential path or socket dir of the home")
	ErrSamePath     = errors.New("sandboxopenshell: a bind's target differs from its source (binds are same-path)")
	ErrCopyTarget   = errors.New("sandboxopenshell: the innermost mount over a copied file's target is not writable")
	ErrEnv          = errors.New("sandboxopenshell: an environment entry is not KEY=VALUE")
	ErrTooManyPaths = errors.New("sandboxopenshell: the policy would list more than 256 paths")
	ErrDriver       = errors.New("sandboxopenshell: unknown compute driver")
)

// reservedTargets are OpenShell's control roots: a mount target may not be,
// contain or sit under one (OS:crates/openshell-core/src/container_paths.rs,
// o0-receipts.md "Bind mounts, tmpfs and the gateway-wide opt-in"; /sandbox
// is the OpenShell workspace root, which the compiler never uses).
var reservedTargets = []string{
	"/.openshell", "/etc/openshell", "/etc/openshell-tls", "/opt/openshell",
	"/run/netns", "/run/openshell", "/run/openshell-sidecar", "/sandbox", "/var/run/netns",
}

// systemReadOnly and systemReadWrite are the system paths the workload may
// read and write. A policy with no network rule gets no baseline paths from
// OpenShell, so it lists them itself (the system paths of lane O0's live
// policy, o0helper.py SYSTEM_RO and SYSTEM_RW).
var (
	systemReadOnly  = []string{"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev", "/run", "/var"}
	systemReadWrite = []string{"/tmp", "/dev/null", "/dev/pts"}
)

// maxPolicyPaths is OpenShell's limit on filesystem_policy paths.
const maxPolicyPaths = 256

// drivers is the closed set of compute drivers whose driver-config key the
// compiler writes (probe row P6 takes the ones a receipt measured on the
// tested version, drivers.go).
var drivers = []string{"docker", "podman"}

// compileRule is one input check, walked top-down; the first error wins.
type compileRule struct {
	id    string
	check func(in Input) error
}

// compileRules are the checks before any mount is planned.
var compileRules = []compileRule{
	{"K1 root", func(in Input) error {
		if in.UID < 1 || in.GID < 1 {
			return fmt.Errorf("%w (uid %d, gid %d)", ErrRoot, in.UID, in.GID)
		}
		return nil
	}},
	{"K2 tier", func(in Input) error {
		row, _ := sandboxbackend.Get(sandboxbackend.BackendOpenShell)
		if !row.OffersTier(in.Settings.Egress) {
			return fmt.Errorf("%w: %q (the row offers %v)", ErrTier, in.Settings.Egress, row.Net.Egress)
		}
		return nil
	}},
	// K3 to K5 re-checked a subset of the selection floors and were
	// removed (audit finding O1A-A8): selection is the floor gate, not
	// Compile. The ids stay unused so docs that cite K6 to K10 keep their
	// meaning.
	{"K6 home mode", func(in Input) error {
		switch in.Settings.HomeMode {
		case "", HomeTmpfs, HomeReadonly, HomeLayer:
			return nil
		}
		return fmt.Errorf("%w %q", ErrHomeMode, in.Settings.HomeMode)
	}},
	{"K7 driver", func(in Input) error {
		if d := in.Settings.Driver; d != "" && !slices.Contains(drivers, d) {
			return fmt.Errorf("%w %q", ErrDriver, d)
		}
		return nil
	}},
	{"K8 home and observer dir", func(in Input) error {
		if !cleanAbs(in.Home) || in.Home == "/" {
			return fmt.Errorf("%w: home %q", ErrPath, in.Home)
		}
		if !mountPath(in.Home) {
			return fmt.Errorf("%w: home %q contains ':' or ','", ErrPath, in.Home)
		}
		if !cleanAbs(in.ObserverDir) {
			return fmt.Errorf("%w: observer dir %q", ErrPath, in.ObserverDir)
		}
		if r := in.ObserverDirResolved; r != "" && !cleanAbs(r) {
			return fmt.Errorf("%w: resolved observer dir %q", ErrPath, r)
		}
		return nil
	}},
	// K9 applies the observer-dir rule to the home mount itself, not only
	// to the bind plan (audit finding O1A-A1): home_mode "readonly" makes
	// the home a read-only bind of the host home, and when the observer dir
	// sits inside it (the usual ~/.observer) the box could read observer.db,
	// every Observer token and keystore file, and ~/.ssh with it. Refused,
	// fail closed, until a mask over the observer dir is measured live (a
	// tmpfs at ObserverDir under the read-only home bind, named for lane
	// O1B's live run).
	{"K9 readonly home holds the observer dir", func(in Input) error {
		if in.Settings.HomeMode != HomeReadonly {
			return nil
		}
		for _, d := range observerDirs(in) {
			if holdsWhole(in.Home, d) {
				return fmt.Errorf("%w: home_mode %q binds the home %s read-only, and it holds the observer dir %s (observer.db and Observer's tokens); use home_mode %q with the openshell backend", ErrObserverDir, HomeReadonly, in.Home, d, HomeTmpfs)
			}
		}
		return nil
	}},
	{"K10 scope roots", func(in Input) error {
		if in.Scope.Workspace == "" || in.Scope.SocketDir == "" {
			return fmt.Errorf("%w: the run's workspace and per-run socket dir are required (workspace %q, socket dir %q)", ErrScope, in.Scope.Workspace, in.Scope.SocketDir)
		}
		for _, r := range scopeRoots(in) {
			if err := checkScopeRoot(in, r); err != nil {
				return err
			}
		}
		return nil
	}},
}

// scopeRoots are every scope root of the run: the workspace, the socket
// dir, the tool-state roots and the bin paths.
func scopeRoots(in Input) []string {
	out := append([]string{in.Scope.Workspace, in.Scope.SocketDir}, in.Scope.ToolState...)
	return append(out, in.Scope.BinPaths...)
}

// systemRoots are host directories that are never a scope root (audit
// finding O1A-R3): binding one same-path would replace the box's own system
// tree with the host's or, under /home, expose every user's home. A file or
// dir BELOW one (a tool's install dir under /usr/local, Observer's binary
// under /usr/bin) may still be a bin path.
var systemRoots = []string{
	"/", "/bin", "/etc", "/home", "/lib", "/lib32", "/lib64", "/libx32", "/media", "/mnt",
	"/opt", "/root", "/sbin", "/snap", "/srv", "/tmp", "/usr", "/usr/bin", "/usr/lib",
	"/usr/lib64", "/usr/libexec", "/usr/local", "/usr/local/bin", "/usr/local/lib",
	"/usr/sbin", "/usr/share", "/var", "/var/lib", "/var/tmp",
}

// systemTrees are kernel and runtime trees no scope root may be or sit in:
// the container engine sockets live in /run and /var/run (/run/docker.sock,
// /run/user/<uid>/podman/podman.sock), and /proc, /sys, /dev and /boot are
// the host kernel's.
var systemTrees = []string{"/boot", "/dev", "/proc", "/run", "/sys", "/var/run"}

// credentialRule is one row of the home's credential table (audit finding
// O1A-R1): a home-relative path no bind source and no scope root may be,
// sit under or hold.
type credentialRule struct {
	rel, why string
}

// credentialPaths is the home's credential table. A tool-state row never
// names one of these; a bind that reaches one is refused even when another
// scope root would admit it.
var credentialPaths = []credentialRule{
	{".ssh", "SSH keys and agent sockets"},
	{".gnupg", "GnuPG keys and the agent socket"},
	{".aws", "AWS credentials"},
	{".azure", "Azure CLI tokens"},
	{".config/gcloud", "Google Cloud credentials"},
	{".kube", "Kubernetes credentials"},
	{".docker", "Docker credentials and Docker Desktop's engine socket (~/.docker/desktop/docker.sock)"},
	{".config/containers", "Podman registry credentials"},
	{".local/share/containers", "Podman's rootless storage"},
	{".config/gh", "GitHub CLI tokens"},
	{".config/openshell", "the OpenShell gateway registry and its mTLS client certificates"},
	{".local/state/openshell", "the OpenShell gateway's key-encryption key"},
	{".netrc", "plaintext login credentials"},
	{".git-credentials", "plaintext git credentials"},
	{".pki", "the NSS certificate store"},
	{".password-store", "pass(1) secrets"},
	{".local/share/keyrings", "the desktop keyring"},
}

// credentialHit returns the credential row p reaches (equal, under or
// holding it), or false.
func credentialHit(home, p string) (credentialRule, bool) {
	for _, c := range credentialPaths {
		cp := home + "/" + c.rel
		if p == cp || under(p, cp) || under(cp, p) {
			return c, true
		}
	}
	return credentialRule{}, false
}

// CheckScopeRoot applies rule K10 and the observer-dir bin rule to one
// candidate bin path of a run (in.Home, in.ObserverDir and
// in.ObserverDirResolved are read), so the driver can leave out a tool bin
// dir or a runtime dir that Compile would refuse (a tool installed under
// /usr/bin, a runtime dir that holds a credential path, a dir under or
// holding the observer dir) instead of failing the launch. file says the
// candidate is a regular file: under the observer dir only a file may be a
// bin path (Observer's own binary), never a dir such as ~/.observer/run,
// the attach socket's dir (audit finding O1B-A9). It returns ErrPath,
// ErrScope, ErrCredential or ErrObserverDir.
func CheckScopeRoot(in Input, root string, file bool) error {
	if err := checkScopeRoot(in, root); err != nil {
		return err
	}
	if file {
		return nil
	}
	for _, d := range observerDirs(in) {
		if d != "" && under(root, d) {
			return fmt.Errorf("%w: %s is a dir under it, and only a regular file (Observer's own binary) may be bound from there", ErrObserverDir, root)
		}
	}
	return nil
}

// checkScopeRoot applies rule K10 to one root.
func checkScopeRoot(in Input, r string) error {
	if !cleanAbs(r) {
		return fmt.Errorf("%w: scope root %q", ErrPath, r)
	}
	if slices.Contains(systemRoots, r) {
		return fmt.Errorf("%w: %s is a system root and cannot be a scope root", ErrScope, r)
	}
	for _, t := range systemTrees {
		if r == t || under(r, t) || under(t, r) {
			return fmt.Errorf("%w: %s reaches the host's %s tree", ErrScope, r, t)
		}
	}
	if r == in.Home || under(in.Home, r) {
		return fmt.Errorf("%w: %s is the home or holds it (the home is never a scope root; name the tool-state roots)", ErrScope, r)
	}
	for _, d := range observerDirs(in) {
		if d != "" && holdsWhole(r, d) {
			return fmt.Errorf("%w: scope root %s is the observer dir or holds it", ErrObserverDir, r)
		}
	}
	if c, hit := credentialHit(in.Home, r); hit {
		return fmt.Errorf("%w: scope root %s reaches ~/%s (%s)", ErrCredential, r, c.rel, c.why)
	}
	return nil
}

// inScope reports whether source is in the run's mount scope: the
// workspace, the socket dir or a tool-state root, or under one; or exactly
// one of the bin paths (audit finding O1A-R3).
func inScope(in Input, source string) bool {
	for _, r := range append([]string{in.Scope.Workspace, in.Scope.SocketDir}, in.Scope.ToolState...) {
		if source == r || under(source, r) {
			return true
		}
	}
	return slices.Contains(in.Scope.BinPaths, source)
}

// bindKind is what the compiler does with one bind-plan entry.
type bindKind string

// The bindKind values, one per row of bindRules.
const (
	kindDirBind  bindKind = "dir_bind"
	kindFileRO   bindKind = "file_bind_read_only"
	kindCopySync bindKind = "copy_sync"
)

// bindRules is the bind table (U-32): a directory is bound either way; a
// read-only file is bound (a rename onto it fails, as it should); a
// writable single file is never bound, it is copied in and synced back,
// because a rename onto a bind-mounted file fails (O0 R4).
var bindRules = []struct {
	file, readOnly bool
	kind           bindKind
}{
	{file: false, readOnly: false, kind: kindDirBind},
	{file: false, readOnly: true, kind: kindDirBind},
	{file: true, readOnly: true, kind: kindFileRO},
	{file: true, readOnly: false, kind: kindCopySync},
}

// classify returns the bind table's kind for b.
func classify(b Bind) bindKind {
	for _, r := range bindRules {
		if r.file == b.File && r.readOnly == b.ReadOnly {
			return r.kind
		}
	}
	return kindCopySync
}

// Compile turns the shipped inputs into the policy document, the driver
// mounts, the copied files and the environment.
//
// Compile is not the floor gate: selection is (sandboxselect.Select, and
// sandboxselect.FloorDrop at launch, which read every org and machine
// floor, the row's maturity and the run's capture). Compile reads no floor,
// so a successful compile never means the floors are met; its rules are
// only the ones that shape or validate the document (audit finding
// O1A-A8). The egress tier rule (K2) stays because the network rules it
// writes (netrules.go) are only defined for the tiers the row offers.
func Compile(in Input) (Plan, error) {
	for _, r := range compileRules {
		if err := r.check(in); err != nil {
			return Plan{}, err
		}
	}
	env, err := compileEnv(in)
	if err != nil {
		return Plan{}, err
	}
	var binds []Mount
	var copies []CopySync
	seen := map[string]bool{in.Home: true}
	for _, b := range in.Binds {
		if err := checkBind(in, b); err != nil {
			return Plan{}, err
		}
		if seen[b.Target] {
			return Plan{}, fmt.Errorf("%w: %s", ErrDuplicate, b.Target)
		}
		seen[b.Target] = true
		if classify(b) == kindCopySync {
			copies = append(copies, CopySync{Source: b.Source, Target: b.Target})
			continue
		}
		binds = append(binds, Mount{Type: mountBind, Source: b.Source, Target: b.Target, ReadOnly: b.ReadOnly})
	}
	sort.SliceStable(binds, func(i, j int) bool {
		di, dj := depth(binds[i].Target), depth(binds[j].Target)
		if di != dj {
			return di < dj
		}
		return binds[i].Target < binds[j].Target
	})
	home, shared := homeMount(in)
	mounts := binds
	if in.Settings.HomeMode != HomeLayer {
		mounts = append([]Mount{home}, binds...)
	}
	for _, p := range in.BoxReadWrite {
		if !cleanAbs(p) || !mountPath(p) {
			return Plan{}, fmt.Errorf("%w: box path %q", ErrPath, p)
		}
	}
	if err := checkCopyTargets(copies, mounts); err != nil {
		return Plan{}, err
	}
	sort.Slice(copies, func(i, j int) bool { return copies[i].Target < copies[j].Target })
	network, err := CompileNetRules(in.Settings.Egress, in.Net)
	if err != nil {
		return Plan{}, err
	}
	policy, err := renderPolicy(in, mounts, network, boxWritable(in))
	if err != nil {
		return Plan{}, err
	}
	dcfg, err := renderDriverConfig(in.Settings.Driver, mounts)
	if err != nil {
		return Plan{}, err
	}
	return Plan{PolicyYAML: policy, DriverConfigJSON: dcfg, Mounts: mounts, CopySync: copies, Env: env, SharedHome: shared, Network: network}, nil
}

// homeMount is the box's home: a tmpfs, always with mode 01777 (fact 1 of
// lane O0's verdict, HomeTmpfsMode) and so always shared, or a read-only
// bind of the host home, which rule K9 allows only when the observer dir is
// not inside it.
func homeMount(in Input) (Mount, bool) {
	if !SharedHome(in.Settings.HomeMode) {
		return Mount{Type: mountBind, Source: in.Home, Target: in.Home, ReadOnly: true}, false
	}
	return Mount{Type: mountTmpfs, Target: in.Home, Mode: HomeTmpfsMode}, true
}

// SharedHome reports whether a run with this home_mode gets the shared
// tmpfs home (Plan.SharedHome): every mode but "readonly" and the org
// row's "layer". The driver writes the run's posture note from it before
// the compile and checks the compiled plan agrees.
func SharedHome(homeMode string) bool { return homeMode != HomeReadonly && homeMode != HomeLayer }

// boxWritable is the writable box-local paths of a run: the BoxReadWrite
// directories, and the home itself under HomeLayer (no mount names it).
func boxWritable(in Input) []string {
	out := append([]string(nil), in.BoxReadWrite...)
	if in.Settings.HomeMode == HomeLayer {
		out = append(out, in.Home)
	}
	return out
}

// checkBind checks one bind-plan entry's paths.
func checkBind(in Input, b Bind) error {
	if !cleanAbs(b.Source) || !cleanAbs(b.Target) {
		return fmt.Errorf("%w: bind %q -> %q", ErrPath, b.Source, b.Target)
	}
	if !mountPath(b.Source) || !mountPath(b.Target) {
		return fmt.Errorf("%w: bind %q -> %q contains ':' or ',' (Docker reads binds as src:dst:mode strings)", ErrPath, b.Source, b.Target)
	}
	for _, r := range reservedTargets {
		if b.Target == r || under(b.Target, r) || under(r, b.Target) {
			return fmt.Errorf("%w: %s (%s)", ErrReserved, b.Target, r)
		}
	}
	for _, d := range observerDirs(in) {
		if holdsWhole(b.Source, d) {
			return fmt.Errorf("%w: %s holds it whole", ErrObserverDir, b.Source)
		}
		if !under(b.Source, d) {
			continue
		}
		// Under the observer dir only a read-only bind of an exact bin path
		// that is a regular file (Observer's own binary) is allowed:
		// observer.db, the attach socket's dir, the run records and every
		// token stay out (audit findings O1A-R2 and O1B-A9).
		if !b.ReadOnly {
			return fmt.Errorf("%w: %s would be writable", ErrObserverDir, b.Source)
		}
		if !slices.Contains(in.Scope.BinPaths, b.Source) {
			return fmt.Errorf("%w: %s is under it and is not a named bin path", ErrObserverDir, b.Source)
		}
		if !b.File {
			return fmt.Errorf("%w: %s is a dir under it; only a regular file (Observer's own binary) may be bound from there", ErrObserverDir, b.Source)
		}
	}
	if c, hit := credentialHit(in.Home, b.Source); hit {
		return fmt.Errorf("%w: %s reaches ~/%s (%s)", ErrCredential, b.Source, c.rel, c.why)
	}
	if !inScope(in, b.Source) {
		return fmt.Errorf("%w: %s", ErrScope, b.Source)
	}
	if b.Target != b.Source {
		return fmt.Errorf("%w: %s -> %s", ErrSamePath, b.Source, b.Target)
	}
	return nil
}

// observerDirs are the spellings of the observer dir every check runs
// against: ObserverDir and, when given, ObserverDirResolved.
func observerDirs(in Input) []string {
	if in.ObserverDirResolved == "" || in.ObserverDirResolved == in.ObserverDir {
		return []string{in.ObserverDir}
	}
	return []string{in.ObserverDir, in.ObserverDirResolved}
}

// holdsWhole reports whether a bind of source would carry the observer dir
// obs whole: source is obs or one of its ancestors. The bind plan's entries
// (checkBind) and the home mount (rule K9) both go through it.
func holdsWhole(source, obs string) bool {
	return source == obs || under(obs, source)
}

// checkCopyTargets requires the innermost mount over every copied file's
// target to be writable (the tmpfs home or a writable directory bind), so
// the box can create it and the tool can rename onto it. A writable
// ancestor is not enough: a read-only bind nested under it would make the
// copy-in fail with EROFS at start (audit finding O1A-A5), so it is refused
// at compile instead.
func checkCopyTargets(copies []CopySync, mounts []Mount) error {
	for _, c := range copies {
		inner := -1
		for i, m := range mounts {
			if under(c.Target, m.Target) && (inner < 0 || depth(m.Target) > depth(mounts[inner].Target)) {
				inner = i
			}
		}
		if inner < 0 || mounts[inner].ReadOnly {
			return fmt.Errorf("%w: %s", ErrCopyTarget, c.Target)
		}
	}
	return nil
}

// envKeyRE is the shape of an environment variable name.
var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// compileEnv validates the run's environment and puts HOME first.
func compileEnv(in Input) ([]string, error) {
	out := []string{"HOME=" + in.Home}
	for _, kv := range in.Env {
		k, _, found := strings.Cut(kv, "=")
		if !found || !envKeyRE.MatchString(k) || k == "HOME" || strings.ContainsAny(kv, "\x00\n") {
			return nil, fmt.Errorf("%w: %q", ErrEnv, k)
		}
		out = append(out, kv)
	}
	return out, nil
}

// renderPolicy writes the policy document (version: 1). Paths are JSON
// string literals, which YAML reads as double-quoted scalars; the shape is
// lane O0's live policy (o0helper.py render_policy), except include_workdir:
// every live run rendered it true (run.sh passes no --no-workdir), and the
// planner writes false because the run's workspace is a same-path bind and
// OpenShell's /sandbox workdir is never used. That difference is unmeasured
// and named for lane O1B's live run (audit finding O1A-A6). Landlock is a
// hard requirement, as live. The network_policies section is the network
// rule compiler's (netrules.go, lane O3): absent on the proxy_only and none
// tiers (no rule: all egress denied), the host allow-list rule on the
// internet tier. With a rule present OpenShell adds its baseline paths
// (read-only /usr /lib /etc /app /var/log /proc /dev/urandom, read-write
// /tmp /dev/null, o0-receipts.md), a subset of or beside the system paths
// listed here, so the workload's filesystem view only gains /app and
// /var/log read-only.
func renderPolicy(in Input, mounts []Mount, network []NetRule, boxRW []string) ([]byte, error) {
	var ro, rw []string
	rw = append(rw, boxRW...)
	for _, m := range mounts {
		if m.Type == mountTmpfs || !m.ReadOnly {
			rw = append(rw, m.Target)
			continue
		}
		ro = append(ro, m.Target)
	}
	sort.Strings(ro)
	sort.Strings(rw)
	ro = mergePaths(systemReadOnly, ro)
	rw = mergePaths(systemReadWrite, rw)
	if len(ro)+len(rw) > maxPolicyPaths {
		return nil, fmt.Errorf("%w (%d)", ErrTooManyPaths, len(ro)+len(rw))
	}
	var b bytes.Buffer
	b.WriteString("version: 1\nfilesystem_policy:\n  include_workdir: false\n  read_only:\n")
	for _, p := range ro {
		b.WriteString("    - " + quote(p) + "\n")
	}
	b.WriteString("  read_write:\n")
	for _, p := range rw {
		b.WriteString("    - " + quote(p) + "\n")
	}
	b.WriteString("landlock:\n  compatibility: hard_requirement\nprocess:\n")
	b.WriteString("  run_as_user: " + quote(strconv.Itoa(in.UID)) + "\n")
	b.WriteString("  run_as_group: " + quote(strconv.Itoa(in.GID)) + "\n")
	b.WriteString(renderNetwork(network))
	return b.Bytes(), nil
}

// mergePaths returns base followed by the entries of extra not already in
// it.
func mergePaths(base, extra []string) []string {
	out := append([]string(nil), base...)
	for _, p := range extra {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// renderDriverConfig writes --driver-config-json: {"<driver>":{"mounts":[...]}}.
func renderDriverConfig(driver string, mounts []Mount) (string, error) {
	if driver == "" {
		driver = "docker"
	}
	b, err := json.Marshal(map[string]map[string][]Mount{driver: {"mounts": mounts}})
	if err != nil {
		return "", fmt.Errorf("sandboxopenshell.renderDriverConfig: %w", err)
	}
	return string(b), nil
}

// quote renders s as a JSON string literal (a YAML double-quoted scalar),
// without HTML escaping.
func quote(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return strings.TrimSuffix(b.String(), "\n")
}

// cleanAbs reports whether p is absolute, clean and free of control
// characters.
func cleanAbs(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// mountPath reports whether p can be a mount path: neither ':' nor ','
// (audit finding O1A-A7), because upstream renders Docker binds as
// src:dst:mode strings (o0-receipts "Docker binds go through
// HostConfig.Binds strings") and a --mount rendering splits on ','. The
// read-only flag must never depend on Docker's parser.
func mountPath(p string) bool {
	return !strings.ContainsAny(p, ":,")
}

// under reports whether p is strictly below dir.
func under(p, dir string) bool {
	if dir == "/" {
		return p != "/" && strings.HasPrefix(p, "/")
	}
	return strings.HasPrefix(p, dir+"/")
}

// depth is the number of path elements of a clean absolute path.
func depth(p string) int {
	if p == "/" {
		return 0
	}
	return strings.Count(p, "/")
}
