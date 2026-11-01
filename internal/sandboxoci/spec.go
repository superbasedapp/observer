package sandboxoci

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Bind is one host path exposed in the container at Target.
type Bind struct {
	Source   string
	Target   string
	ReadOnly bool
}

// CreatePlan is the run's bind plan as the cmd layer resolved it: every path
// absolute and symlink-free on the host, every protected path already turned
// into a hide or a read-only bind (the same protection table the bwrap
// driver uses, terminal_sandbox.go overlays()). The planner validates and
// renders it; it never adds a mount the plan did not name.
type CreatePlan struct {
	RunID     string
	InstallID string
	// Image is the run's image, pinned by digest.
	Image string
	// WorkDir is the agent's working directory, the workspace at its host
	// path (same-path delivery, section 6 bind_same_path).
	WorkDir string
	// Entrypoint is the container's main process: the in-container init
	// (`observer sandbox-oci-init -- observer sandbox-guest ... -- observer
	// <verb>`, section 5.5 "Main process").
	Entrypoint []string
	Env        []string
	// Binds: the workspace (rw), the tool state (rw), the observer binary
	// and the relay socket dir (ro), the protected-state overlays (ro).
	Binds []Bind
	// Pins are existing paths inside a read-write bind (a repository folder
	// and its .git under the workspace or an extra write bind) bound onto
	// themselves, keeping their writability (the bwrap path's
	// sandbox.Request.Pins, SBX-WORKTREE-SOURCE audit finding 4, built for
	// this driver in lane SHR-FOLLOWUPS): a mount point cannot be renamed
	// (EBUSY), so the box cannot move a .git aside and plant a replacement
	// the read-only overlays over its hooks and config would no longer
	// cover. Rendered after the binds; the depth sort then mounts each after
	// its enclosing write bind and before the overlays inside it. A pin
	// outside every read-write bind is refused (it would make a read-only
	// path writable).
	Pins []string
	// HideFiles are covered by a read-only bind of /dev/null; HideDirs by
	// an empty read-only tmpfs.
	HideFiles []string
	HideDirs  []string
	// Tmpfs are writable tmpfs mounts (the home, /tmp).
	Tmpfs []string
	// Volumes are named volumes (the tool cache of a cache-installed tool,
	// read-only; lane SBX-P3C). A volume exposes no host path the plan did
	// not name: its contents are what the setup container installed.
	Volumes []VolumeMount
	User    UserPlan
	// ReadonlyRootfs: the image's root filesystem is mounted read-only.
	ReadonlyRootfs bool
	// StopGraceSeconds is the engine's stop timeout.
	StopGraceSeconds int
	// EngineSocket is the engine socket the host helper drives; no bind may
	// expose it (it is root-equivalent on a rootful engine and full control
	// of every container on a rootless one).
	EngineSocket string
	// ObserverDir is the host's ~/.observer; it never enters the box whole
	// (the container never sees observer.db), only files bound from it.
	ObserverDir string
	// PidsLimit caps the container's tasks (0 = engine default).
	PidsLimit int64
	// Engine is the engine the probe identified on the socket. It picks
	// the owner option of a writable tmpfs (tmpfsOwnerTable): Docker and
	// Podman accept different spellings (live check 2026-10-22, D5).
	Engine Engine
	// Runtime is the OCI runtime the create asks for (HostConfig.Runtime,
	// the row's RuntimeProfile.CreateRuntime): "" for the engine's default
	// (oci-runc), "runsc" for the oci-runsc row. The read-back requires the
	// engine to report exactly it.
	Runtime string
}

// MountSpec is one HostConfig.Mounts entry of the Engine API.
type MountSpec struct {
	Type        string       `json:"Type"`
	Source      string       `json:"Source,omitempty"`
	Target      string       `json:"Target"`
	ReadOnly    bool         `json:"ReadOnly"`
	BindOptions *BindOptions `json:"BindOptions,omitempty"`
}

// BindOptions is the bind propagation (rprivate: no mount made later on the
// host shows up in the box). Only the engines whose bindOptionsTable row
// sends it get it.
type BindOptions struct {
	Propagation string `json:"Propagation"`
}

// bindOptionsRow is one engine's form of a bind's options in the create
// body: what every bind carries so that it is mounted recursively (rbind)
// with private propagation.
type bindOptionsRow struct {
	engine Engine
	// propagation is the BindOptions.Propagation sent; "" sends no
	// BindOptions at all.
	propagation string
}

// bindOptionsTable is walked by engine; an engine with no row sends none
// (the "engine" spec rule has already refused an engine with no tmpfs
// owner form, so both rows below are the engines a plan can name).
var bindOptionsTable = []bindOptionsRow{
	// Docker Engine mounts a bind recursively unless BindOptions sets
	// NonRecursive, and takes the propagation as given: rprivate, stated so
	// no mount made later on the host shows up in the box. Unchanged since
	// the driver was built (live checks of 2026-10-22 and 2026-10-23 on
	// rootful Docker 29.9.2 with runc and runsc passed with it).
	{engine: EngineDocker, propagation: "rprivate"},
	// Podman's Docker-compatible create turns a bind that carries any
	// BindOptions into a NON-recursive bind (Linux live re-check on the
	// Docker sandbox, 2026-10-23, Podman 5.7.0, N2: the same mount through
	// the API is [rbind] with no BindOptions, [bind] with Propagation
	// rprivate, and still [bind] with NonRecursive false). Under keep-id
	// runc runs the container in a nested user namespace where the mounts
	// Podman made under the bound tree (the container's own userdata/shm
	// tmpfs under ~/.local/share) are locked, and the kernel refuses a
	// non-recursive bind of a tree with locked submounts with EINVAL, so
	// every launch on runc failed before the agent started (crun passed).
	// With no BindOptions Podman mounts rbind with its default bind
	// propagation, rprivate (podman-run(1) bind-propagation), which is what
	// the Docker row states. The replay of the driver's own create body
	// with BindOptions removed initialized on runc.
	{engine: EnginePodman},
}

// bindOptionsFor is engine's BindOptions for one bind (a fresh value per
// mount), nil when its row sends none.
func bindOptionsFor(engine Engine) *BindOptions {
	for _, r := range bindOptionsTable {
		if r.engine == engine {
			if r.propagation == "" {
				return nil
			}
			return &BindOptions{Propagation: r.propagation}
		}
	}
	return nil
}

// LogConfig is the container's log driver.
type LogConfig struct {
	Type string `json:"Type"`
}

// RestartPolicy is never "restart": a run ends with its agent.
type RestartPolicy struct {
	Name string `json:"Name"`
}

// DeviceMapping is one HostConfig.Devices entry; the driver sends none.
type DeviceMapping struct {
	PathOnHost        string `json:"PathOnHost"`
	PathInContainer   string `json:"PathInContainer"`
	CgroupPermissions string `json:"CgroupPermissions"`
}

// HostConfig is the subset of the Engine API HostConfig the driver sets.
type HostConfig struct {
	NetworkMode    string   `json:"NetworkMode"`
	CapDrop        []string `json:"CapDrop"`
	CapAdd         []string `json:"CapAdd"`
	SecurityOpt    []string `json:"SecurityOpt"`
	ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
	Privileged     bool     `json:"Privileged"`
	UsernsMode     string   `json:"UsernsMode,omitempty"`
	// Runtime is omitted for the engine's default runtime, so an oci-runc
	// create body is byte for byte what it was before the oci-runsc row.
	Runtime    string `json:"Runtime,omitempty"`
	Init       bool   `json:"Init"`
	AutoRemove bool   `json:"AutoRemove"`
	IpcMode    string `json:"IpcMode"`
	PidsLimit  int64  `json:"PidsLimit,omitempty"`
	// Devices is always sent as [] (never omitted), so the create states
	// "no devices" the way the docker CLI does instead of leaving it to the
	// engine's default (live checks 2026-10-22, D1).
	Devices       []DeviceMapping `json:"Devices"`
	LogConfig     LogConfig       `json:"LogConfig"`
	RestartPolicy RestartPolicy   `json:"RestartPolicy"`
	Mounts        []MountSpec     `json:"Mounts"`
	// Tmpfs are the writable and the hiding tmpfs mounts with their mount
	// options (owner, mode, size), which the Mounts tmpfs form cannot set.
	Tmpfs map[string]string `json:"Tmpfs,omitempty"`
}

// CreateBody is the POST /containers/create body.
type CreateBody struct {
	User         string            `json:"User"`
	AttachStdin  bool              `json:"AttachStdin"`
	AttachStdout bool              `json:"AttachStdout"`
	AttachStderr bool              `json:"AttachStderr"`
	Tty          bool              `json:"Tty"`
	OpenStdin    bool              `json:"OpenStdin"`
	StdinOnce    bool              `json:"StdinOnce"`
	Env          []string          `json:"Env"`
	Entrypoint   []string          `json:"Entrypoint"`
	Cmd          []string          `json:"Cmd"`
	Image        string            `json:"Image"`
	WorkingDir   string            `json:"WorkingDir"`
	Labels       map[string]string `json:"Labels"`
	StopSignal   string            `json:"StopSignal"`
	StopTimeout  int               `json:"StopTimeout"`
	HostConfig   HostConfig        `json:"HostConfig"`
}

// The fixed hardening every container gets (section 4.6, SBX-BE-3).
const (
	NetworkNone      = "none"
	CapAll           = "ALL"
	NoNewPrivileges  = "no-new-privileges"
	logDriverNone    = "none"
	defaultStopGrace = 10
	hideTmpfsBytes   = 4096
	tmpfsBytes       = 1 << 30
)

// digestRefRE is an image reference pinned by a sha256 digest.
var digestRefRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$`)

// ValidateImageRef accepts only an image pinned by digest; a tag can move
// under the run (section 13 P3, SBX-BE-3).
func ValidateImageRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fmt.Errorf("no image is configured: set [terminal.sandbox.oci].image to an image pinned by digest (name@sha256:...); Observer's own default image is not published yet")
	}
	if !digestRefRE.MatchString(ref) {
		return fmt.Errorf("image %q is not pinned by digest: use name@sha256:<64 hex>", ref)
	}
	return nil
}

// envDenied are variables the box's environment must never carry: engine
// endpoints (a box must never learn a socket), and the loader and runtime
// hooks the inner launcher must not inherit.
var envDenied = []string{"DOCKER_HOST", "CONTAINER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "LD_PRELOAD", "LD_LIBRARY_PATH", "NODE_OPTIONS"}

// DeniedEnv returns the variables a box's environment never carries (the
// host helper strips them from the environment it passes in).
func DeniedEnv() []string { return append([]string(nil), envDenied...) }

// specRule is one validation row of a create plan.
type specRule struct {
	name  string
	check func(p CreatePlan) error
}

func cleanAbs(p string) bool { return p != "" && path.IsAbs(p) && path.Clean(p) == p }

// under reports whether p is dir or inside it.
func under(p, dir string) bool {
	if dir == "" {
		return false
	}
	return p == dir || dir == "/" || strings.HasPrefix(p, dir+"/")
}

// The answers of nearestPinMount.
const (
	pinOutside = iota
	pinUnderReadOnly
	pinUnderWriteBind
)

// nearestPinMount classifies the mount nearest above pin (the deepest bind,
// hidden directory or tmpfs target pin lies strictly inside; lane
// SHR-FOLLOWUPS audit finding 1): a pin is mounted read-write only when that
// mount is a read-write bind, so a read-only bind nested in a write bind
// never has its .git reopened writable. A pin that is itself a mount target
// is outside. The cmd seam's sandbox.PinWritable applies the same rule
// before a pin reaches the plan; this package is stdlib-only, so the rule is
// restated here as the planner's backstop.
func nearestPinMount(p CreatePlan, pin string) int {
	best, writable := -1, false
	consider := func(target string, rw bool) bool {
		if target == pin {
			return false
		}
		if target == "" || !under(pin, target) {
			return true
		}
		switch d := len(target); {
		case d > best:
			best, writable = d, rw
		case d == best:
			writable = writable && rw
		}
		return true
	}
	for _, b := range p.Binds {
		if !consider(b.Target, !b.ReadOnly) {
			return pinOutside
		}
	}
	for _, d := range p.HideDirs {
		if !consider(d, false) {
			return pinOutside
		}
	}
	for _, d := range p.Tmpfs {
		if !consider(d, false) {
			return pinOutside
		}
	}
	switch {
	case best < 0:
		return pinOutside
	case !writable:
		return pinUnderReadOnly
	}
	return pinUnderWriteBind
}

// specRules is walked top-down; the first failing row refuses the plan.
var specRules = []specRule{
	{"ids", func(p CreatePlan) error {
		if !ValidToken(p.RunID) || !ValidToken(p.InstallID) {
			return fmt.Errorf("run id %q or install id %q is not a clean token", p.RunID, p.InstallID)
		}
		return nil
	}},
	{"image", func(p CreatePlan) error { return ValidateImageRef(p.Image) }},
	{"entrypoint", func(p CreatePlan) error {
		if len(p.Entrypoint) == 0 || !cleanAbs(p.Entrypoint[0]) {
			return fmt.Errorf("the entrypoint must start with the absolute path of the observer binary")
		}
		return nil
	}},
	{"workdir", func(p CreatePlan) error {
		if !cleanAbs(p.WorkDir) {
			return fmt.Errorf("working directory %q is not a clean absolute path", p.WorkDir)
		}
		for _, b := range p.Binds {
			if b.Target == p.WorkDir && !b.ReadOnly {
				return nil
			}
		}
		return fmt.Errorf("the workspace %s is not bound read-write at its own path", p.WorkDir)
	}},
	{"paths", func(p CreatePlan) error {
		seen := map[string]bool{}
		check := func(kind, src, dst string) error {
			if (src != "" && !cleanAbs(src)) || !cleanAbs(dst) {
				return fmt.Errorf("%s %q -> %q is not a clean absolute path", kind, src, dst)
			}
			if dst == "/" || under(dst, "/proc") || under(dst, "/sys") || under(dst, "/dev") {
				return fmt.Errorf("%s target %s is reserved", kind, dst)
			}
			if seen[dst] {
				return fmt.Errorf("%s target %s is mounted twice", kind, dst)
			}
			seen[dst] = true
			return nil
		}
		for _, b := range p.Binds {
			if err := check("bind", b.Source, b.Target); err != nil {
				return err
			}
		}
		for _, pin := range p.Pins {
			if err := check("pin", pin, pin); err != nil {
				return err
			}
		}
		for _, d := range p.Tmpfs {
			if err := check("tmpfs", "", d); err != nil {
				return err
			}
		}
		for _, v := range p.Volumes {
			if !strings.HasPrefix(v.Name, CacheVolumePrefix) {
				return fmt.Errorf("volume %q is not an Observer tool cache", v.Name)
			}
			if err := check("volume", "", v.Target); err != nil {
				return err
			}
		}
		for _, f := range p.HideFiles {
			if err := check("hidden file", "", f); err != nil {
				return err
			}
		}
		for _, d := range p.HideDirs {
			if err := check("hidden dir", "", d); err != nil {
				return err
			}
		}
		return nil
	}},
	{"pins", func(p CreatePlan) error {
		for _, pin := range p.Pins {
			switch nearestPinMount(p, pin) {
			case pinOutside:
				return fmt.Errorf("pin %s lies outside every read-write bind", pin)
			case pinUnderReadOnly:
				return fmt.Errorf("pin %s lies under a read-only bind, a hidden directory or a tmpfs nested in a read-write bind", pin)
			}
		}
		return nil
	}},
	{"engine socket", func(p CreatePlan) error {
		if p.EngineSocket == "" {
			return fmt.Errorf("the engine socket is not named, so no bind can be checked against it")
		}
		for _, b := range p.Binds {
			if under(p.EngineSocket, b.Source) {
				return fmt.Errorf("bind %s would expose the engine socket %s inside the box", b.Source, p.EngineSocket)
			}
		}
		return nil
	}},
	{"observer dir", func(p CreatePlan) error {
		if p.ObserverDir == "" {
			return nil
		}
		reblind := false
		for _, d := range p.Tmpfs {
			reblind = reblind || d == p.ObserverDir
		}
		for _, b := range p.Binds {
			if !under(p.ObserverDir, b.Source) {
				continue
			}
			// A same-path bind of a parent (a project at the home
			// directory) is allowed only with the observer dir blinded
			// again by a tmpfs at its own path.
			if reblind && b.Target == b.Source {
				continue
			}
			return fmt.Errorf("bind %s would expose the whole observer directory (and observer.db) inside the box", b.Source)
		}
		return nil
	}},
	{"env", func(p CreatePlan) error {
		for _, kv := range p.Env {
			k, _, ok := strings.Cut(kv, "=")
			if !ok || k == "" {
				return fmt.Errorf("environment entry %q is not KEY=value", kv)
			}
			for _, d := range envDenied {
				if k == d {
					return fmt.Errorf("the box's environment may not set %s", k)
				}
			}
		}
		return nil
	}},
	{"runtime", func(p CreatePlan) error {
		if p.Runtime == "" {
			return nil
		}
		for _, rp := range runtimeProfiles {
			if rp.CreateRuntime != "" && rp.CreateRuntime == p.Runtime {
				return nil
			}
		}
		return fmt.Errorf("runtime %q is not an oci-* row's runtime", p.Runtime)
	}},
	{"engine", func(p CreatePlan) error {
		if _, ok := tmpfsOwnerFor(p.Engine); !ok {
			return fmt.Errorf("engine %q has no tmpfs owner form", p.Engine)
		}
		return nil
	}},
	{"user", func(p CreatePlan) error {
		if p.User.User == "" {
			return fmt.Errorf("no uid table row was chosen")
		}
		if (p.User.User == "0:0" || strings.HasPrefix(p.User.User, "0:")) && !p.User.ContainerRootIsHostUser {
			return fmt.Errorf("the uid row %q would run container root on an engine where root is not the host user", p.User.Row)
		}
		return nil
	}},
}

// BuildCreate validates the plan and renders the create body and the
// container name. Mounts are sorted by target so a parent is always
// mounted before what is bound inside it.
func BuildCreate(p CreatePlan) (string, CreateBody, error) {
	for _, r := range specRules {
		if err := r.check(p); err != nil {
			return "", CreateBody{}, fmt.Errorf("sandboxoci: create plan (%s): %w", r.name, err)
		}
	}
	grace := p.StopGraceSeconds
	if grace <= 0 {
		grace = defaultStopGrace
	}
	var mounts []MountSpec
	for _, b := range p.Binds {
		mounts = append(mounts, MountSpec{Type: "bind", Source: b.Source, Target: b.Target, ReadOnly: b.ReadOnly, BindOptions: bindOptionsFor(p.Engine)})
	}
	for _, pin := range p.Pins {
		mounts = append(mounts, MountSpec{Type: "bind", Source: pin, Target: pin, BindOptions: bindOptionsFor(p.Engine)})
	}
	for _, v := range p.Volumes {
		mounts = append(mounts, MountSpec{Type: "volume", Source: v.Name, Target: v.Target, ReadOnly: v.ReadOnly})
	}
	tmpfs := map[string]string{}
	row, _ := tmpfsOwnerFor(p.Engine)
	uid, gid := userIDs(p.User.User)
	owner := row.option(uid, gid)
	for _, d := range p.Tmpfs {
		tmpfs[d] = fmt.Sprintf("rw,nosuid,nodev,size=%d,mode=0700,%s", tmpfsBytes, owner)
	}
	for _, f := range p.HideFiles {
		mounts = append(mounts, MountSpec{Type: "bind", Source: "/dev/null", Target: f, ReadOnly: true, BindOptions: bindOptionsFor(p.Engine)})
	}
	for _, d := range p.HideDirs {
		tmpfs[d] = fmt.Sprintf("ro,nosuid,nodev,noexec,size=%d,mode=0500", hideTmpfsBytes)
	}
	if len(tmpfs) == 0 {
		tmpfs = nil
	}
	sort.SliceStable(mounts, func(i, j int) bool { return mountDepth(mounts[i].Target) < mountDepth(mounts[j].Target) })
	body := CreateBody{
		User: p.User.User, AttachStdin: true, AttachStdout: true, AttachStderr: true,
		Tty: true, OpenStdin: true, StdinOnce: false,
		Env: append([]string(nil), p.Env...), Entrypoint: append([]string(nil), p.Entrypoint...), Cmd: []string{},
		Image: strings.TrimSpace(p.Image), WorkingDir: p.WorkDir,
		Labels: Labels(p.InstallID, p.RunID), StopSignal: "SIGTERM", StopTimeout: grace,
		HostConfig: HostConfig{
			NetworkMode: NetworkNone, CapDrop: []string{CapAll}, CapAdd: []string{}, SecurityOpt: []string{NoNewPrivileges},
			ReadonlyRootfs: p.ReadonlyRootfs, UsernsMode: p.User.UsernsMode, Runtime: p.Runtime, IpcMode: "private", PidsLimit: p.PidsLimit, Devices: []DeviceMapping{},
			LogConfig: LogConfig{Type: logDriverNone}, RestartPolicy: RestartPolicy{Name: "no"}, Mounts: mounts, Tmpfs: tmpfs,
		},
	}
	return ContainerName(p.InstallID, p.RunID), body, nil
}

// tmpfsOwnerRow is one engine's spelling of the owner option of a
// writable tmpfs (the container user owns it, so a rootful run's home is
// writable by the host uid it runs as), and how its inspect answer shows
// that option.
type tmpfsOwnerRow struct {
	engine Engine
	// option is the mount option for the container user uid:gid.
	option func(uid, gid string) string
	// shown reports whether a read-back option list carries it.
	shown func(opts []string, uid, gid string) bool
}

// tmpfsOwnerTable is walked by engine; an engine with no row is refused by
// the "engine" spec rule before anything is created.
var tmpfsOwnerTable = []tmpfsOwnerRow{
	// Docker Engine passes uid= and gid= to the tmpfs mount and reads them
	// back verbatim (live check 2026-10-22: Docker 29.9.2 rootful,
	// "rw,nosuid,nodev,size=1073741824,mode=0700,uid=1000,gid=1000").
	{
		engine: EngineDocker,
		option: func(uid, gid string) string { return "uid=" + uid + ",gid=" + gid },
		shown:  func(o []string, uid, gid string) bool { return hasOption(o, "uid="+uid) && hasOption(o, "gid="+gid) },
	},
	// Podman refuses uid= and gid= (5.7.0: `unknown mount option "uid=1000":
	// invalid mount option`, live check D5; pkg/util/mount_opts.go
	// ProcessOptions has no uid or gid case). Its own U option chowns a tmpfs
	// to the container process's user: libpod's generateSpec turns U on a
	// tmpfs into uid=<execUser.Uid>,gid=<execUser.Gid> of the container's
	// User field (podman-run(1) --mount type=tmpfs "U, chown"). Inspect
	// reports the stored options, U included (libpod container_inspect.go
	// joins the spec mount's options).
	{
		engine: EnginePodman,
		option: func(string, string) string { return "U" },
		shown:  func(o []string, _, _ string) bool { return hasOption(o, "U") },
	},
}

// tmpfsOwnerFor is engine's row of tmpfsOwnerTable.
func tmpfsOwnerFor(engine Engine) (tmpfsOwnerRow, bool) {
	for _, r := range tmpfsOwnerTable {
		if r.engine == engine {
			return r, true
		}
	}
	return tmpfsOwnerRow{}, false
}

// userIDs splits a container User ("uid:gid", or "uid" alone).
func userIDs(user string) (string, string) {
	uid, gid, ok := strings.Cut(user, ":")
	if !ok {
		gid = uid
	}
	return uid, gid
}

// hasOption reports whether a comma-split option list holds opt exactly.
func hasOption(opts []string, opt string) bool {
	for _, o := range opts {
		if strings.TrimSpace(o) == opt {
			return true
		}
	}
	return false
}

func mountDepth(p string) int { return strings.Count(path.Clean(p), "/") }
