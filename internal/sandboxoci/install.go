package sandboxoci

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// install.go is the first-start install step of the container driver
// (sandbox plan v2 section 5.4 "Agent tool delivery", 13 P3, ledger
// SBX-IMG-1, lane SBX-P3C): when the image cannot run the host's own copy
// of the tool, a short setup container from the SAME image installs the
// vendor's package into a per-image cache volume, and later launches mount
// that volume read-only. The setup container gets:
//
//   - no workspace, no tool state, no credential and no host environment:
//     its environment is the fixed allow-list InstallEnv builds (the proxy
//     variables naming its own loopback forward, a throwaway HOME and npm
//     cache under its private /tmp);
//   - a read-only root, every capability dropped, no new privileges,
//     --network none, a small pids limit, no devices, no log driver;
//   - three mounts only: the observer binary (read-only, it runs the
//     in-box forward and then the installer), the install gateway's socket
//     directory (read-only), and the cache volume (read-write);
//   - egress only through its own gateway, whose host allow-list is the
//     tool's install source host set (internal/integration's side table).
//
// The cache volume is keyed by the image digest, the tool and the version
// (CacheVolumeName) and labelled for this install (CacheLabels), so a
// shared engine never mixes two installs' caches and the prune of a revoked
// image finds its caches by label. The version is the host's installed
// version of the same tool (ValidInstallVersion), never "latest": a cache of
// another version than the host's is stale (ClassifyCache) and refreshed on
// the next consented launch.
//
// Everything here is pure: the cmd layer reads the facts, runs the engine
// calls and asks the user.

// The install refusals (each a Verdict code; the delivery table uses them).
const (
	// VerdictInstallSourceUnknown: no grounded in-box install source for
	// the tool (internal/integration's side table has no row).
	VerdictInstallSourceUnknown = "install_source_unknown"
	// VerdictInstallVersionUnknown: the host has no readable version of the
	// tool to pin the install to (a version picker is later).
	VerdictInstallVersionUnknown = "install_version_unknown"
	// VerdictInstallRuntimeMissing: the image lacks the installer's runtime
	// (npm and node for the npm installer), probed like the tool (S11).
	VerdictInstallRuntimeMissing = "install_runtime_missing"
	// VerdictInstallScriptsRequired: the tool's install source declares that
	// its package needs its own install script, and the first-start install
	// runs no package script under its host allow-list (lane SBX-P3C audit
	// finding 2).
	VerdictInstallScriptsRequired = "install_scripts_required"
)

// ToolCacheMount is where the cache volume is mounted, in the setup
// container (read-write) and in the agent's container (read-only).
const ToolCacheMount = "/observer-tool-cache"

// InstallProxyPort is the setup container's loopback forward to its
// gateway socket (the in-box forward listens on 127.0.0.1 only).
const InstallProxyPort = 3128

// The cache volume's labels.
const (
	// RoleToolCache is the LabelRole value of a tool cache volume.
	RoleToolCache     = "tool-cache"
	LabelCacheTool    = "app.superbased.observer.cache.tool"
	LabelCacheVersion = "app.superbased.observer.cache.version"
	LabelCacheImage   = "app.superbased.observer.cache.image"
	LabelCachePackage = "app.superbased.observer.cache.package"
	// CacheVolumePrefix starts every cache volume name.
	CacheVolumePrefix = "observer-tool-"
)

// InstallSource is the cmd layer's copy of one install source row (the
// registry's side table; this package names no tool).
type InstallSource struct {
	Kind    string
	Package string
	Bin     string
	Hosts   []string
	// NeedsScripts is the row's NeedsInstallScripts: such a source is
	// refused (VerdictInstallScriptsRequired) unless ScriptSHA256 names the
	// reviewed scripts the guest may run (DecideInstallScripts, lane
	// LEFT-SBX).
	NeedsScripts bool
	// ScriptSHA256 are the accepted sha256 hashes of the package's own
	// lifecycle script files for this version (DecideInstallScripts). Empty
	// for a source that needs no script.
	ScriptSHA256 []string
	// ScriptPackages are the artifacts the install may fetch, each pinned by
	// its registry integrity (ScriptDecision.Packages, ruling P-142): the
	// guest checks them before it runs a script. Empty for a source whose
	// script fetches nothing.
	ScriptPackages []PackagePin
}

// ScriptRunFlag and ScriptSHAFlag are the setup container's guest flags
// that name the installed package directory whose pinned lifecycle scripts
// it runs after the installer, and each accepted script hash.
const (
	ScriptRunFlag = "--run-scripts"
	ScriptSHAFlag = "--script-sha"
)

// installerRow is one installer kind: the runtime programs the image must
// hold, the install command over the cache prefix, and the bin directory
// the command fills under it.
type installerRow struct {
	kind    string
	runtime []string
	argv    func(pkg, version, prefix string) []string
	binDir  string
	// pkgDir is where the installed package lands under prefix, for its
	// pinned lifecycle scripts (nil for a kind that runs none).
	pkgDir func(prefix, pkg string) string
	// pkgRE is the kind's package name shape (it goes into the argv).
	pkgRE *regexp.Regexp
	// env are the kind's own fixed environment variables (InstallEnvFor).
	env []string
}

// installerTable is walked by kind; a kind with no row is refused.
var installerTable = []installerRow{
	{
		kind:    "npm",
		runtime: []string{"node", "npm"},
		argv: func(pkg, version, prefix string) []string {
			// --ignore-scripts: no package's lifecycle script runs during the
			// install (lane SBX-P3C audit finding 2); a source that needs its
			// scripts never reaches this argv (VerdictInstallScriptsRequired).
			return []string{"npm", "install", "--global", "--prefix", prefix, "--ignore-scripts", "--no-audit", "--no-fund", "--no-update-notifier", pkg + "@" + version}
		},
		binDir: "bin",
		pkgDir: NPMPackageDir,
		pkgRE:  installPackageRE,
	},
	{
		// uv tool install (lane LEFT-SBX): wheels only, so no package code
		// runs at install (--no-build refuses a source build), and the
		// image's own python3, never a downloaded interpreter. The tool's
		// environment and its entry points land in the cache (UV_TOOL_DIR
		// and UV_TOOL_BIN_DIR in InstallEnv); the venv's interpreter link
		// names the image's python3, which the agent's container, from the
		// same image, holds at the same path.
		kind:    "uv",
		runtime: []string{"uv", "python3"},
		argv: func(pkg, version, _ string) []string {
			return []string{"uv", "tool", "install", "--no-build", "--no-python-downloads", "--python", "python3", "--no-config", pkg + "==" + version}
		},
		binDir: "bin",
		pkgRE:  pythonPackageRE,
		// The tool environments and their entry points in the cache, uv's
		// own cache in /tmp, and never a downloaded interpreter.
		env: []string{
			"UV_TOOL_DIR=" + ToolCacheMount + "/uv-tools",
			"UV_TOOL_BIN_DIR=" + ToolCacheMount + "/bin",
			"UV_CACHE_DIR=/tmp/observer-install-uv-cache",
			"UV_PYTHON_DOWNLOADS=never",
		},
	},
}

// pythonPackageRE is a Python package index name (PEP 508's name rule).
var pythonPackageRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,100}[A-Za-z0-9])?$`)

func installerFor(kind string) (installerRow, bool) {
	for _, r := range installerTable {
		if r.kind == kind {
			return r, true
		}
	}
	return installerRow{}, false
}

// InstallerRuntime is the programs the image must hold for kind (probed
// with ImageToolPaths), ok false for an unknown kind.
func InstallerRuntime(kind string) ([]string, bool) {
	r, ok := installerFor(kind)
	if !ok {
		return nil, false
	}
	return append([]string(nil), r.runtime...), true
}

// CacheBinDir is the bin directory the installer of kind fills in the cache,
// at its in-box path ("" for an unknown kind).
func CacheBinDir(kind string) string {
	r, ok := installerFor(kind)
	if !ok {
		return ""
	}
	return ToolCacheMount + "/" + r.binDir
}

// installVersionRE is the version an install may be pinned to: a plain
// semantic version (with an optional pre-release or build suffix). It goes
// into the installer's argv as pkg@version, so nothing else is allowed.
var installVersionRE = regexp.MustCompile(`^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}([-+][0-9A-Za-z][0-9A-Za-z.-]{0,40})?$`)

// ValidInstallVersion reports whether v can pin an install.
func ValidInstallVersion(v string) bool { return installVersionRE.MatchString(v) }

// installPackageRE is an npm package name (scoped or not), lowercase.
var installPackageRE = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]{0,100}/)?[a-z0-9][a-z0-9._-]{0,100}$`)

// imageDigestRE finds the digest of a digest-pinned image reference.
var imageDigestRE = regexp.MustCompile(`@(sha256:[a-f0-9]{64})$`)

// ImageDigestOf returns the sha256 digest of a digest-pinned image
// reference.
func ImageDigestOf(ref string) (string, bool) {
	m := imageDigestRE.FindStringSubmatch(strings.TrimSpace(ref))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// CacheVolumeName is the cache volume of (install, image digest, tool,
// version): the prefix, a short install id and 24 hex of a hash over all
// four keys, so no tool or package text reaches the engine's name space.
func CacheVolumeName(installID, imageDigest, tool, version string) string {
	sum := sha256.Sum256([]byte(installID + "\x00" + imageDigest + "\x00" + tool + "\x00" + version))
	short := installID
	if len(short) > 8 {
		short = short[:8]
	}
	return CacheVolumePrefix + short + "-" + hex.EncodeToString(sum[:12])
}

// CacheLabels are a cache volume's labels.
func CacheLabels(installID, imageDigest, tool, version, pkg string) map[string]string {
	return map[string]string{
		LabelRole: RoleToolCache, LabelInstall: installID,
		LabelCacheTool: tool, LabelCacheVersion: version, LabelCacheImage: imageDigest, LabelCachePackage: pkg,
	}
}

// CacheFilter selects this install's cache volumes; tool and imageDigest
// narrow it when non-empty.
func CacheFilter(installID, imageDigest, tool string) map[string][]string {
	l := []string{LabelRole + "=" + RoleToolCache, LabelInstall + "=" + installID}
	if imageDigest != "" {
		l = append(l, LabelCacheImage+"="+imageDigest)
	}
	if tool != "" {
		l = append(l, LabelCacheTool+"="+tool)
	}
	return map[string][]string{"label": l}
}

// CacheVolumeFact is one volume the cache classification sees.
type CacheVolumeFact struct {
	Name   string
	Labels map[string]string
}

// CacheState is a tool cache's verdict for one launch.
type CacheState string

// The CacheState values.
const (
	// CacheAbsent: no cache of this image and tool.
	CacheAbsent CacheState = "absent"
	// CacheCurrent: a completed cache of exactly the host's version.
	CacheCurrent CacheState = "current"
	// CacheStale: only caches of other versions (the host's version
	// changed); the next consented launch refreshes it.
	CacheStale CacheState = "stale"
)

// CacheVerdict is ClassifyCache's answer: the state, the current volume's
// name (CacheCurrent), and the volumes a refresh removes (every other cache
// of this image and tool, completed or not).
type CacheVerdict struct {
	State   CacheState
	Current string
	Others  []string
}

// ClassifyCache judges the cache of (install, image, tool) for version from
// the engine's volume list. completed reports whether a volume's install
// finished (the host's own record: a volume the setup container never
// finished is not a cache). A volume that does not carry this install's,
// image's and tool's labels is never considered.
func ClassifyCache(vols []CacheVolumeFact, completed func(name string) bool, installID, imageDigest, tool, version string) CacheVerdict {
	want := CacheVolumeName(installID, imageDigest, tool, version)
	var v CacheVerdict
	for _, vol := range vols {
		l := vol.Labels
		if l[LabelRole] != RoleToolCache || l[LabelInstall] != installID || l[LabelCacheImage] != imageDigest || l[LabelCacheTool] != tool {
			continue
		}
		if vol.Name == want && l[LabelCacheVersion] == version && completed != nil && completed(vol.Name) {
			v.Current = vol.Name
			continue
		}
		v.Others = append(v.Others, vol.Name)
	}
	sort.Strings(v.Others)
	switch {
	case v.Current != "":
		v.State = CacheCurrent
	case len(v.Others) > 0:
		v.State = CacheStale
	default:
		v.State = CacheAbsent
	}
	return v
}

// InstallCreatePlan is the setup container's plan.
type InstallCreatePlan struct {
	// RunID and InstallID label the container like the run's own, so the
	// orphan sweep reaps it with the run.
	RunID     string
	InstallID string
	Image     string
	// EntrypointPrefix is the in-box forward's command up to the
	// installer's argv (`<observer> sandbox-oci-install --gateway <sock>
	// --port <n> --`), which the cmd layer owns.
	EntrypointPrefix []string
	// ObserverBin is the observer binary, bound read-only at its own path.
	ObserverBin string
	// SockDir is the install gateway's host socket directory, bound
	// read-only at GuestSockDir.
	SockDir      string
	GuestSockDir string
	// Volume is the cache volume, mounted read-write at ToolCacheMount.
	Volume  string
	Source  InstallSource
	Version string
	User    UserPlan
	Engine  Engine
	// Runtime is the row's runtime (the agent's own row: "" for oci-runc,
	// "runsc" for oci-runsc).
	Runtime string
	// EngineSocket and ObserverDir are checked against every bind, as for
	// the agent's container.
	EngineSocket string
	ObserverDir  string
}

// InstallNPMCache is the setup container's npm cache, in its private
// /tmp, so it holds only what this install fetched: the guest's integrity
// check (CheckFetchedPackages) reads its _cacache content store.
const InstallNPMCache = "/tmp/observer-install-npm-cache"

// InstallEnv is the setup container's whole environment: the proxy
// variables naming its loopback forward, a throwaway HOME and npm cache in
// its private /tmp, and the update notifier off. Nothing of the host's.
func InstallEnv(port int) []string {
	proxy := "http://127.0.0.1:" + strconv.Itoa(port)
	return []string{
		"HTTP_PROXY=" + proxy, "HTTPS_PROXY=" + proxy, "http_proxy=" + proxy, "https_proxy=" + proxy,
		"NO_PROXY=", "no_proxy=",
		"HOME=/tmp/observer-install-home",
		"npm_config_cache=" + InstallNPMCache,
		"npm_config_update_notifier=false",
		"NO_UPDATE_NOTIFIER=1",
	}
}

// InstallEnvFor is InstallEnv plus the installer kind's own fixed
// variables (installerRow.env), the setup container's whole environment.
func InstallEnvFor(kind string, port int) []string {
	env := InstallEnv(port)
	if r, ok := installerFor(kind); ok {
		env = append(env, r.env...)
	}
	return env
}

// installPidsLimit caps the setup container's tasks.
const installPidsLimit = 512

// installRules validate a setup plan, walked top-down.
var installRules = []specRule{
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
	{"engine socket", func(p CreatePlan) error {
		for _, b := range p.Binds {
			if p.EngineSocket == "" || under(p.EngineSocket, b.Source) {
				return fmt.Errorf("bind %s would expose the engine socket inside the setup container", b.Source)
			}
		}
		return nil
	}},
	{"observer dir", func(p CreatePlan) error {
		for _, b := range p.Binds {
			if p.ObserverDir != "" && under(p.ObserverDir, b.Source) {
				return fmt.Errorf("bind %s would expose the observer directory inside the setup container", b.Source)
			}
		}
		return nil
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
		if strings.HasPrefix(p.User.User, "0:") && !p.User.ContainerRootIsHostUser {
			return fmt.Errorf("the uid row %q would run container root on an engine where root is not the host user", p.User.Row)
		}
		return nil
	}},
}

// BuildInstallCreate validates the setup plan and renders its create body
// and container name (the run's name with an "-install" suffix).
func BuildInstallCreate(p InstallCreatePlan) (string, CreateBody, error) {
	inst, ok := installerFor(p.Source.Kind)
	if !ok {
		return "", CreateBody{}, fmt.Errorf("sandboxoci: install (kind): installer kind %q is not offered", p.Source.Kind)
	}
	if inst.pkgRE == nil || !inst.pkgRE.MatchString(p.Source.Package) {
		return "", CreateBody{}, fmt.Errorf("sandboxoci: install (package): %q is not a package name", p.Source.Package)
	}
	if p.Source.NeedsScripts && (len(p.Source.ScriptSHA256) == 0 || inst.pkgDir == nil) {
		return "", CreateBody{}, fmt.Errorf("sandboxoci: install (scripts): %s: %s needs its own install script, and no reviewed pin covers it", VerdictInstallScriptsRequired, p.Source.Package)
	}
	for _, h := range p.Source.ScriptSHA256 {
		if !sha256HexRE.MatchString(h) {
			return "", CreateBody{}, fmt.Errorf("sandboxoci: install (scripts): %q is not a sha256", h)
		}
	}
	for _, pk := range p.Source.ScriptPackages {
		if why := ValidPackagePin(pk); why != "" || !p.Source.NeedsScripts {
			return "", CreateBody{}, fmt.Errorf("sandboxoci: install (scripts): package pin %+v is not usable (%s)", pk, why)
		}
	}
	n := len(p.EntrypointPrefix)
	if n == 0 || p.EntrypointPrefix[n-1] != "--" {
		return "", CreateBody{}, fmt.Errorf("sandboxoci: install (entrypoint): the guest prefix must end with \"--\"")
	}
	prefix := append([]string(nil), p.EntrypointPrefix[:n-1]...)
	if p.Source.NeedsScripts {
		// The guest runs the installed package's lifecycle scripts after the
		// installer, only those whose file hash is one of these.
		prefix = append(prefix, ScriptRunFlag, inst.pkgDir(ToolCacheMount, p.Source.Package))
		for _, h := range p.Source.ScriptSHA256 {
			prefix = append(prefix, ScriptSHAFlag, h)
		}
		for _, pk := range p.Source.ScriptPackages {
			prefix = append(prefix, PackageIntegrityFlag, pk.Flag())
		}
	}
	prefix = append(prefix, "--")
	if !ValidInstallVersion(p.Version) {
		return "", CreateBody{}, fmt.Errorf("sandboxoci: install (version): %q is not a version an install can be pinned to", p.Version)
	}
	if !strings.HasPrefix(p.Volume, CacheVolumePrefix) || !cleanAbs(p.ObserverBin) || !cleanAbs(p.SockDir) || !cleanAbs(p.GuestSockDir) {
		return "", CreateBody{}, fmt.Errorf("sandboxoci: install (mounts): the volume, observer binary and socket directory must be named")
	}
	cp := CreatePlan{
		RunID: p.RunID, InstallID: p.InstallID, Image: p.Image, User: p.User, Engine: p.Engine,
		EngineSocket: p.EngineSocket, ObserverDir: p.ObserverDir,
		Entrypoint: append(prefix, inst.argv(p.Source.Package, p.Version, ToolCacheMount)...),
		Binds: []Bind{
			{Source: p.ObserverBin, Target: p.ObserverBin, ReadOnly: true},
			{Source: p.SockDir, Target: p.GuestSockDir, ReadOnly: true},
		},
	}
	for _, r := range installRules {
		if err := r.check(cp); err != nil {
			return "", CreateBody{}, fmt.Errorf("sandboxoci: install (%s): %w", r.name, err)
		}
	}
	mounts := []MountSpec{
		{Type: "bind", Source: p.ObserverBin, Target: p.ObserverBin, ReadOnly: true, BindOptions: bindOptionsFor(p.Engine)},
		{Type: "bind", Source: p.SockDir, Target: p.GuestSockDir, ReadOnly: true, BindOptions: bindOptionsFor(p.Engine)},
		{Type: "volume", Source: p.Volume, Target: ToolCacheMount},
	}
	row, _ := tmpfsOwnerFor(p.Engine)
	uid, gid := userIDs(p.User.User)
	body := CreateBody{
		User: p.User.User, AttachStdout: true, AttachStderr: true, Tty: true,
		Env: InstallEnvFor(p.Source.Kind, InstallProxyPort), Entrypoint: cp.Entrypoint, Cmd: []string{},
		Image: strings.TrimSpace(p.Image), WorkingDir: "/tmp",
		Labels: Labels(p.InstallID, p.RunID), StopSignal: "SIGTERM", StopTimeout: defaultStopGrace,
		HostConfig: HostConfig{
			NetworkMode: NetworkNone, CapDrop: []string{CapAll}, CapAdd: []string{}, SecurityOpt: []string{NoNewPrivileges},
			ReadonlyRootfs: true, UsernsMode: p.User.UsernsMode, Runtime: p.Runtime, IpcMode: "private", PidsLimit: installPidsLimit, Devices: []DeviceMapping{},
			LogConfig: LogConfig{Type: logDriverNone}, RestartPolicy: RestartPolicy{Name: "no"}, Mounts: mounts,
			Tmpfs: map[string]string{"/tmp": fmt.Sprintf("rw,nosuid,nodev,size=%d,mode=0700,%s", tmpfsBytes, row.option(uid, gid))},
		},
	}
	return ContainerName(p.InstallID, p.RunID) + "-install", body, nil
}

// InstallReadBackPlan is the setup container's plan in the shape the
// strict read-back (ReadBack) judges, so the setup container is checked
// against what was planned before it starts, like the agent's.
func InstallReadBackPlan(p InstallCreatePlan) CreatePlan {
	return CreatePlan{
		RunID: p.RunID, InstallID: p.InstallID, Image: p.Image, User: p.User, Engine: p.Engine, Runtime: p.Runtime,
		EngineSocket: p.EngineSocket, ObserverDir: p.ObserverDir, ReadonlyRootfs: true, PidsLimit: installPidsLimit,
		WorkDir: "/tmp",
		Binds: []Bind{
			{Source: p.ObserverBin, Target: p.ObserverBin, ReadOnly: true},
			{Source: p.SockDir, Target: p.GuestSockDir, ReadOnly: true},
		},
		Volumes: []VolumeMount{{Name: p.Volume, Target: ToolCacheMount}},
		Tmpfs:   []string{"/tmp"},
	}
}

// InstallLine is the one line a launch shows before it installs: what it
// downloads, from where, into what, and why.
func InstallLine(tool string, src InstallSource, version, volume string, refresh bool) string {
	what := "first start"
	if refresh {
		what = "the host's " + tool + " is now " + version + ", the cache is stale"
	}
	return fmt.Sprintf("%s: the image cannot run this host's %s, so a setup container from the same image installs %s@%s with %s from %s into the cache volume %s (no workspace, no credential, no other host reachable)",
		what, tool, src.Package, version, src.Kind, strings.Join(src.Hosts, ", "), volume)
}

// VolumeMount is a named volume in a create plan (the tool cache, mounted
// read-only in the agent's container).
type VolumeMount struct {
	Name     string
	Target   string
	ReadOnly bool
}
