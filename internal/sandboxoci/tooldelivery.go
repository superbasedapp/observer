package sandboxoci

import (
	"fmt"
	"path"
	"strings"
)

// tooldelivery.go decides how the agent's CLI reaches the container
// (sandbox plan v2 section 5.4, D-751 Q38 "Never bundle"): Observer's image
// carries no agent CLI. The host's own toolchain is bound read-only when
// the image can run it (the host binary's ELF loader is present in the
// image, or the binary is static). Otherwise, with
// [terminal.sandbox.oci].install_cache off, the run is refused with
// tool_unavailable_in_image as before (the image's own copy runs only on
// the projected oci-runsc row). With it on (lane SBX-P3C): an image's own
// copy of the tool runs on a projected tool state on any row, because its
// version is never proven equal to the host's and it must never see the
// real tool state (Opus M19); and a tool the image cannot run is installed
// first into a per-image cache volume (install.go), pinned to the host's
// version, so it is proven and binds the real state on a same-kernel row.
// That install is refused install_source_unknown, install_version_unknown
// or install_runtime_missing when its source, version or runtime is not
// there.
//
// Projected state (section 5.4, G27, lane SBX-P3B) is decided here too: the
// choice keys on the row's CrossesKernel, never on "a container". A
// same-kernel row binds the real tool state at its own path; a row that
// crosses a kernel (gVisor serves the bind through its own gofer, with its
// own lock semantics) gets a per-run projected directory for each state
// path instead, under the run's managed workspaces tree, so the box never
// writes the real ~/.claude and a tool's SQLite store written in the box is
// never read live by the host (the db-copy one-shot makes a consistent copy
// inside the guest, SBX-BE-10).

// Delivery is how the tool reaches the box.
type Delivery string

// The Delivery values.
const (
	// DeliveryHostBind: the host's toolchain dirs are bound read-only.
	DeliveryHostBind Delivery = "host_bind"
	// DeliveryImageInstalled: the image already has the tool.
	DeliveryImageInstalled Delivery = "image_installed"
	// DeliveryInstallCache: a first-start install into a per-image cache.
	DeliveryInstallCache Delivery = "install_cache"
)

// VerdictToolUnavailable is the selection table's
// tool_unavailable_in_image (S11).
const VerdictToolUnavailable = "tool_unavailable_in_image"

// ToolFacts are what the driver found about one launch's tool.
type ToolFacts struct {
	// HostBinary is the resolved host binary (or the interpreter a script
	// names); empty when the tool did not resolve on the host.
	HostBinary string
	// Interp is the binary's ELF program interpreter (its dynamic loader,
	// "/lib64/ld-linux-x86-64.so.2"); empty for a static binary.
	Interp string
	// ImageHasInterp: the image holds Interp (read through the engine's
	// path stat of a created, never-started container).
	ImageHasInterp bool
	// ImageHasTool: the image holds a binary of the tool's own name.
	ImageHasTool bool
	// StateProjected: the run's tool state is a per-run projection, never
	// the real state (a row that crosses a kernel), so a CLI of another
	// version than the host's may run on it.
	StateProjected bool
	// InstallCache is [terminal.sandbox.oci].install_cache (lane SBX-P3C).
	// Off, the table is exactly what it was before the install step: the
	// three refusals below keep their text. On, an image's own copy of the
	// tool runs on a projected state on any row (Opus M19: its version is
	// never proven equal to the host's), and a tool the image cannot run is
	// installed into the per-image cache when the rows after it allow.
	InstallCache bool
	// InstallSourceKnown: the registry's side table grounds an in-box
	// install source for the tool.
	InstallSourceKnown bool
	// InstallVersion is the host's installed version of the tool, the one
	// the install is pinned to ("" when it could not be read).
	InstallVersion string
	// ImageHasRuntime: the image holds the installer's runtime (npm and node
	// for the npm installer), probed like the tool (S11).
	ImageHasRuntime bool
	// InstallNeedsScripts: the install source declares that its package
	// needs its own install script (refused, VerdictInstallScriptsRequired).
	InstallNeedsScripts bool
}

// deliveryRow is one row of the decision table, walked top-down.
type deliveryRow struct {
	name  string
	match func(f ToolFacts) bool
	pick  Delivery
	// refuse, when set, is the reason the row refuses.
	refuse string
	// code is the refusal's verdict code ("" for tool_unavailable_in_image).
	code string
}

// deliveryTable is the decision table. Rows marked "cache off" match only
// while InstallCache is off, so with it off the table answers exactly as it
// did before the install step (TestToolDeliveryCacheOffUnchanged).
var deliveryTable = []deliveryRow{
	{
		name: "no host tool", match: func(f ToolFacts) bool { return f.HostBinary == "" && !f.ImageHasTool && !f.InstallCache },
		refuse: "the tool is not installed on this host and the image does not have it; install it on the host (Observer never bundles an agent CLI)",
	},
	{name: "static host binary", match: func(f ToolFacts) bool { return f.HostBinary != "" && f.Interp == "" }, pick: DeliveryHostBind},
	{name: "image runs the host binary", match: func(f ToolFacts) bool { return f.HostBinary != "" && f.ImageHasInterp }, pick: DeliveryHostBind},
	{name: "image has the tool on projected state", match: func(f ToolFacts) bool { return f.ImageHasTool && (f.StateProjected || f.InstallCache) }, pick: DeliveryImageInstalled},
	{
		name: "image has the tool", match: func(f ToolFacts) bool { return f.ImageHasTool },
		refuse: "the image has its own copy of the tool, which may be a different version from the host's; it never runs on the real tool state, only on a projected one (the oci-runsc row), so it is not used here",
	},
	{
		name: "image lacks the loader", match: func(f ToolFacts) bool { return !f.InstallCache },
		refuse: "the image cannot run the host's tool: its loader %s is not in the image; use an image with the same C library as this host (glibc for most distributions), or wait for the first-start install (needs the egress domain allow-list, G23)",
	},
	{
		name: "install source unknown", match: func(f ToolFacts) bool { return !f.InstallSourceKnown }, code: VerdictInstallSourceUnknown,
		refuse: "the image cannot run the host's tool and Observer has no grounded in-box install source for it (only vendor-documented npm installs are offered); use an image with the host's C library or one that holds the tool",
	},
	{
		name: "install scripts required", match: func(f ToolFacts) bool { return f.InstallNeedsScripts }, code: VerdictInstallScriptsRequired,
		refuse: "the image cannot run the host's tool, and the tool's package needs its own install script; the first-start install runs npm with --ignore-scripts under its host allow-list (a script could open any connection the list allows and change what the agent later runs), so it is not installed; use an image with the host's C library or one that holds the tool",
	},
	{
		name: "install version unknown", match: func(f ToolFacts) bool { return !ValidInstallVersion(f.InstallVersion) }, code: VerdictInstallVersionUnknown,
		refuse: "the first-start install pins the tool to the host's installed version, and no version of it could be read on this host; install the tool on the host first",
	},
	{
		name: "install runtime missing", match: func(f ToolFacts) bool { return !f.ImageHasRuntime }, code: VerdictInstallRuntimeMissing,
		refuse: "the image lacks the installer's runtime (node and npm for an npm install), so the first-start install cannot run in it; use an image that holds node and npm",
	},
	{name: "install cache", match: func(ToolFacts) bool { return true }, pick: DeliveryInstallCache},
}

// ProjectsState reports whether a run with delivery d gets a projected tool
// state instead of the real one: always on a row that crosses a kernel
// (StateModeFor), and for an image's own copy of the tool on any row (its
// version is never proven equal to the host's, Opus M19). A cache install
// pinned to the host's own version is proven and binds the real state on a
// same-kernel row.
func ProjectsState(d Delivery, crossesKernel bool) bool {
	return StateModeFor(crossesKernel) == StateProject || d == DeliveryImageInstalled
}

// PlanToolDelivery picks the delivery, or refuses with
// tool_unavailable_in_image.
func PlanToolDelivery(f ToolFacts) (Delivery, Verdict) {
	for _, r := range deliveryTable {
		if !r.match(f) {
			continue
		}
		if r.refuse != "" {
			reason := r.refuse
			if r.name == "image lacks the loader" {
				reason = fmt.Sprintf(r.refuse, f.Interp)
			}
			code := r.code
			if code == "" {
				code = VerdictToolUnavailable
			}
			return "", refuse(code, reason)
		}
		return r.pick, pass()
	}
	return "", refuse(VerdictToolUnavailable, "no delivery row matched")
}

// ImageToolPaths are where the probe looks for a tool of name inside an
// image.
func ImageToolPaths(name string) []string {
	name = path.Base(path.Clean("/" + name))
	if name == "/" || name == "." {
		return nil
	}
	return []string{"/usr/local/bin/" + name, "/usr/bin/" + name, "/bin/" + name}
}

// The started path check (the fallback of the tool-delivery path stat for
// an engine that cannot stat a created container): Observer's own binary,
// bound read-only into a probe container from the image with no network,
// no capabilities, no new privileges and a read-only root, stats each path
// and exits PathCheckBase plus one bit per path found. Nothing of the
// image runs; the image's files are only read.
const (
	// PathCheckBase is the exit code when no path was found.
	PathCheckBase = 64
	// PathCheckMax is the most paths one check answers (the bits stay
	// below 128, which a shell reports for a signal).
	PathCheckMax = 6
)

// PathCheckExit encodes which paths were found.
func PathCheckExit(found []bool) int {
	code := PathCheckBase
	for i, ok := range found {
		if ok && i < PathCheckMax {
			code |= 1 << i
		}
	}
	return code
}

// DecodePathCheckExit reads a started check's exit code for n paths. Any
// code outside the check's range (the binary could not run in the image,
// was killed, or the engine reported a failure) is an error, never an
// answer.
func DecodePathCheckExit(code, n int) ([]bool, error) {
	if n < 1 || n > PathCheckMax {
		return nil, fmt.Errorf("sandboxoci: the started path check takes 1 to %d paths, not %d", PathCheckMax, n)
	}
	if code < PathCheckBase || code >= PathCheckBase+(1<<n) {
		return nil, fmt.Errorf("sandboxoci: the started path check did not run (exit status %d)", code)
	}
	out := make([]bool, n)
	for i := range out {
		out[i] = code&(1<<i) != 0
	}
	return out, nil
}

// StateMode is how a row delivers the tool's own state (section 5.4).
type StateMode string

// The StateMode values.
const (
	// StateBind: the real state is bound at its own path, with the
	// protected-state overlays (a same-kernel row).
	StateBind StateMode = "bind"
	// StateProject: a per-run projected directory stands in for each state
	// path (a row that crosses a kernel).
	StateProject StateMode = "project_dir"
)

// StateModeFor is the one rule: projection keys on CrossesKernel.
func StateModeFor(crossesKernel bool) StateMode {
	if crossesKernel {
		return StateProject
	}
	return StateBind
}

// ProjectedDir is one projected state directory: Host is the per-run
// directory on the host, Target the tool's own path in the box.
type ProjectedDir struct {
	Host   string
	Target string
}

// ProjectionLeaf is the per-run projection root's suffix under the managed
// workspaces tree (<managed>/<run><ProjectionLeaf>), outside the observer
// directory's protected files and beside the run's own workspace.
const ProjectionLeaf = ".state"

// DBCopyDirName is the directory inside each projected state directory
// where the guest's db-copy one-shot writes its consistent copies (the
// host reads them no-follow and size-capped after the run, SBX-BE-10).
const DBCopyDirName = ".observer-dbcopy"

// PlanProjection maps the tool's writable state paths (relative to home)
// onto per-run directories under root: <root>/<n> for the n-th path, so
// no path from the tool's spec is ever spelled on the host side. Each
// relative path must be clean, relative and stay inside home.
func PlanProjection(root, home string, stateRW []string) ([]ProjectedDir, error) {
	if !cleanAbs(root) || !cleanAbs(home) {
		return nil, fmt.Errorf("sandboxoci: projection root %q and home %q must be clean absolute paths", root, home)
	}
	var out []ProjectedDir
	seen := map[string]bool{}
	for i, rel := range stateRW {
		c := path.Clean(rel)
		if rel == "" || path.IsAbs(rel) || c == "." || c == ".." || len(c) > 2 && c[:3] == "../" {
			return nil, fmt.Errorf("sandboxoci: tool state path %q is not a clean relative path under home", rel)
		}
		target := path.Join(home, c)
		if seen[target] {
			continue
		}
		seen[target] = true
		out = append(out, ProjectedDir{Host: path.Join(root, fmt.Sprintf("%d", i)), Target: target})
	}
	return out, nil
}

// SeedCopy is one non-secret file copied from the real tool state into a
// projected directory at launch (G27): From is the real file under the
// home, To its place in the projection on the host.
type SeedCopy struct {
	From string
	To   string
}

// TranscriptRoot is one transcript subtree of a projection: Host is the
// directory on the host the watcher reads, Box the path the tool writes it
// at in the box (the adapter judges a file at its box path).
type TranscriptRoot struct {
	Host string
	Box  string
}

// PlanSeeds maps a tool's seed row (HOME-relative files and transcript
// subtrees, internal/integration's projection seed table) onto the run's
// projected directories: each path must be clean, relative and lie strictly
// inside one projected state path, and is spelled on the host side under
// that directory's per-run root only.
func PlanSeeds(proj []ProjectedDir, home string, files, transcripts []string) ([]SeedCopy, []TranscriptRoot, error) {
	place := func(rel string) (string, string, error) {
		c := path.Clean(rel)
		if rel == "" || path.IsAbs(rel) || c != rel || c == ".." || strings.HasPrefix(c, "../") {
			return "", "", fmt.Errorf("sandboxoci: seed path %q is not a clean relative path under home", rel)
		}
		abs := path.Join(home, c)
		for _, pd := range proj {
			if strings.HasPrefix(abs, pd.Target+"/") {
				return abs, path.Join(pd.Host, strings.TrimPrefix(abs, pd.Target+"/")), nil
			}
		}
		return "", "", fmt.Errorf("sandboxoci: seed path %q lies in no projected state directory", rel)
	}
	var copies []SeedCopy
	for _, f := range files {
		from, to, err := place(f)
		if err != nil {
			return nil, nil, err
		}
		copies = append(copies, SeedCopy{From: from, To: to})
	}
	var roots []TranscriptRoot
	for _, tr := range transcripts {
		box, host, err := place(tr)
		if err != nil {
			return nil, nil, err
		}
		roots = append(roots, TranscriptRoot{Host: host, Box: box})
	}
	return copies, roots, nil
}
