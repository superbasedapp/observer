package config

// This file holds the config types of the [terminal.sandbox] backend
// sub-tables. TerminalSandboxConfig itself and the hosted sub-table stay in
// config.go, which the OpenShell boundary invariant allows to name that
// backend.

// TerminalSandboxSetupConfig is the [terminal.sandbox.setup] block. Every
// key is local and never distributed by an organization.
type TerminalSandboxSetupConfig struct {
	// AllowElevated lets a setup step that needs your password (sudo on
	// Linux, WSL and macOS; a User Account Control prompt on Windows) run in
	// a visible setup terminal, where you type the password yourself. Only
	// allow-listed shapes are ever elevated: a named package from the host's
	// own repositories, a vendor's documented registration command, a
	// verified local package file and Windows optional features. Default
	// FALSE (decision P-250): while it is off, every such step is shown as a
	// command to run yourself. Observer never stores, reads or pipes a
	// password, and never adds you to a group.
	AllowElevated bool `toml:"allow_elevated"`
}

// TerminalSandboxVMConfig is the [terminal.sandbox.vm] block. Every key is
// local; none widens what the VM may reach (it has no network device in
// any tier). The guest image set is never a path: it comes only from the
// signed content kinds sandbox.rootfs and sandbox.guest_binary.
type TerminalSandboxVMConfig struct {
	// VMM is the virtual machine monitor: "cloud-hypervisor" (the default
	// and only value).
	VMM string `toml:"vmm"`
	// ImageSet is the verified guest image set to boot, named by its
	// version (MAJOR.MINOR.PATCH); "" (the default) is the newest verified
	// set. Never a path.
	ImageSet string `toml:"image_set"`
	// VCPUs is the guest's vCPU count. Default 2, 1 to 64.
	VCPUs int `toml:"vcpus"`
	// MemoryMB is the guest's memory in MiB (shared with virtiofsd, so the
	// host reserves it whole). Default 4096, 512 to 262144.
	MemoryMB int `toml:"memory_mb"`
	// InstallCache lets a run whose image set holds no agent tool install it
	// at first start into a per-image-set cache disk (SBX-P3C's install
	// sources, host allow-list, consent and version pin). Default false: a
	// run with no tool in the image and no cache is refused
	// tool_unavailable_in_image.
	InstallCache bool `toml:"install_cache"`
	// WorkspaceDelivery is how a workspace copy reaches the VM:
	// "virtiofs" (the default: shared by a virtiofsd) or "disk_image" (the
	// copy written into an ext4 image with mkfs.ext4 -d, no root, and read
	// back with debugfs for the scanned return; copies only, never live or
	// worktree).
	WorkspaceDelivery string `toml:"workspace_delivery"`
	// CloudHypervisorPath and VirtiofsdPath are optional absolute paths to
	// the two programs, owner-checked at the probe ("" resolves each on
	// PATH with Observer's own shims excluded).
	CloudHypervisorPath string `toml:"cloud_hypervisor_path"`
	VirtiofsdPath       string `toml:"virtiofsd_path"`
}

// TerminalSandboxLandlockConfig is the [terminal.sandbox.landlock] block.
type TerminalSandboxLandlockConfig struct {
	// MinABI is the lowest Landlock ABI a process_lite launch accepts.
	// Default 9 (Linux 7.1+), which is also the floor: below ABI 9 the
	// daemon's relay endpoint and the attach socket would be reachable from
	// the box, so a lower value is refused. Raising it is stricter.
	MinABI int `toml:"min_abi"`
}

// TerminalSandboxSeatbeltConfig is the [terminal.sandbox.seatbelt] block.
type TerminalSandboxSeatbeltConfig struct {
	// AllowKeychain lets the sandboxed agent reach the Keychain's mach
	// services (com.apple.SecurityServer, com.apple.securityd.xpc), which a
	// Keychain-backed login (Claude Code, Codex on macOS) needs. It widens
	// what the box can ask the Keychain for, so it defaults to FALSE.
	AllowKeychain bool `toml:"allow_keychain"`
	// Driver is the Seatbelt driver (sandbox plan v2 section 10.1's
	// seatbelt_driver, lane SBX-UPD): "sandbox-exec" (the default, also what
	// an empty value means) or "mxc-exec-mac", Microsoft's declared
	// fallback, which the probe refuses fallback_driver_unavailable until a
	// documented binary can be pinned and a Mac run proves it (MAC-10).
	Driver string `toml:"driver"`
}

// TerminalSandboxAppleContainerConfig is the [terminal.sandbox.apple_container]
// block.
type TerminalSandboxAppleContainerConfig struct {
	// Image is the run's image, pinned by digest (name@sha256:<64 hex>): a
	// linux/arm64 image that holds the agent CLI and a linux/arm64 observer
	// (the host's macOS binary cannot run in the container). Empty (the
	// default) leaves the driver unavailable.
	Image string `toml:"image"`
	// MemoryMiB is the container's memory (--memory). Default 4096.
	MemoryMiB int `toml:"memory_mib"`
	// CPUs is the container's CPU count (--cpus). Default 4.
	CPUs int `toml:"cpus"`
}

// TerminalSandboxMXCConfig is the [terminal.sandbox.mxc] block. Every key
// is local; none widens what the box may reach. The MXC files themselves
// are not configurable: the driver only ever uses the copies bundled
// beside the observer binary and checked against the hashes compiled into
// it.
type TerminalSandboxMXCConfig struct {
	// StopGraceSeconds is how long a stopping run gets after Ctrl-Break
	// before its container is closed (MXC kills what is left). Default 5.
	StopGraceSeconds int `toml:"stop_grace_seconds"`
	// ProbeTimeoutSeconds bounds the probe helper (the library load, MXC's
	// request probe and its create-and-close check). Default 30, at least
	// 5: the first run of a freshly updated binary is scanned by Defender
	// and can take seconds (sandbox plan revision 6.1, JSP-2).
	ProbeTimeoutSeconds int `toml:"probe_timeout_seconds"`
}

// TerminalSandboxOCIConfig is the [terminal.sandbox.oci] block. Every key
// is local; the authority-expanding ones (AllowRootful,
// AllowDevcontainerImage) default to false.
type TerminalSandboxOCIConfig struct {
	// AllowRootful lets the driver use a ROOTFUL engine socket, which is
	// root-equivalent (anyone who can reach it can become root). Default
	// FALSE: rootless Docker or Podman is preferred (D-746 Q29). Even when
	// true, a rootful engine never runs container root: the container runs
	// as your uid and gid.
	AllowRootful bool `toml:"allow_rootful"`
	// Socket is the engine socket: an absolute path or unix:///path. Empty
	// (the default) uses $DOCKER_HOST, then $CONTAINER_HOST, then the
	// rootless sockets under $XDG_RUNTIME_DIR, then /run/docker.sock and
	// /run/podman/podman.sock. A TCP or SSH endpoint is never used.
	Socket string `toml:"socket"`
	// Image is the run's image, pinned by digest (name@sha256:<64 hex>). A
	// tag is refused. Empty (the default) leaves the driver unavailable:
	// Observer's own default image is not published yet. Once a signed
	// sandbox.image manifest is installed, empty uses Observer's verified
	// default image instead (plan 12.3). An org may pin this key, to an image
	// pinned by digest only.
	Image string `toml:"image"`
	// PodmanUserns is the rootless Podman user namespace: "keep-id" (the
	// default, the container runs as your uid) or "default" (container root
	// is you). Both leave files you own in the workspace.
	PodmanUserns string `toml:"podman_userns"`
	// StopGraceSeconds is how long a stopping run gets before the engine
	// kills it. Default 10.
	StopGraceSeconds int `toml:"stop_grace_seconds"`
	// AllowDevcontainerImage lets a repository's .devcontainer image (by
	// digest only) be used for that repository after you consent to it once
	// per repository and digest; every host-executing or privilege field of
	// devcontainer.json is ignored. Default FALSE.
	AllowDevcontainerImage bool `toml:"allow_devcontainer_image"`
	// InstallCache lets a launch whose image cannot run this host's copy of
	// the tool install the tool first, into a per-image cache volume: a
	// short setup container from the same image, with no workspace, no
	// credential and egress only to the tool's documented install hosts,
	// runs the vendor's npm install pinned to the host's version, after the
	// launch says what it downloads and from where and you answer yes. A
	// tool the image holds itself then runs on a projected tool state, never
	// your real one. Default FALSE: nothing creates a volume or runs an
	// install, and such a launch is refused as before.
	InstallCache bool `toml:"install_cache"`
	// InstallScripts says whether the first-start install may run a tool
	// package's own install script (lane LEFT-SBX, operator ruling P-136):
	// "none" never runs one, "pinned" (the default; empty reads as pinned)
	// runs a tool's scripts only when each script file matches a reviewed
	// pin for that package version (Observer's own, one you added, or your
	// organization's), under the same host allow-list as the download. A
	// tool that needs its script is refused naming why otherwise. Only read
	// while install_cache is on. An org may pin it to "none".
	InstallScripts string `toml:"install_scripts"`
	// InstallScriptsTools limits the tools whose pinned scripts may run to
	// these install-source tools (the dashboard picks them from the
	// catalog). Empty (the default) is every tool of the catalog. An org may
	// narrow it.
	InstallScriptsTools []string `toml:"install_scripts_tools"`
	// InstallScriptPins are pins you added: a tool, the package version and
	// the sha256 of its install script file. The dashboard adds one only
	// after you confirm it.
	InstallScriptPins []TerminalSandboxOCIScriptPin `toml:"install_script_pins"`
	// InstallVersions picks the version the first-start install installs,
	// per tool ({"claude-code" = "2.1.310"}). A tool with no entry installs
	// the host's own installed version, as before; with neither, the launch
	// is refused install_version_unknown. The dashboard offers the vendor's
	// published versions.
	InstallVersions map[string]string `toml:"install_versions"`
	// OrgInstallScriptPins are the organization's signed install-script pins
	// from the managed sandbox body in force (never read from the file;
	// cmd/observer's managed compose fills it on a managed node holding
	// enforce.sandbox).
	OrgInstallScriptPins []TerminalSandboxOCIScriptPin `toml:"-" json:"-"`
}

// TerminalSandboxOCIScriptPin is one user-added install script pin.
type TerminalSandboxOCIScriptPin struct {
	// Tool is the registry tool id.
	Tool string `toml:"tool" json:"tool"`
	// Version is the package version the pin covers.
	Version string `toml:"version" json:"version"`
	// SHA256 is the script file's sha256, lowercase hex.
	SHA256 string `toml:"sha256" json:"sha256"`
	// Added is when the pin was added (YYYY-MM-DD), shown with it.
	Added string `toml:"added" json:"added,omitempty"`
	// Packages pin what the install fetches by the registry's integrity
	// value (sha512): the package itself and every platform package its
	// script may place (R-014, ruling P-142). A tool whose install script
	// fetches more packages (opencode, kilo) runs its script under this pin
	// only when they are set; the setup container checks every installed
	// package against them before any script runs, as for Observer's own
	// pins.
	Packages []TerminalSandboxOCIPackagePin `toml:"packages" json:"packages,omitempty"`
}

// TerminalSandboxOCIPackagePin is one fetched npm artifact pinned by its
// registry integrity value.
type TerminalSandboxOCIPackagePin struct {
	// Name is the npm package name (scoped names allowed).
	Name string `toml:"name" json:"name"`
	// Version is the package version.
	Version string `toml:"version" json:"version"`
	// Integrity is the registry's sha512 integrity value
	// ("sha512-<base64>"), as the package's version document lists it.
	Integrity string `toml:"integrity" json:"integrity"`
}

// sandboxIsolationClasses is the closed min_isolation vocabulary, weakest
// first. It mirrors internal/sandboxvocab's class ladder above "none"
// (config stays a leaf; the mirror is pinned by a test in
// cmd/observer).
var sandboxIsolationClasses = []string{"process", "container", "userspace_kernel", "hw_vm"}

// SandboxIsolationClasses returns the closed [terminal.sandbox].min_isolation
// values, weakest first.
func SandboxIsolationClasses() []string { return append([]string(nil), sandboxIsolationClasses...) }
