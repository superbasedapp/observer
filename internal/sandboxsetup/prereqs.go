package sandboxsetup

import (
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
)

// The host family keys (Remedy.Family, PlanInput.Family).
const (
	FamilyDebian  = "debian"
	FamilyFedora  = "fedora"
	FamilyArch    = "arch"
	FamilySUSE    = "suse"
	FamilyAlpine  = "alpine"
	FamilyMacOS   = "macos"
	FamilyWindows = "windows"
)

// familyByPM maps a toolinstall package-manager name to its family key, and
// back (pmForFamily): the one place the two vocabularies meet.
var familyByPM = map[string]string{
	"apt":    FamilyDebian,
	"dnf":    FamilyFedora,
	"pacman": FamilyArch,
	"zypper": FamilySUSE,
	"apk":    FamilyAlpine,
	"brew":   FamilyMacOS,
}

// FamilyFor is the host family key for a host: macOS and Windows by goos,
// Linux by the package manager toolinstall.PackageManagerFor chose from
// os-release; "" for an unknown family (every remedy with a Family then
// misses, and the any-family guide applies).
func FamilyFor(goos string, pm toolinstall.PackageManager) string {
	switch goos {
	case "darwin":
		return FamilyMacOS
	case "windows":
		return FamilyWindows
	}
	return familyByPM[pm.Name]
}

// pmForFamily is the package manager of a family key (ok false for a family
// with none, such as windows).
func pmForFamily(family string) (toolinstall.PackageManager, bool) {
	for name, f := range familyByPM {
		if f == family {
			return toolinstall.PackageManagerByName(name)
		}
	}
	return toolinstall.PackageManager{}, false
}

// The generic prerequisite ids the planner adds to every plan (never listed
// in a registry row's Setup).
const (
	PrereqComponent = "component"
	PrereqEnable    = "enable"
)

// Docs anchors.
const (
	docsBwrap    = "sandboxed-terminals.md#enabling-it"
	docsOCI      = "sandboxed-terminals.md#which-engine-which-socket"
	docsOCIImage = "sandboxed-terminals.md#the-default-image-on-this-machine-pull-and-revoked-images"
	docsRunsc    = "sandboxed-terminals.md#gvisor-oci-runsc-beta"
	docsLandlock = "sandboxed-terminals.md#landlock-only-process_lite-beta"
	docsVM       = "sandboxed-terminals.md#microvm-sandboxes-cloud-hypervisor-beta"
	docsVMProbe  = "sandboxed-terminals.md#the-probe"
	docsVMImages = "sandboxed-terminals.md#image-set-and-import"
	docsMXC      = "sandboxed-terminals.md#native-windows-mxc-processcontainer-mxc-process-beta"
	docsMXCFiles = "sandboxed-terminals.md#the-mxc-files-as-a-signed-kind"
	docsMac      = "sandboxed-terminals.md#macos-sandboxes-beta-seatbelt-and-apple-container"
	docsHosted   = "sandboxed-terminals.md#hosted-sandboxes-beta-e2b-modal-and-vercel-sandbox"
	// docsHostedCustody is where a hosted run's model key custody is told.
	docsHostedCustody = "sandbox-credential-custody.md#the-four-custody-modes"
	docsOpenShell     = "sandbox-openshell.md#what-you-need"
	docsOpenShellGw   = "sandbox-openshell.md#managed-gateway-mode-the-default"
	docsOrgShell      = "sandbox-openshell-org.md#turning-it-on"
	docsComponents    = "sandboxed-terminals.md#the-isolation-engine-component-isolation"
)

// Host sets.
var (
	hostsLinux   = []sandboxbackend.HostKind{sandboxbackend.HostLinux, sandboxbackend.HostWSL2}
	hostsNative  = []sandboxbackend.HostKind{sandboxbackend.HostLinux}
	hostsWSL2    = []sandboxbackend.HostKind{sandboxbackend.HostWSL2}
	hostsMac     = []sandboxbackend.HostKind{sandboxbackend.HostMacOS}
	hostsWindows = []sandboxbackend.HostKind{sandboxbackend.HostWindows}
)

// The package names below are listed ONLY where they were confirmed in the
// distribution's own package index, with the source beside each. On
// 2026-11-06 this session could reach packages.ubuntu.com only (the
// Debian, Fedora, Arch, openSUSE and Alpine indexes were outside its
// network), so every other family reads as a guide step with the docs
// anchor and no package: never a guessed name. A later lane that confirms a
// name adds its row above the guide row, with its source.

// prereqTable is THE prerequisite table, one row per prerequisite in plan
// section 2.2. Detect.Verdicts is filled from the verdict map (verdicts.go)
// when the index is built, so each verdict is written down once.
var prereqTable = []Prereq{
	{
		ID: "bwrap", Kind: KindProgram, Label: "Bubblewrap (bwrap) 0.4.0 or newer",
		Detect: Detect{Programs: []string{"bwrap"}, MinVersion: "0.4.0"},
		Remedies: []Remedy{
			// packages.ubuntu.com/noble/bubblewrap (0.9.0, /usr/bin/bwrap).
			{Hosts: hostsLinux, Family: FamilyDebian, Class: ClassElevated, Channel: ChPM, Package: "bubblewrap", Docs: docsBwrap},
			{Hosts: hostsLinux, Class: ClassGuide, Channel: ChNone, Display: "Install the bubblewrap package (it provides bwrap) with your distribution's package manager, then check again.", Docs: docsBwrap},
		},
		Shared: true,
	},
	{
		ID: "userns", Kind: KindKernel, Label: "Unprivileged user and network namespaces",
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassNever, Channel: ChNone, Display: "This machine refuses unprivileged user namespaces (for example Ubuntu's kernel.apparmor_restrict_unprivileged_userns setting, or a container host). That is a kernel security setting Observer never changes; the docs explain the choices.", Docs: docsBwrap},
		},
	},
	{
		ID: "landlock-abi", Kind: KindKernel, Label: "Landlock in the running kernel, at the ABI the backend needs",
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassNever, Channel: ChNone, Display: "The running kernel has no Landlock, or an older Landlock ABI than this backend needs (the check names the ABI it found). Upgrading the kernel is yours to do; Observer never changes it.", Docs: docsLandlock},
		},
		Shared: true,
	},
	{
		ID: "kvm-device", Kind: KindKernel, Label: "A usable /dev/kvm (hardware virtualization)",
		Remedies: []Remedy{
			{Hosts: hostsWSL2, Class: ClassNever, Channel: ChNone, Display: "WSL2 needs nested virtualization turned on in your Windows .wslconfig (nestedVirtualization=true) and a restart of WSL. Observer never writes that Windows-side file.", Docs: docsVMProbe, After: AfterReboot},
			{Hosts: hostsNative, Class: ClassNever, Channel: ChNone, Display: "Turn on hardware virtualization (Intel VT-x or AMD-V) in the machine's firmware, or nested virtualization when this is a VM. Observer never touches firmware or the hypervisor.", Docs: docsVMProbe, After: AfterReboot},
		},
	},
	{
		ID: "kvm-group", Kind: KindGroup, Label: "Your user can open /dev/kvm",
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassNever, Channel: ChNone, Display: "Your user must be able to open /dev/kvm, usually through the kvm group. Group membership is yours to change: run sudo usermod -aG kvm $USER yourself, then sign out and in again.", Docs: docsVMProbe, After: AfterRelogin},
		},
	},
	{
		ID: "cloud-hypervisor", Kind: KindProgram, Label: "Cloud Hypervisor",
		Detect: Detect{Programs: []string{"cloud-hypervisor"}, DriverBinary: true, PathKey: "terminal.sandbox.vm.cloud_hypervisor_path"},
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassAuto, Channel: ChPinned, Package: "cloud-hypervisor", Display: "Download Cloud Hypervisor's pinned static release binary into Observer's own tools directory and point cloud_hypervisor_path at it.", Docs: docsVM},
		},
	},
	{
		// The Debian and Ubuntu package installs /usr/libexec/virtiofsd, off
		// PATH: the caller resolves it there too (the vm driver's own
		// ConfinedVirtiofsd), or reads [terminal.sandbox.vm].virtiofsd_path.
		ID: "virtiofsd", Kind: KindProgram, Label: "virtiofsd",
		Detect: Detect{Programs: []string{"virtiofsd"}, PathKey: "terminal.sandbox.vm.virtiofsd_path"},
		Remedies: []Remedy{
			// packages.ubuntu.com/noble/virtiofsd (1.10.0, /usr/libexec/virtiofsd).
			{Hosts: hostsLinux, Family: FamilyDebian, Class: ClassElevated, Channel: ChPM, Package: "virtiofsd", Docs: docsVM},
			{Hosts: hostsLinux, Class: ClassGuide, Channel: ChNone, Display: "Install virtiofsd with your distribution's package manager, then check again.", Docs: docsVM},
		},
	},
	{
		// mkfs.ext4 and debugfs live in /usr/sbin, which a user's PATH may
		// not hold: the caller resolves sbin too.
		ID: "e2fsprogs", Kind: KindProgram, Label: "e2fsprogs (mkfs.ext4 and debugfs)",
		Detect: Detect{Programs: []string{"mkfs.ext4", "debugfs"}},
		Remedies: []Remedy{
			// packages.ubuntu.com/noble/e2fsprogs (1.47.0, /usr/sbin/mkfs.ext4, /usr/sbin/debugfs).
			{Hosts: hostsLinux, Family: FamilyDebian, Class: ClassElevated, Channel: ChPM, Package: "e2fsprogs", Docs: docsVMImages},
			{Hosts: hostsLinux, Class: ClassGuide, Channel: ChNone, Display: "Install e2fsprogs (it provides mkfs.ext4 and debugfs) with your distribution's package manager, then check again.", Docs: docsVMImages},
		},
	},
	{
		ID: "vm-image-set", Kind: KindContent, Label: "The signed guest image set",
		Detect: Detect{Content: []string{"sandbox.rootfs", "sandbox.guest_binary"}},
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassAuto, Channel: ChContent, Package: "sandbox.rootfs,sandbox.guest_binary", Display: "Import the signed guest image set (a root filesystem and the guest helper) from a directory, or fetch it once it is published.", Docs: docsVMImages},
		},
	},
	{
		ID: "container-engine", Kind: KindProgram, Label: "A container engine in this Linux (Podman or Docker Engine, not Docker Desktop)",
		Detect: Detect{Programs: []string{"podman|docker"}},
		Remedies: []Remedy{
			// packages.ubuntu.com/noble/podman (4.9.3). Rootless Podman needs no
			// group membership, so it is the engine offered.
			{Hosts: hostsLinux, Family: FamilyDebian, Class: ClassElevated, Channel: ChPM, Package: "podman", Docs: docsOCI, Disclosure: "Podman runs containers as your own user (rootless); nothing else on this machine changes."},
			{Hosts: hostsLinux, Class: ClassGuide, Channel: ChNone, Display: "Install Podman or Docker Engine inside this Linux with your distribution's package manager (Docker Desktop's VM is not used), then check again.", Docs: docsOCI},
		},
	},
	{
		// A rootless engine listens only once its socket is started; nothing
		// else on the machine starts Podman's.
		ID: "engine-socket", Kind: KindService, Label: "The container engine's socket (Podman's started for your user)",
		Detect: Detect{EngineSocket: true},
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassTerminal, Channel: ChCommand, Argv: []string{"systemctl", "--user", "enable", "--now", "podman.socket"}, Display: "systemctl --user enable --now podman.socket", Docs: docsOCI, Disclosure: "This starts Podman's socket for your user now and at each login (a systemd user unit). It runs as you and needs no password."},
		},
	},
	{
		ID: "docker-engine", Kind: KindProgram, Label: "Docker Engine in this Linux (not Docker Desktop)",
		Detect: Detect{Programs: []string{"docker"}},
		Remedies: []Remedy{
			// packages.ubuntu.com/noble/docker.io (29.1.3).
			{Hosts: hostsLinux, Family: FamilyDebian, Class: ClassElevated, Channel: ChPM, Package: "docker.io", Docs: docsOCI, Disclosure: "Docker Engine runs a root daemon on this machine; anyone who can reach its socket is root-equivalent."},
			{Hosts: hostsLinux, Class: ClassGuide, Channel: ChNone, Display: "Install Docker Engine inside this Linux with your distribution's package manager or Docker's own instructions (Docker Desktop's VM is not used), then check again.", Docs: docsOCI},
		},
		Shared: true,
	},
	{
		ID: "docker-group", Kind: KindGroup, Label: "Your user can reach Docker's socket",
		Detect: Detect{DockerSocketAccess: true},
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassNever, Channel: ChNone, Display: "Your user needs access to Docker's socket. Being in the docker group is root-equivalent, so Observer never adds you: if you accept that, run sudo usermod -aG docker $USER yourself, then sign out and in again.", Docs: docsOCI, After: AfterRelogin, Disclosure: "Membership of the docker group is equivalent to root on this machine."},
		},
		Shared: true,
	},
	{
		ID: "oci-allow-rootful", Kind: KindConfig, Label: "Rootful engine use allowed ([terminal.sandbox.oci].allow_rootful)",
		Detect: Detect{ConfigKey: "terminal.sandbox.oci.allow_rootful"},
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassAuto, Channel: ChConfig, Package: "terminal.sandbox.oci.allow_rootful", Display: "Allow this sandbox to use the rootful Docker engine (sets [terminal.sandbox.oci].allow_rootful).", Docs: docsRunsc, Disclosure: "A rootful engine runs the box's container under a root daemon; gVisor is the boundary between the agent and this kernel."},
		},
	},
	{
		ID: "oci-image", Kind: KindImage, Label: "The sandbox image, pulled by digest",
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassTerminal, Channel: ChOCIPull, Package: "oci", Display: "Pull the configured image by its digest (observer sandbox oci pull).", Docs: docsOCIImage},
		},
		Shared: true,
	},
	{
		// gVisor is not in the distributions' main repositories this session
		// could confirm; the vendor's release is the documented route.
		ID: "runsc", Kind: KindProgram, Label: "gVisor (runsc)",
		Detect: Detect{Programs: []string{"runsc"}},
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassGuide, Channel: ChNone, Display: "Install gVisor's runsc from gVisor's own release instructions, then check again.", Docs: docsRunsc},
		},
	},
	{
		ID: "runsc-registered", Kind: KindService, Label: "runsc registered with Docker (host-uds open)",
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassElevated, Channel: ChCommand, Argv: []string{"sudo", "runsc", "install", "--", "--host-uds=open"}, Display: "sudo runsc install -- --host-uds=open", Docs: docsRunsc, After: AfterEngineRestart, Disclosure: "This edits /etc/docker/daemon.json to register runsc. Restart Docker afterwards (sudo systemctl restart docker), which stops every running container."},
		},
	},
	{
		ID: "openshell-pkg", Kind: KindProgram, Label: "OpenShell v0.1.6 (openshell and openshell-gateway, root-owned)",
		Detect: Detect{Programs: []string{"openshell", "openshell-gateway"}, DriverBinary: true},
		Remedies: []Remedy{
			{Hosts: hostsNative, Class: ClassGuide, Channel: ChNone, Display: "Install OpenShell v0.1.6 (openshell and openshell-gateway) root-owned, as OpenShell's own instructions describe, then check again.", Docs: docsOpenShell},
		},
	},
	{
		ID: "openshell-supervisor", Kind: KindService, Label: "Your systemd user manager (managed gateway mode)",
		Remedies: []Remedy{
			{Hosts: hostsNative, Class: ClassGuide, Channel: ChNone, Display: "Managed gateway mode runs the gateway under your systemd user manager, which needs XDG_RUNTIME_DIR; on a machine you do not stay signed in to, loginctl enable-linger $USER keeps it running.", Docs: docsOpenShellGw},
		},
	},
	{
		ID: "macos-12", Kind: KindOSVersion, Label: "macOS 12 or newer",
		Remedies: []Remedy{
			{Hosts: hostsMac, Class: ClassNever, Channel: ChNone, Display: "Seatbelt needs macOS 12 or newer. Upgrading macOS is yours to do.", Docs: docsMac},
		},
	},
	{
		ID: "macos-sandbox-exec", Kind: KindProgram, Label: "macOS's built-in sandbox-exec",
		Detect: Detect{Programs: []string{"sandbox-exec"}},
		Remedies: []Remedy{
			{Hosts: hostsMac, Class: ClassNever, Channel: ChNone, Display: "/usr/bin/sandbox-exec is part of macOS. When it is missing or not the system's own, the OS install is damaged; Observer never replaces it.", Docs: docsMac},
		},
	},
	{
		ID: "macos-26-arm", Kind: KindOSVersion, Label: "macOS 26 on Apple silicon",
		Remedies: []Remedy{
			{Hosts: hostsMac, Class: ClassNever, Channel: ChNone, Display: "Apple container needs macOS 26 on Apple silicon (and virtualization available to it). Observer never changes the OS or the hardware.", Docs: docsMac},
		},
	},
	{
		ID: "apple-container-cli", Kind: KindProgram, Label: "Apple's container CLI",
		Detect: Detect{Programs: []string{"container"}, DriverBinary: true},
		Remedies: []Remedy{
			{Hosts: hostsMac, Class: ClassGuide, Channel: ChNone, Display: "Download Apple's signed installer package (container-<version>-installer-signed.pkg) from https://github.com/apple/container/releases, check it with pkgutil --check-signature <file> (the signer must be Apple), install it with sudo installer -pkg <file> -target / (it needs an administrator), then check again.", Docs: docsMac},
		},
	},
	{
		ID: "apple-container-service", Kind: KindService, Label: "Apple container's system service started",
		Remedies: []Remedy{
			{Hosts: hostsMac, Class: ClassTerminal, Channel: ChCommand, Argv: []string{"container", "system", "start"}, Display: "container system start", Docs: docsMac, Disclosure: "The first start downloads a Linux kernel from Apple's own release; Observer cannot verify that download."},
		},
	},
	{
		ID: "apple-container-image", Kind: KindImage, Label: "The sandbox image, pulled by digest (linux/arm64)",
		Remedies: []Remedy{
			// The pull is Apple's own CLI verb with the configured reference
			// as its last argument (the planner appends it; a fixed argv,
			// never a request field).
			{Hosts: hostsMac, Class: ClassTerminal, Channel: ChCommand, Argv: []string{"container", "image", "pull"}, ArgKey: "terminal.sandbox.apple_container.image", Display: "Pull the configured linux/arm64 image by its digest (container image pull).", Docs: docsMac},
		},
	},
	{
		ID: "win-build-psec", Kind: KindOSVersion, Label: "Windows 11 at the build where MXC offers its container tier",
		Remedies: []Remedy{
			{Hosts: hostsWindows, Class: ClassNever, Channel: ChNone, Display: "This Windows build does not offer the MXC container tier this backend needs. Updating Windows is yours to do.", Docs: docsMXC},
		},
		Shared: true,
	},
	{
		ID: "mxc-files", Kind: KindContent, Label: "The MXC files (signed, hash-checked)",
		Detect: Detect{Content: []string{"sandbox.native_files"}},
		Remedies: []Remedy{
			{Hosts: hostsWindows, Class: ClassAuto, Channel: ChContent, Package: "sandbox.native_files", Display: "Fetch the signed MXC files, or import them from a directory.", Docs: docsMXCFiles},
		},
		Shared: true,
	},
	{
		ID: "hosted-account", Kind: KindAccount, Label: "An account with the provider",
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassNever, Channel: ChNone, Display: "You need your own account with the provider; Observer never creates one.", Docs: docsHosted},
		},
		Shared: true,
	},
	{
		ID: "hosted-key", Kind: KindCredential, Label: "The provider's API key in this machine's keychain",
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassAuto, Channel: ChHostedKey, Display: "Paste the provider's API key; it is kept in this machine's keychain and never logged.", Docs: docsHosted},
		},
		Shared: true,
	},
	{
		// How the agent in the box gets its model key (audit
		// hosted-sandbox-key-custody-2026-11-18). The default keeps the key on
		// this machine, which works only when this machine adds it to the
		// agent's requests (credential injection or the org AI gateway route);
		// otherwise every hosted launch is refused, so the step reads missing.
		// The remedy is the one in-place choice: put the key in the box. It
		// changes the consent's facts, so the consent step after it reopens
		// and the new custody is disclosed before the first upload.
		ID: "hosted-custody", Kind: KindConfig, Label: "A way for the agent to get its model key",
		Detect: Detect{ConfigKey: "terminal.sandbox.hosted.key_custody"},
		Remedies: []Remedy{
			{
				Hosts: hostsLinux, Class: ClassAuto, Channel: ChConfig, Package: "terminal.sandbox.hosted.key_custody", Value: "in_box_api_key",
				Action:     "Put the API key in the box",
				Display:    "Put the model provider's API key in the box: the API key variables this machine holds are copied into the agent's environment there. Or keep the key on this machine by storing it for credential injection, or use your organization's AI gateway.",
				Docs:       docsHostedCustody,
				Disclosure: "The agent in the box can read the API key and use it directly, and you agree again before the next upload. This applies to every hosted provider; your organization's own sandboxes keep the key on this machine and stop being offered.",
			},
		},
		Shared: true,
		// One key ([terminal.sandbox.hosted].key_custody) for every hosted
		// row: its undo changes it back for all of them.
		NodeWide: true,
	},
	{
		ID: "hosted-consent", Kind: KindConsent, Label: "Your consent for this provider",
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassAuto, Channel: ChConsent, Display: "Read what leaves this machine and record your consent for this provider.", Docs: docsHosted, Disclosure: "Your workspace is uploaded to the provider's machines for each run."},
		},
		Shared: true,
	},
	{
		ID: "orgshell-login", Kind: KindAccount, Label: "Signed in to your organization's OpenShell gateway",
		Remedies: []Remedy{
			{Hosts: hostsLinux, Class: ClassAuto, Channel: ChOrgShell, Display: "Sign in to your organization's OpenShell gateway with this machine.", Docs: docsOrgShell},
		},
	},
}

// genericPrereqs are the steps the planner adds to every plan: the
// component first, the enable step last.
var genericPrereqs = map[string]Prereq{
	PrereqComponent: {
		ID: PrereqComponent, Kind: KindComponent, Label: "The backend's module selected",
		Remedies: []Remedy{
			{Class: ClassAuto, Channel: ChComponent, Display: "Select this backend's module in Settings > Components.", Docs: docsComponents},
		},
	},
	PrereqEnable: {
		ID: PrereqEnable, Kind: KindEnable, Label: "The backend enabled",
		Detect: Detect{ConfigKey: "terminal.sandbox.backends"},
		Remedies: []Remedy{
			{Class: ClassAuto, Channel: ChEnable, Package: "terminal.sandbox.backends", Display: "Add this backend to the end of [terminal.sandbox].backends (and turn the sandbox on when it is off).", Docs: docsBwrap},
		},
	},
}

// index is the prerequisite table by id, with Detect.Verdicts filled from
// the verdict map.
var index = buildIndex(prereqTable, verdictMap)

func buildIndex(table []Prereq, vm []driverVerdicts) map[string]Prereq {
	out := make(map[string]Prereq, len(table))
	for _, p := range table {
		p.Detect.Verdicts = nil
		seen := map[string]bool{}
		for _, d := range vm {
			for _, m := range d.Missing {
				if m.Prereq == p.ID && !seen[m.Verdict] {
					seen[m.Verdict] = true
					p.Detect.Verdicts = append(p.Detect.Verdicts, m.Verdict)
				}
			}
		}
		out[p.ID] = p
	}
	return out
}

// Lookup returns a prerequisite row by id (the generic component and enable
// rows included).
func Lookup(id string) (Prereq, bool) {
	if p, ok := genericPrereqs[id]; ok {
		return p, true
	}
	p, ok := index[id]
	return p, ok
}

// IDs returns every prerequisite id of the table, in table order (the
// generic ids excluded).
func IDs() []string {
	out := make([]string, 0, len(prereqTable))
	for _, p := range prereqTable {
		out = append(out, p.ID)
	}
	return out
}

// remedyFor is the first remedy of p matching host and family.
func remedyFor(p Prereq, host sandboxbackend.HostKind, family string) (Remedy, bool) {
	for _, r := range p.Remedies {
		if r.Family != "" && r.Family != family {
			continue
		}
		if len(r.Hosts) > 0 && !hostIn(r.Hosts, host) {
			continue
		}
		return r, true
	}
	return Remedy{}, false
}

func hostIn(hs []sandboxbackend.HostKind, h sandboxbackend.HostKind) bool {
	for _, x := range hs {
		if x == h {
			return true
		}
	}
	return false
}
