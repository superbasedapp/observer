package sandboxbackend

import (
	"sort"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// The backend id vocabulary (section 4.9). The ids are closed; a row's key
// equals its ID (coverage test).
const (
	BackendBwrap           = "bwrap"
	BackendProcessLite     = "process_lite"
	BackendOCIRunc         = "oci-runc"
	BackendOCIRunsc        = "oci-runsc"
	BackendCloudHypervisor = "cloud-hypervisor"
	BackendSeatbelt        = "seatbelt"
	BackendAppleContainer  = "apple-container"
	BackendMXCProcess      = "mxc-process"
	BackendCodespaces      = "codespaces"
	BackendCoder           = "coder"
	BackendE2B             = "e2b"
	BackendK8sAgentSandbox = "k8s-agent-sandbox"
	BackendAgentCore       = "agentcore"
	// BackendModal and BackendVercelSandbox joined P7 by operator ruling
	// P-080 (lane SBX-P7).
	BackendModal         = "modal"
	BackendVercelSandbox = "vercel-sandbox"
	// BackendMXCAppContainer, BackendWSLC and BackendHCS are lane
	// GATES-SBX's Windows rows (operator ruling P-129): beta, explicit-only,
	// probe-only in this release (their runs are refused by name).
	BackendMXCAppContainer = "mxc-appcontainer"
	BackendWSLC            = "wslc"
	BackendHCS             = "hcs"
)

// ConnectorSSH is the SSH connector id.
const ConnectorSSH = "ssh"

// liveBwrapSource names the in-repo receipts for bwrap's live grounding.
const liveBwrapSource = "cmd/observer/terminal_sandbox_linux_test.go, terminal_sandbox_net_linux_test.go; docs/plans/spikes/JSP-12-custom-driver-isolation-2026-10.md (bwrap 0.4.0 to 0.13.1)"

// ociSpikeSource names the grounding of the oci-runc mechanisms.
const ociSpikeSource = "docs/plans/spikes/JSP-4-oci-lifecycle-2026-10.md (rootful and rootless Docker 28.1.1 and 29.9.1, rootless and rootful Podman 4.9.3, rootless Podman 5.6.2); internal/sandboxoci and internal/sandboxengine recorded-answer tests"

// ociLiveOwed names the live runs the oci-runc row still owes.
const ociLiveOwed = "SBX-P3A live checks (JSP-4 owed halves)"

// runscDocSource names the grounding of the oci-runsc row (lane SBX-P3B).
const runscDocSource = "gvisor.dev docs (runsc install, Docker quick start, --host-uds); Docker Engine API types.Runtime (path, runtimeArgs) and HostConfig.Runtime; internal/sandboxoci runtime and read-back tests, internal/sandboxengine recorded-shape /info answers"

// runscLiveOwed names the live runs the oci-runsc row still owes.
const runscLiveOwed = "SBX-P3B live checks (runsc on rootful Docker: the egress tiers, a hook through the relay, db-copy, Ctrl-C, a daemon kill)"

// landlockDocSource names the grounding of the process_lite row (lane
// SBX-P3B).
const landlockDocSource = "Linux Landlock documentation (Documentation/userspace-api/landlock.rst: ABI versions, path-beneath and net-port rules, scopes); golang.org/x/sys/unix uapi constants; internal/sandboxlandlock and cmd/observer unit tests"

// mxcDocSource names the grounding of the mxc-process row.
const mxcDocSource = "@microsoft/mxc-sdk 1.0.1 (npm, sha256 416d9607...cef49): dist/bindings/process-container-pty.js, probe.js, generated/v1_0_0/wire.d.ts and bin/x64/dotnet/NativeMethods.g.cs; internal/sandboxmxc and internal/sandboxmxcdll tests"

// mxcRegister names the register rows the mxc-process row owes.
const mxcRegister = "WIN-1 to WIN-4 (sandbox plan section 13.10), scripts/sandbox/p6-live-check.ps1"

// seatbeltDocSource names the grounding of the Seatbelt row (lane SBX-P5).
const seatbeltDocSource = "sandbox-exec(1); the SBPL forms of Chromium's mac sandbox policies, the Codex CLI's seatbelt base policy and Anthropic's sandbox-runtime; internal/sandboxsbpl golden and oracle tests"

// seatbeltRegister names the register rows the Seatbelt row still owes.
const seatbeltRegister = "MAC-1 to MAC-10, MAC-34, MAC-35, MAC-37 (task T-898)"

// appleContainerDocSource names the grounding of the Apple container row.
const appleContainerDocSource = "github.com/apple/container command reference and how-to (run, ls --format json, inspect, --network, -l, --memory, --cpus, -v); internal/sandboxapple contract tests over outputs reconstructed from those documents"

// appleContainerRegister names the register rows the Apple container row
// still owes.
const appleContainerRegister = "MAC-11 to MAC-19, MAC-27, MAC-33 (task T-898)"

// chDocSource names the grounding of the cloud-hypervisor row (lane
// SBX-P4).
const chDocSource = "Cloud Hypervisor v54 API (vmm.ping, vm.create, vm.boot, vm.info, vm.shutdown, vm.delete, vmm.shutdown; the hybrid vsock CONNECT protocol) and docs/plans/spikes/JSP-5-cloud-hypervisor-2026-10.md (P-097 boot half, the 2026-10-24 Elastic Metal spike); internal/sandboxvm and internal/sandboxvmm recorded-answer tests"

// chRegister names the register rows the cloud-hypervisor row owes.
const chRegister = "LIN-2 onward (sandbox plan section 13.11, docs/sandboxed-terminals.md \"microVM sandboxes\")"

// registry is the table. Adding a backend is adding a row (plus its id
// constant, its component row and its config rows, section 11.3).
var registry = map[string]Capability{
	BackendBwrap: {
		ID: BackendBwrap, Label: "Bubblewrap", Maturity: MaturityShipped, Phase: "P1a",
		Verification: []Verified{
			{Host: HostLinux, Kind: vocab.VerifiedLive, Source: liveBwrapSource, Date: "2026-10-20"},
			{Host: HostWSL2, Kind: vocab.VerifiedLive, Source: liveBwrapSource, Date: "2026-10-20"},
		},
		Iso: Isolation{
			// documented: the host helper's post-launch re-check
			// (sandboxselect.RecheckBwrap) refuses a measured mismatch, but
			// a launch whose namespaces cannot be read, or one with no host
			// helper (the host tier without placeholders), is not measured.
			Class: vocab.ClassProcess, ClassSource: vocab.SourceDocumented,
			Location: vocab.LocationLocal, Tenancy: TenancyPerRun,
			Hosts: []HostKind{HostLinux, HostWSL2},
		},
		Control: Control{
			Interface: InterfaceCLI, Stability: StabilityVendorStable,
			Pins: DriverPins{RequiredMin: "0.4.0", TestedLow: "0.4.0", TestedHigh: "0.13.1"},
		},
		Term: Terminal{PTYOwner: PTYHost, Resize: ResizeHostPTY, Reattach: ReattachDaemonOnly, RelayReattach: RelayNotNeeded},
		Net: Network{
			Egress:   []vocab.Tier{vocab.TierHost, vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer: EnforcerObserverGateway,
			EgressSource: map[vocab.Tier]vocab.ClassSource{
				// the private namespace is proved by the netns canary before
				// a launch; the shared namespace is the host's own network.
				vocab.TierInternet: vocab.SourceMeasured, vocab.TierProxyOnly: vocab.SourceMeasured,
				vocab.TierNone: vocab.SourceMeasured, vocab.TierHost: vocab.SourceDocumented,
			},
			KeyCustody:        []vocab.KeyCustody{vocab.CustodyHostBound, vocab.CustodyHomeRelay},
			ProviderHostBlock: true,
		},
		Capture:            Capture{Ceiling: vocab.CaptureFull, HookPath: HookDirectDB},
		ReadBack:           ReadBackProcNS,
		AllowsNestedUserns: true,
		// Observer's plan mounts a fresh /proc and covers parts of it, and
		// gives the private network namespace no TUN device (N11, N12;
		// plan analysis, confirmed by the Linux probe matrix).
		ProcView: ProcFreshCovered,
		Note:     "Linux and WSL2 only; same kernel, so hooks write the home database directly through the ~/.observer bind until the P2 relay.",
	},
	BackendProcessLite: {
		ID: BackendProcessLite, Label: "Landlock only", Maturity: MaturityPreview, Phase: "P3",
		// doc (beta everywhere): the project's only Linux rig is WSL2, whose
		// kernel reports ABI 7, below the row's floor, so the row is built
		// against the kernel's Landlock documentation and unit-tested only
		// (lane SBX-P3B); its live proof is register entry LIN-1.
		Verification: []Verified{
			{Host: HostLinux, Kind: vocab.VerifiedDoc, Source: landlockDocSource, Date: "2026-10-22", RegisterRef: "LIN-1 (sandbox plan section 13.11)"},
		},
		Iso: Isolation{
			// documented: Landlock alone, no namespaces (section 4.1); the exec
			// step checks the ruleset holds (the observer directory is
			// unreadable) before the agent starts.
			Class: vocab.ClassProcess, ClassSource: vocab.SourceDocumented,
			Location: vocab.LocationLocal, Tenancy: TenancyPerRun,
			// Linux only: WSL2's kernel reports ABI 7, below the floor, so
			// the probe refuses it there by name.
			Hosts: []HostKind{HostLinux},
		},
		Control: Control{
			// The kernel's own syscalls (golang.org/x/sys/unix, no CGO); the
			// version a pin reads is the Landlock ABI the kernel reports.
			Interface: InterfaceInProcess, Stability: StabilityVendorStable,
			Pins: DriverPins{RequiredMin: "9", TestedLow: "9", TestedHigh: "9"},
		},
		// The agent is the host PTY's own child, as under bwrap.
		Term: Terminal{PTYOwner: PTYHost, Resize: ResizeHostPTY, Reattach: ReattachDaemonOnly, RelayReattach: RelayNotNeeded},
		Net: Network{
			// The host's network: TCP is an allow-list of every port but
			// Observer's own, UDP is unrestricted below ABI 10, and every
			// other loopback service is reachable (SBX-BE-17). Its only
			// tier is host; a min_egress floor refuses it.
			Egress:       []vocab.Tier{vocab.TierHost},
			Enforcer:     EnforcerNone,
			EgressSource: map[vocab.Tier]vocab.ClassSource{vocab.TierHost: vocab.SourceDocumented},
			KeyCustody:   []vocab.KeyCustody{vocab.CustodyHostBound, vocab.CustodyHomeRelay},
		},
		// No ~/.observer path is granted: hooks reach the daemon through the
		// relay's per-run socket (the only unix socket the box may connect
		// to, ABI 9).
		Capture:  Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay},
		ReadBack: ReadBackSelfTest,
		// Explicit-only (S1b): never an automatic choice nor the guard's
		// enforcement target; used only when a launch names it.
		ExplicitOnly: true,
		Landlock:     true,
		// No PID namespace and no private /proc: the host's own view.
		ProcView: ProcInherited,
		Note:     "Linux with Landlock ABI 9 or later (Linux 7.1+), for hosts that block the user namespaces bubblewrap needs; explicit-only, beta (register LIN-1). Weaker than bubblewrap: no private /proc, process list or network; TCP to every port but Observer's own, UDP open below ABI 10; its only tier is host.",
	},
	BackendOCIRunc: {
		ID: BackendOCIRunc, Label: "Docker or Podman (runc)", Maturity: MaturityPreview, Phase: "P3",
		// doc on both hosts, so every surface labels it beta and no floor
		// accepts it unless the floor accepts beta: the mechanisms were
		// measured by spike JSP-4 (prototypes), the driver itself is owed
		// its live runs (SBX-P3A report, "Live checks owed").
		Verification: []Verified{
			{Host: HostLinux, Kind: vocab.VerifiedDoc, Source: ociSpikeSource, Date: "2026-10-21", RegisterRef: ociLiveOwed},
			{Host: HostWSL2, Kind: vocab.VerifiedDoc, Source: ociSpikeSource, Date: "2026-10-21", RegisterRef: ociLiveOwed},
		},
		Iso: Isolation{
			// measured: the host helper reads every container back through
			// the Engine API before the agent starts and refuses a weaker
			// build (sandboxoci.ReadBack, built_below_plan).
			Class: vocab.ClassContainer, ClassSource: vocab.SourceMeasured,
			Location: vocab.LocationLocal, Tenancy: TenancyPerRun,
			Hosts: []HostKind{HostLinux, HostWSL2},
		},
		Control: Control{
			Interface: InterfaceEngineAPIUDS, Stability: StabilityVendorStable,
			// The version a row pin reads is the negotiated Engine API
			// version (Podman's compatible API reports 1.41); the per-engine
			// floors (Docker API 1.44, Podman 4.9.3) are sandboxoci's.
			Pins: DriverPins{RequiredMin: "1.41", TestedLow: "1.41", TestedHigh: "1.56", RequireAuthenticatedVersion: true},
		},
		Term: Terminal{PTYOwner: PTYBackendMainTTY, Resize: ResizeBackendAPI, Reattach: ReattachBackendNative, RelayReattach: RelayNotNeeded},
		Net: Network{
			// --network none: the container has only its own loopback, and
			// the guest helper forwards the tier's sockets from the
			// read-only socket dir, exactly as in bwrap's private namespace.
			Egress:   []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer: EnforcerObserverGateway,
			EgressSource: map[vocab.Tier]vocab.ClassSource{
				vocab.TierInternet: vocab.SourceMeasured, vocab.TierProxyOnly: vocab.SourceMeasured, vocab.TierNone: vocab.SourceMeasured,
			},
			KeyCustody:        []vocab.KeyCustody{vocab.CustodyHostBound, vocab.CustodyHomeRelay},
			ProviderHostBlock: true,
		},
		// Same kernel, but the container never sees observer.db: hooks
		// reach the daemon through the capture relay's bound socket dir.
		Capture:  Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay},
		ReadBack: ReadBackEngineAPI,
		// The engine's default seccomp and masked /proc paths, with every
		// capability dropped: no nested user namespace and no fresh procfs.
		ProcView: ProcFreshCovered,
		Note:     "Docker Engine or rootless Podman on this machine, through the Engine API on a local unix socket (Linux and WSL2); the container is read back per engine before the agent starts. A rootful engine only with [terminal.sandbox.oci].allow_rootful.",
	},
	BackendOCIRunsc: {
		ID: BackendOCIRunsc, Label: "Docker with gVisor (runsc)", Maturity: MaturityPreview, Phase: "P3",
		// doc on both hosts (beta everywhere, never picked automatically,
		// ruling P-062): built against gVisor's and Docker's documentation
		// with recorded-shape engine answers (lane SBX-P3B); the runsc runs
		// are owed live (register entry below).
		Verification: []Verified{
			{Host: HostLinux, Kind: vocab.VerifiedDoc, Source: runscDocSource, Date: "2026-10-22", RegisterRef: runscLiveOwed},
			{Host: HostWSL2, Kind: vocab.VerifiedDoc, Source: runscDocSource, Date: "2026-10-22", RegisterRef: runscLiveOwed},
		},
		Iso: Isolation{
			// measured: the host helper reads the container back and refuses
			// one the engine does not report as runsc (sandboxoci.ReadBack,
			// built_below_plan); gVisor's own kernel serves every syscall.
			Class: vocab.ClassUserspaceKernel, ClassSource: vocab.SourceMeasured,
			Location: vocab.LocationLocal, Tenancy: TenancyPerRun,
			Hosts: []HostKind{HostLinux, HostWSL2},
			// gVisor serves files through its own gofer with its own lock
			// semantics: hooks go through the relay (I5) and the tool's
			// state is projected, never bound (section 5.4).
			CrossesKernel: true,
		},
		Control: Control{
			// The same Engine API client as oci-runc, on rootful Docker
			// Engine only (gVisor's documented integration, `runsc
			// install`); the version a pin reads is the negotiated API.
			Interface: InterfaceEngineAPIUDS, Stability: StabilityVendorStable,
			Pins: DriverPins{RequiredMin: "1.44", TestedLow: "1.44", TestedHigh: "1.56", RequireAuthenticatedVersion: true},
		},
		Term: Terminal{PTYOwner: PTYBackendMainTTY, Resize: ResizeBackendAPI, Reattach: ReattachBackendNative, RelayReattach: RelayNotNeeded},
		Net: Network{
			// --network none as for oci-runc; the guest helper reaches the
			// run's sockets through gVisor's host-UDS bridge, which the row's
			// own probe requires (runsc registered with --host-uds=open).
			Egress:   []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer: EnforcerObserverGateway,
			EgressSource: map[vocab.Tier]vocab.ClassSource{
				vocab.TierInternet: vocab.SourceDocumented, vocab.TierProxyOnly: vocab.SourceDocumented, vocab.TierNone: vocab.SourceDocumented,
			},
			KeyCustody:        []vocab.KeyCustody{vocab.CustodyHostBound, vocab.CustodyHomeRelay},
			ProviderHostBlock: true,
		},
		Capture:  Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay},
		ReadBack: ReadBackEngineAPI,
		// gVisor presents its own /proc; nested agent sandboxes are not
		// grounded inside it, so the strictest view applies (N11).
		ProcView: ProcFreshCovered,
		Note:     "Rootful Docker Engine with gVisor's runsc registered as a runtime with --host-uds=open (`sudo runsc install -- --host-uds=open`; Linux and WSL2), through the same Engine API driver as oci-runc and only with [terminal.sandbox.oci].allow_rootful. The agent's syscalls are served by gVisor's user-space kernel; the tool's state is a per-run projected directory (empty at start: log in inside the box) and its SQLite stores are copied inside the box at the end. Beta: the runsc runs are owed live.",
	},
	BackendCloudHypervisor: {
		ID: BackendCloudHypervisor, Label: "Cloud Hypervisor microVM", Maturity: MaturityPreview, Phase: "P4",
		// doc on both hosts (beta everywhere, never picked automatically,
		// ruling P-062): spike JSP-5 booted Cloud Hypervisor v54 as an
		// unprivileged user (plans decision log P-097, the 2026-10-24 Elastic
		// Metal spike), but the driver itself is built and unit-tested without
		// /dev/kvm (lane SBX-P4); its live runs are register rows LIN-2
		// onward.
		Verification: []Verified{
			{Host: HostLinux, Kind: vocab.VerifiedDoc, Source: chDocSource, Date: "2026-10-24", RegisterRef: chRegister},
			{Host: HostWSL2, Kind: vocab.VerifiedDoc, Source: chDocSource, Date: "2026-10-24", RegisterRef: chRegister},
		},
		Iso: Isolation{
			// measured: the host helper reads the VM back through vm.info
			// before the agent starts (and again after boot, since vm.add-fs
			// hotplug exists) and refuses any NIC, another vsock CID, an
			// unplanned share or disk, a writable rootfs or unshared memory
			// (sandboxvm.ReadBack, built_below_plan): the oci-runc precedent.
			Class: vocab.ClassHWVM, ClassSource: vocab.SourceMeasured,
			Location: vocab.LocationLocal, Tenancy: TenancyPerRun,
			Hosts: []HostKind{HostLinux, HostWSL2},
			// The guest kernel is another kernel: hooks go through the relay
			// (I5) and the tool's state is projected, never bound (5.4).
			CrossesKernel: true,
		},
		Control: Control{
			// Cloud Hypervisor's REST API on its --api-socket unix socket;
			// the version a pin reads is vmm.ping's major version.
			Interface: InterfaceRESTUDS, Stability: StabilityVendorStable,
			Pins: DriverPins{RequiredMin: "54", TestedLow: "54", TestedHigh: "54"},
		},
		// The guest helper opens and HOLDS the guest PTY (D-751 Q35) and its
		// bytes ride stream 2 of the relay mux over the VMM's hybrid vsock
		// socket; the size travels on the same stream's control frames. No
		// reattach: the death of the guest helper, the host helper or the
		// daemon ends the run, tears the VM down and offers native resume.
		Term: Terminal{PTYOwner: PTYGuestHelper, Resize: ResizeGuest, Reattach: ReattachNone, RelayReattach: RelayNotNeeded, Transport: TransportVsockUDS},
		Net: Network{
			// No NIC at all: the VM is the one network owner (N8) and its
			// only way out is the vsock mux, whose kinds are the tier's (the
			// relay always, the proxy forward, the gateway on internet).
			// documented until a live receipt (register LIN-2 onward).
			Egress:   []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer: EnforcerObserverGateway,
			EgressSource: map[vocab.Tier]vocab.ClassSource{
				vocab.TierInternet: vocab.SourceDocumented, vocab.TierProxyOnly: vocab.SourceDocumented, vocab.TierNone: vocab.SourceDocumented,
			},
			KeyCustody:        []vocab.KeyCustody{vocab.CustodyHostBound, vocab.CustodyHomeRelay},
			ProviderHostBlock: true,
		},
		Capture:  Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay, Relay: RelayVsockUDS},
		ReadBack: ReadBackVMMInfo,
		// GuestUnprivUserns stays false on the row: the driver sets it on its
		// copy only when the verified image set's descriptor declares it and
		// the guest self-test confirms it (N13, lane SBX-P4 decision 7).
		Note: "Linux and WSL2 with a usable /dev/kvm (nested virtualisation inside a VM), through Cloud Hypervisor 54's REST API on a unix socket; each run is its own microVM with no network device, booted from Observer's signed guest image set (sandbox.rootfs and sandbox.guest_binary, imported with `observer sandbox content import`). Beta: built and unit-tested without /dev/kvm; its live runs are owed (register LIN-2 onward).",
	},
	BackendSeatbelt: {
		ID: BackendSeatbelt, Label: "macOS Seatbelt", Maturity: MaturityPreview, Phase: "P5",
		// doc, so every surface labels it beta and no floor accepts it unless
		// the floor accepts beta: built against vendor documentation, never
		// run on a Mac (lane SBX-P5; register section 13.9, task T-898).
		Verification: []Verified{
			{Host: HostMacOS, Kind: vocab.VerifiedDoc, Source: seatbeltDocSource, Date: "2026-10-22", RegisterRef: seatbeltRegister},
		},
		Iso: Isolation{
			// documented: the launch self-test (sandbox-seatbelt-selftest)
			// reads the profile back before the agent starts, but it has
			// never run on a Mac.
			Class: vocab.ClassProcess, ClassSource: vocab.SourceDocumented,
			Location: vocab.LocationLocal, Tenancy: TenancyPerRun,
			Hosts: []HostKind{HostMacOS},
		},
		Control: Control{
			// Apple's man page marks sandbox-exec deprecated while every
			// macOS still ships it; mxc-exec-mac is the declared fallback.
			Interface: InterfaceCLI, Stability: StabilityVendorPreview,
			// The version a pin reads is the macOS product version (the
			// binary has none): the floor is Go's own macOS floor, the
			// range is what the SBPL sources were written for.
			Pins: DriverPins{RequiredMin: "12.0", TestedLow: "14.0", TestedHigh: "26.99"},
		},
		// The agent stays the PTY's child under sandbox-exec, exactly as
		// under bwrap.
		Term: Terminal{PTYOwner: PTYHost, Resize: ResizeHostPTY, Reattach: ReattachDaemonOnly, RelayReattach: RelayNotNeeded},
		Net: Network{
			// No host tier: the box shares the host network, so the profile
			// allows only the relay socket and the tier's loopback ports.
			Egress:   []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer: EnforcerObserverGateway,
			EgressSource: map[vocab.Tier]vocab.ClassSource{
				vocab.TierInternet: vocab.SourceDocumented, vocab.TierProxyOnly: vocab.SourceDocumented, vocab.TierNone: vocab.SourceDocumented,
			},
			KeyCustody: []vocab.KeyCustody{vocab.CustodyHostBound, vocab.CustodyHomeRelay},
			// No rule reaches any address but localhost, so a direct or
			// literal-IP provider call is refused by the profile, and the
			// gateway refuses the provider hosts (section 7.3).
			ProviderHostBlock: true,
		},
		Capture:  Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay},
		ReadBack: ReadBackSelfTest,
		// No ExplicitOnly: the doc verification above is what keeps the row
		// out of an automatic choice (selection rule S4c, ruling P-062) and
		// out of the guard's auto-upgrade (S0), one table for every beta row.
		Seatbelt: true,
		Note:     "macOS only (Seatbelt through /usr/bin/sandbox-exec, a Go-generated profile); beta: built from Apple's and open-source SBPL documentation, never run on a Mac (register MAC-1 to MAC-10, MAC-34, MAC-35, MAC-37). Hooks reach the daemon through the capture relay's unix socket.",
	},
	BackendAppleContainer: {
		ID: BackendAppleContainer, Label: "Apple container", Maturity: MaturityPreview, Phase: "P5",
		// doc (beta): built against Apple's container documentation, never
		// run on a Mac (lane SBX-P5; register section 13.9, task T-898).
		Verification: []Verified{
			{Host: HostMacOS, Kind: vocab.VerifiedDoc, Source: appleContainerDocSource, Date: "2026-10-22", RegisterRef: appleContainerRegister},
		},
		Iso: Isolation{
			// Each container is its own lightweight Linux VM
			// (Virtualization.framework): documented, read back with
			// `container inspect` before the run is trusted, never measured
			// on a Mac. An Intel Mac or a macOS below 26 gets the Seatbelt
			// row only (the probe's arch_unsupported and os_too_old).
			Class: vocab.ClassHWVM, ClassSource: vocab.SourceDocumented,
			Location: vocab.LocationLocal, Tenancy: TenancyPerRun,
			Hosts:         []HostKind{HostMacOS},
			CrossesKernel: true,
		},
		Control: Control{
			// The CLI is the documented interface; 1.6.x is checked live
			// (sandboxapple.DocLow to DocHigh).
			Interface: InterfaceCLI, Stability: StabilityVendorPreview,
			Pins: DriverPins{RequiredMin: "0.5.0", TestedLow: "1.6.0", TestedHigh: "1.6.99"},
		},
		// The agent is the container's main process under `container run
		// -it` in the host PTY; the CLI carries the TTY and its size. No
		// attach command exists, so a lost CLI ends the run (native resume).
		Term: Terminal{PTYOwner: PTYBackendMainTTY, Resize: ResizeHostPTY, Reattach: ReattachNone, RelayReattach: RelayNotNeeded},
		Net: Network{
			// --network none: only the container's loopback, and the guest
			// helper forwards the tier's ports to the mounted socket dir.
			Egress:   []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer: EnforcerObserverGateway,
			EgressSource: map[vocab.Tier]vocab.ClassSource{
				vocab.TierInternet: vocab.SourceDocumented, vocab.TierProxyOnly: vocab.SourceDocumented, vocab.TierNone: vocab.SourceDocumented,
			},
			KeyCustody:        []vocab.KeyCustody{vocab.CustodyHostBound, vocab.CustodyHomeRelay},
			ProviderHostBlock: true,
		},
		// Another kernel: hooks reach the daemon only through the relay's
		// mounted socket (invariant I5).
		Capture:  Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay},
		ReadBack: ReadBackVMMInfo,
		Note:     "macOS 26 on Apple silicon, through Apple's own container CLI (each container a lightweight Linux VM with no network but the run's sockets); beta: built from Apple's documentation, never run on a Mac (register MAC-11 to MAC-19, MAC-27, MAC-33). The image provides the agent and a linux/arm64 observer.",
	},
	BackendMXCProcess: {
		ID: BackendMXCProcess, Label: "MXC ProcessContainer", Maturity: MaturityPreview, Phase: "P6",
		// doc on Windows, so every surface labels it beta and no floor
		// accepts it unless the floor accepts beta: built from MXC's own
		// SDK sources and published 1.0.1 packages (lane SBX-P6); its live
		// proofs are register rows WIN-1 to WIN-4 (sandbox plan 13.10).
		Verification: []Verified{
			{Host: HostWindows, Kind: vocab.VerifiedDoc, Source: mxcDocSource, Date: "2026-10-22", RegisterRef: mxcRegister},
		},
		Iso: Isolation{
			// documented: the helper reads MXC's own tier choice (the request
			// probe must say base-container) and runs the create-and-close
			// check, but it does not read the built container back.
			Class: vocab.ClassProcess, ClassSource: vocab.SourceDocumented,
			Location: vocab.LocationLocal, Tenancy: TenancyPerRun,
			Hosts: []HostKind{HostWindows},
			// allowDaclMutation = false: MXC's DACL tier is refused, never
			// used, so the row changes no host ACL.
			HostMutation: false,
		},
		Control: Control{
			// The C ABI (mxc_ffi, loaded lazily without CGO in the per-run
			// helper only) is the fail-closed surface: version, probe and
			// validation. The interactive run is wxc-exec (vendor_preview,
			// MXC's documented fallback path) under the terminal's ConPTY.
			Interface: InterfaceCABILazyDLL, Stability: StabilityVendorStable,
			// The version is mxc_version() from the hash-pinned library.
			Pins: DriverPins{RequiredMin: "1.0.0", TestedLow: "1.0.0", TestedHigh: "1.0.1", RequireAuthenticatedVersion: true},
		},
		Term: Terminal{PTYOwner: PTYHost, Resize: ResizeHostPTY, Reattach: ReattachDaemonOnly, RelayReattach: RelayNotNeeded, Transport: TransportExecUnderHostConPTY},
		Net: Network{
			// MXC's per-container WFP filter permits only the run's one
			// loopback port; the helper's token decides what each tier may
			// open there (section 5.2). documented until WIN-2.
			Egress:   []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer: EnforcerObserverGateway,
			EgressSource: map[vocab.Tier]vocab.ClassSource{
				vocab.TierInternet: vocab.SourceDocumented, vocab.TierProxyOnly: vocab.SourceDocumented, vocab.TierNone: vocab.SourceDocumented,
			},
			KeyCustody:        []vocab.KeyCustody{vocab.CustodyHostBound, vocab.CustodyHomeRelay},
			ProviderHostBlock: true,
		},
		// Same kernel and same filesystem, but the box never reads
		// observer.db (the observer directory is denied): hooks reach the
		// daemon through the helper's port and the owner-only named pipe.
		Capture:      Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay, Relay: RelaySingleLoopbackPortToken},
		ReadBack:     ReadBackSelfTest,
		AppContainer: true,
		Discloses:    []Disclosure{DiscloseCLITelemetry},
		Note:         "Native Windows 11 at or above ProcessContainer's build floor, where MXC's own probe offers the PSEC BaseContainer tier (Windows Home may not). The MXC files are bundled and hash-checked; MXC's telemetry is switched off in every run. The proxy runs in MXC's Least tier (host loopback allowed, no peer identity), so the run's one port authenticates every request with a per-run token.",
	},
	// MXC's weaker AppContainer tier (lane GATES-SBX decision 5): the same
	// MXC files and wire as mxc-process, accepting exactly the
	// appcontainer-bfs tier MXC's probe reports where PSEC is not offered
	// (Windows Home, WIN-4). @microsoft/mxc-sdk 1.0.1 documents that tier as
	// "AppContainer + BFS filesystem isolation" (dist/v1/types.d.ts) and
	// says AppContainer processes see every directory whose ACL grants ALL
	// APPLICATION PACKAGES without brokering (dist/v1/policy/filesystem.js),
	// so it is weaker than the BaseContainer tier. Its loopback capabilities
	// are documented for BaseContainer only, so the row offers tier none
	// alone, and the run's relay over the shared port is claimed until
	// WIN-4 proves it. appcontainer-dacl stays refused: it rewrites host
	// ACLs (allowDaclMutation = false).
	BackendMXCAppContainer: {
		ID: BackendMXCAppContainer, Label: "MXC AppContainer tier (weaker than ProcessContainer)", Maturity: MaturityPreview, Phase: "P6",
		Verification: []Verified{
			{Host: HostWindows, Kind: vocab.VerifiedDoc, Source: mxcDocSource + "; dist/v1/types.d.ts (IsolationTier), dist/v1/policy/filesystem.js (ALL_APPLICATION_PACKAGES)", Date: "2026-10-24", RegisterRef: "WIN-4, WIN-9 (docs/sandboxed-terminals.md)"},
		},
		Iso: Isolation{
			Class: vocab.ClassProcess, ClassSource: vocab.SourceDocumented,
			Location: vocab.LocationLocal, Tenancy: TenancyPerRun,
			Hosts: []HostKind{HostWindows}, HostMutation: false,
		},
		Control: Control{
			Interface: InterfaceCABILazyDLL, Stability: StabilityVendorStable,
			Pins: DriverPins{RequiredMin: "1.0.0", TestedLow: "1.0.0", TestedHigh: "1.0.1", RequireAuthenticatedVersion: true},
		},
		Term: Terminal{PTYOwner: PTYHost, Resize: ResizeHostPTY, Reattach: ReattachDaemonOnly, RelayReattach: RelayNotNeeded, Transport: TransportExecUnderHostConPTY},
		Net: Network{
			Egress:       []vocab.Tier{vocab.TierNone},
			Enforcer:     EnforcerObserverGateway,
			EgressSource: map[vocab.Tier]vocab.ClassSource{vocab.TierNone: vocab.SourceClaimed},
			KeyCustody:   []vocab.KeyCustody{vocab.CustodyHostBound, vocab.CustodyHomeRelay},
		},
		Capture:      Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay, Relay: RelaySingleLoopbackPortToken},
		ReadBack:     ReadBackSelfTest,
		AppContainer: true,
		ExplicitOnly: true,
		Discloses:    []Disclosure{DiscloseCLITelemetry},
		Note:         "Native Windows 11 where MXC offers only its AppContainer tier (appcontainer-bfs), not PSEC (often Windows Home). Weaker than ProcessContainer: an AppContainer sees every folder whose access list grants ALL APPLICATION PACKAGES. Tier none only. Beta and probe-only in this release (register WIN-4, WIN-9); a run is refused by name.",
	},
	// wslc (lane GATES-SBX decision 6; sandbox plan 17.1 row 35): WSL
	// containers on Windows 11 through the wslc CLI. Tier none only
	// (--network none) until a token-authenticated host path is tested;
	// the relay rides the exec's stdio (the hosted exec_stdio precedent);
	// the PTY sits under an Observer ConPTY, resize claimed until WIN-5.
	// Probe-only in this release: no pinned wslc version's --help and JSON
	// are captured yet, so no argv is grounded and a run is refused.
	BackendWSLC: {
		ID: BackendWSLC, Label: "WSL containers (wslc)", Maturity: MaturityPreview, Phase: "P6",
		Verification: []Verified{
			{Host: HostWindows, Kind: vocab.VerifiedDoc, Source: "sandbox plan v2 sections 4.8 and 7.1 (the wslc rows); @microsoft/mxc-sdk 1.0.1 generated/v1_0_0/wire.d.ts (OneShotWslc: image, portMappings; WSLC networking None or Bridged)", Date: "2026-10-24", RegisterRef: "WIN-5 (docs/sandboxed-terminals.md)"},
		},
		Iso: Isolation{
			Class: vocab.ClassContainer, ClassSource: vocab.SourceDocumented,
			Location: vocab.LocationLocal, Tenancy: TenancyPerRun, Hosts: []HostKind{HostWindows},
		},
		// No wslc version is tested yet: the pins are 0.0.0 so every
		// installed version reads beta, and the probe refuses a run until
		// WIN-5 records a version's help and JSON.
		Control: Control{Interface: InterfaceCLI, Stability: StabilityVendorPreview, Pins: DriverPins{RequiredMin: "0.0.0", TestedLow: "0.0.0", TestedHigh: "0.0.0", RequireAuthenticatedVersion: true}},
		Term:    Terminal{PTYOwner: PTYHost, Resize: ResizeHostPTY, Reattach: ReattachDaemonOnly, RelayReattach: RelayNotNeeded, Transport: TransportExecUnderHostConPTY},
		Net: Network{
			Egress:       []vocab.Tier{vocab.TierNone},
			Enforcer:     EnforcerProvider,
			EgressSource: map[vocab.Tier]vocab.ClassSource{vocab.TierNone: vocab.SourceDocumented},
			KeyCustody:   []vocab.KeyCustody{vocab.CustodyInBoxAPIKey},
		},
		Capture:      Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay, Relay: RelayExecStdio},
		ReadBack:     ReadBackNone,
		ExplicitOnly: true,
		Note:         "Windows 11 with WSL: Linux containers through the wslc CLI, with no network (--network none). Beta and probe-only in this release (register WIN-5): the pinned wslc version's help and JSON are not captured yet, so a run is refused by name.",
	},
	// hcs (lane GATES-SBX decision 7; sandbox plan 17.1 row 59): Hyper-V
	// isolated containers through the HCS v2 compute system API, loaded
	// lazily from computecore.dll in the per-run helper only. No network
	// adapter (tier none). Probe-only in this release: no utility VM image
	// can be pinned and verified without a release artifact, so the probe
	// refuses image_missing.
	BackendHCS: {
		ID: BackendHCS, Label: "Hyper-V isolated containers (HCS)", Maturity: MaturityPreview, Phase: "P6",
		Verification: []Verified{
			{Host: HostWindows, Kind: vocab.VerifiedDoc, Source: "Microsoft's Host Compute Service API reference (computecore.dll: HcsCreateOperation, HcsCreateComputeSystem, HcsEnumerateComputeSystems; HCS schema v2 ComputeSystem with a HyperV Container); internal/sandboxhcs tests", Date: "2026-10-24", RegisterRef: "WIN-10 (docs/sandboxed-terminals.md)"},
		},
		Iso: Isolation{
			Class: vocab.ClassHWVM, ClassSource: vocab.SourceDocumented,
			Location: vocab.LocationLocal, Tenancy: TenancyPerRun, Hosts: []HostKind{HostWindows},
		},
		// The pins are the HCS schema version the planner writes (2.1), not
		// a version a live run has seen (WIN-10).
		Control: Control{Interface: InterfaceCABILazyDLL, Stability: StabilityVendorStable, Pins: DriverPins{RequiredMin: "2.1", TestedLow: "2.1", TestedHigh: "2.1", RequireAuthenticatedVersion: true}},
		Term:    Terminal{PTYOwner: PTYHost, Resize: ResizeHostPTY, Reattach: ReattachDaemonOnly, RelayReattach: RelayNotNeeded, Transport: TransportExecUnderHostConPTY},
		Net: Network{
			Egress:       []vocab.Tier{vocab.TierNone},
			Enforcer:     EnforcerObserverGateway,
			EgressSource: map[vocab.Tier]vocab.ClassSource{vocab.TierNone: vocab.SourceDocumented},
			KeyCustody:   []vocab.KeyCustody{vocab.CustodyInBoxAPIKey},
		},
		Capture:      Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay},
		ReadBack:     ReadBackNone,
		ExplicitOnly: true,
		Note:         "Windows Pro, Enterprise or Education with the Containers and Hyper-V features: each run in its own Hyper-V utility VM with no network adapter. Beta and probe-only in this release (register WIN-10): no utility VM image can be pinned and verified yet, so the probe refuses image_missing.",
	},
	BackendCodespaces: planned(BackendCodespaces, "GitHub Codespaces", "P7", vocab.ClassHWVM, vocab.LocationRemote,
		[]HostKind{HostRemote}, "reached through the SSH connector; class documented by the vendor", false),
	BackendCoder: planned(BackendCoder, "Coder", "P7", vocab.ClassNone, vocab.LocationRemote,
		[]HostKind{HostRemote}, "class depends on the template; speaks REST and WebSocket (codersdk is AGPL, never imported)", false),
	// The three hosted rows of lane SBX-P7 (operator ruling P-080): real
	// drivers, opt-in (each its own component, inactive in every distro) and
	// beta (Verification doc) until a live receipt, so P-062 keeps an
	// automatic choice from picking one. The vendor facts behind each field
	// are internal/sandboxremote's vendor table, grounded per call in
	// docs/sandboxed-terminals.md "Hosted sandboxes".
	BackendE2B: hostedRow(Capability{
		ID: BackendE2B, Label: "E2B",
		// Firecracker microVMs, documented by the vendor (another kernel).
		Iso:     Isolation{Class: vocab.ClassHWVM},
		Control: Control{Interface: InterfaceConnectRPC, Stability: StabilityVendorStable, Pins: DriverPins{RequiredMin: "2", TestedLow: "2", TestedHigh: "2"}},
		// The PTY is envd's own (process Start with a pty, Update to
		// resize), and Connect by pid re-attaches after a dropped stream.
		Term: Terminal{PTYOwner: PTYBackendExec, Resize: ResizeBackendAPI, Reattach: ReattachBackendNative, RelayReattach: RelaySeparateStream, Transport: TransportConnectStream},
		Net: hostedNet(
			// E2B documents refusing private and link-local ranges outside
			// the guest for every sandbox, but the 2026-10-23 live run got an
			// answer from 169.254.169.254 inside the box: claimed, and
			// disclosed on the consent screen (sandboxremote NetworkNotes).
			vocab.SourceClaimed),
		LifetimeCapSeconds: 3600,
		Note:               "E2B Firecracker microVMs on E2B's machines, through E2B's REST API and envd's Connect process API from Go (no SDK); beta: built from E2B's documentation, first live run 2026-10-23 (register REM-1 to REM-12). The run's workspace is uploaded after consent; hooks reach this daemon through the relay over a second exec stream. In that live run the metadata address 169.254.169.254 answered inside the box on proxy_only and internet: that is E2B's own network, outside Observer's control.",
	}, 3600),
	BackendModal: hostedRow(Capability{
		ID: BackendModal, Label: "Modal",
		// gVisor, documented by the vendor (sandboxes guide, Runtimes); the
		// driver asks for it explicitly.
		Iso: Isolation{Class: vocab.ClassUserspaceKernel},
		// Modal's own Go SDK (pure Go, Apache-2.0), because Modal documents
		// no HTTP route and declares its gRPC private; pre-1.0, so preview.
		Control: Control{Interface: InterfaceGoSDK, Stability: StabilityVendorPreview, Pins: DriverPins{RequiredMin: "0.11.1", TestedLow: "0.11.1", TestedHigh: "0.11.1"}},
		// No documented resize or reattach: the guest helper owns the PTY
		// and applies sizes from the relay's control stream; a cut
		// transport ends the run and native resume applies (A7). The guest
		// helper's own kept-PTY re-adoption (lane SBX-UPD) is built but held
		// off on this row (sandboxremote Vendor.GuestReattach false) until
		// REM-13 is checked live, so "no reattach" is what a run gets today.
		Term:               Terminal{PTYOwner: PTYGuestHelper, Resize: ResizeGuest, Reattach: ReattachNone, RelayReattach: RelaySeparateStream, Transport: TransportExecStdio},
		Net:                hostedNet(vocab.SourceClaimed),
		LifetimeCapSeconds: 86400,
		Note:               "Modal sandboxes (gVisor) on Modal's machines, through Modal's Go SDK; beta: built from Modal's documentation and SDK source, never run with a key (register REM-1 to REM-12). No reattach: a cut connection ends the run and the agent's native resume applies.",
	}, 86400),
	BackendVercelSandbox: hostedRow(Capability{
		ID: BackendVercelSandbox, Label: "Vercel Sandbox",
		// Firecracker microVMs with a dedicated kernel, documented.
		Iso:     Isolation{Class: vocab.ClassHWVM},
		Control: Control{Interface: InterfaceRESTRemote, Stability: StabilityVendorStable, Pins: DriverPins{RequiredMin: "2", TestedLow: "2", TestedHigh: "2"}},
		// Only a stdin pipe is documented (the /interactive WebSocket is SDK
		// source only): the guest helper owns the PTY. No vendor reattach;
		// the guest helper's kept-PTY re-adoption (lane SBX-UPD) is held off
		// on this row too (Vendor.GuestReattach false) until REM-13.
		Term:               Terminal{PTYOwner: PTYGuestHelper, Resize: ResizeGuest, Reattach: ReattachNone, RelayReattach: RelaySeparateStream, Transport: TransportExecStdio},
		Net:                hostedNet(vocab.SourceClaimed),
		LifetimeCapSeconds: 2700,
		Note:               "Vercel Sandbox Firecracker microVMs on Vercel's machines, through Vercel's REST API from Go (no SDK); beta: built from Vercel's documentation, never run with a key (register REM-1 to REM-12). A Hobby plan caps a box at 45 minutes; no reattach.",
	}, 2700),
	BackendK8sAgentSandbox: planned(BackendK8sAgentSandbox, "Kubernetes agent-sandbox", "P7", vocab.ClassNone, vocab.LocationRemote,
		[]HostKind{HostRemote}, "class is the RuntimeClass's (gVisor or Kata); org provisioned", false),
	BackendAgentCore: planned(BackendAgentCore, "AWS Bedrock AgentCore Runtime", "P7", vocab.ClassHWVM, vocab.LocationRemote,
		[]HostKind{HostRemote}, "org provisioned; managed and full distros only", false),
}

// planned builds a row that is not offered yet: the class, location and
// hosts are what section 4.9 records; every capability the phase grounds
// stays at its honest zero.
func planned(id, label, phase string, class vocab.IsoClass, loc vocab.Location, hosts []HostKind, note string, explicitOnly bool) Capability {
	c := Capability{
		ID: id, Label: label, Maturity: MaturityPlanned, Phase: phase,
		Iso:          Isolation{Class: class, ClassSource: vocab.SourceClaimed, Location: loc, Tenancy: TenancyPerRun, Hosts: hosts},
		ReadBack:     ReadBackNone,
		ExplicitOnly: explicitOnly,
		Note:         "planned for " + phase + ": " + note,
	}
	if loc == vocab.LocationRemote {
		c.Discloses = []Disclosure{DiscloseDataLeaves, DiscloseAccountLogin}
	}
	return c
}

// hostedDocSource names the grounding of the hosted rows.
const hostedDocSource = "the vendors' public API documentation read 2026-10-22 (docs/sandboxed-terminals.md \"Hosted sandboxes\", the endpoint tables); internal/sandboxremote recorded-response and httptest fake tests"

// hostedRegister names the register rows the hosted rows owe.
const hostedRegister = "REM-1 to REM-12 (docs/sandboxed-terminals.md, the hosted register)"

// hostedRow completes a hosted row (lane SBX-P7): preview, beta on the
// hosts whose daemon can run the driver's host services (Linux and WSL2),
// a documented remote class read from the provider's own description, the
// relay as the hook path, and the remote disclosures.
func hostedRow(c Capability, lifetime int) Capability {
	c.Maturity, c.Phase = MaturityPreview, "P7"
	c.Verification = []Verified{
		{Host: HostLinux, Kind: vocab.VerifiedDoc, Source: hostedDocSource, Date: "2026-10-22", RegisterRef: hostedRegister},
		{Host: HostWSL2, Kind: vocab.VerifiedDoc, Source: hostedDocSource, Date: "2026-10-22", RegisterRef: hostedRegister},
	}
	c.Iso.ClassSource, c.Iso.Location, c.Iso.Tenancy = vocab.SourceDocumented, vocab.LocationRemote, TenancyPerRun
	c.Iso.Hosts = []HostKind{HostLinux, HostWSL2}
	c.Iso.CrossesKernel = true
	c.Capture = Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay, Relay: RelayExecStdio}
	c.ReadBack = ReadBackProvider
	c.LifetimeCapSeconds = lifetime
	c.Discloses = []Disclosure{DiscloseDataLeaves, DiscloseAccountLogin, DisclosePaidTier}
	return c
}

// hostedNet is a hosted row's network: the provider enforces every tier
// (block-all for none and proxy_only, its own allow-all for internet, the
// relay carrying the model proxy), the host tier is absent, and internet
// means the shipped tier only where the vendor documents refusing private
// and metadata ranges (internetSource).
func hostedNet(internetSource vocab.ClassSource) Network {
	return Network{
		Egress:   []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
		Enforcer: EnforcerProvider,
		EgressSource: map[vocab.Tier]vocab.ClassSource{
			vocab.TierInternet: internetSource, vocab.TierProxyOnly: vocab.SourceDocumented, vocab.TierNone: vocab.SourceDocumented,
		},
		// provider_injected stays out until a vendor documents it cleanly.
		KeyCustody: []vocab.KeyCustody{vocab.CustodyHomeRelay, vocab.CustodyInBoxAPIKey, vocab.CustodyInBoxOAuthSeed},
	}
}

// connectors is the connector table (section 4.1).
var connectors = map[string]Connector{
	ConnectorSSH: {
		ID: ConnectorSSH, Reaches: []string{BackendCodespaces}, Tunnel: "gh",
		Note: "planned for P7: the pure-Go SSH client; reaches GitHub Codespaces through `gh codespace ssh`",
	},
}

// Get returns the row for id.
func Get(id string) (Capability, bool) {
	c, ok := registry[id]
	return c, ok
}

// IDs returns every row id, sorted.
func IDs() []string {
	out := make([]string, 0, len(registry))
	for id := range registry {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Offered returns the rows a picker, probe or selector may show, sorted by
// id. Planned rows are never in it.
func Offered() []Capability {
	var out []Capability
	for _, id := range IDs() {
		if c := registry[id]; c.Offered() {
			out = append(out, c)
		}
	}
	return out
}

// Connectors returns the connector rows, sorted by id.
func Connectors() []Connector {
	ids := make([]string, 0, len(connectors))
	for id := range connectors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Connector, 0, len(ids))
	for _, id := range ids {
		out = append(out, connectors[id])
	}
	return out
}
