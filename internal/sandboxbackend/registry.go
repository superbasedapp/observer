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
	// BackendOpenShell is the OpenShell row (OpenShell plan doc 04 R2.5,
	// build plan 05 section 2, lane O1A): a container under OpenShell's
	// supervisor, external gateway mode, explicit-only and preview.
	BackendOpenShell = "openshell"
	// BackendOpenShellOrg is the org-hosted OpenShell row (tracker F-019,
	// docs/plans/openshell/build/g1-design.md section 3.1, lane G4): a box
	// on the organization's own OpenShell gateway, reached through the
	// org's validating front. Explicit-only and preview; offered only on a
	// managed node whose verified sandbox body publishes the gateway.
	BackendOpenShellOrg = "openshell-org"
	// BackendDockerSandboxes is Docker's cloud sandboxes (the Docker
	// Agentic Platform's Sandboxes API; lane SBX-DOCKER): a hosted row,
	// opt-in and beta. Docker's local `sbx` microVMs are a different
	// product and no row here.
	BackendDockerSandboxes = "docker-sandboxes"
	// BackendInstaBox is the InstaBox hosted row (instabox.sh): beta, a
	// Linux VM on InstaBox's machines, internet tier only.
	BackendInstaBox = "instabox"
	// BackendDaytona is Daytona Cloud, a hosted row: REST plus its
	// SSH access tokens through the pure-Go SSH transport (sandbox plan v2's
	// Daytona row), beta until a live receipt.
	BackendDaytona = "daytona"
)

// ConnectorSSH is the SSH connector id.
const ConnectorSSH = "ssh"

// setupBetaWindowsPro is the setup beta sentence (operator ruling P-256):
// Windows 11 Pro is the host whose setup is not checked live in the
// sandbox installation lifecycle arc.
const setupBetaWindowsPro = "Setup on Windows 11 Pro is beta: it has not been checked on a live host yet."

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

// refusalAuditLinux grounds RefusalAuditTiers on the Linux rows (lanes N1, N4):
// one gateway builder for the bwrap, oci and microVM host helpers and the
// re-adopt helper, whose Report sends each refusal on the run's relay link;
// every launch path of these rows writes the run's relay record and passes
// its run id to the host helper, which fails the launch when it cannot serve
// the relay.
const refusalAuditLinux = "cmd/observer/sandbox_helpers_linux.go hostEgressGateway (startHostServices; sandbox_readopt_helper_linux.go) and sandbox_egress_refusal_report.go; tests TestLaunchHelperRefusalsLand, TestReadoptGatewayRefusalsStillLand, TestEgressRefusalSinkReachesTheStore, TestEveryLocalGatewayReportsRefusals"

// refusalAuditOCIInstall is what the OCI rows add: the first-start install
// step's gateway (a setup container that installs the tool, before the
// agent's container exists) answers its refusals on the terminal only; the
// agent's own run reports its refusals (N1 audit finding N1-A11).
const refusalAuditOCIInstall = "; the first-start install step's setup container is not audited (terminal_sandbox_oci_install_linux.go, N1-A11): the agent never runs there"

// refusalAuditMac grounds RefusalAuditTiers on the two macOS rows: one gateway in
// the shared macOS host helper.
const refusalAuditMac = "cmd/observer/terminal_sandbox_macdriver_darwin.go (the Seatbelt and Apple container helper's gateway, Report from sandboxEgressRefusalSink); test TestEveryLocalGatewayReportsRefusals; live register N4-L1"

// refusalAuditMXC grounds RefusalAuditTiers on the MXC ProcessContainer row.
const refusalAuditMXC = "cmd/observer/terminal_sandbox_mxc_run.go mxcGatewayFor (Report from sandboxEgressRefusalSink over the relay's named pipe); test TestEveryLocalGatewayReportsRefusals; live register N4-L1"

// refusalAuditOpenShell grounds RefusalAuditTiers on the OpenShell row (lane
// O3): OpenShell's proxy denies every connection no network rule allows and
// exports the denial as an OCSF event over OTLP; the daemon's loopback
// receiver maps each one of a run's box into the refusal audit, and an
// internet launch is refused when the gateway does not export them.
const refusalAuditOpenShell = "internal/sandboxopenshell/ocsf.go (the OCSF-to-refusal table) and cmd/observer/terminal_sandbox_openshell_egress*.go (the loopback receiver and the launch refusal); tests TestOCSFMappingRows, TestOpenShellOCSFReachesTheSink; live register O3-L1"

// openShellReceipt names the live grounding of the OpenShell row's
// mechanisms: lane O0's GO receipt on native Linux (OpenShell v0.1.6 CLI and
// gateway, Ubuntu 24.04, kernel 6.8, Landlock ABI 4, rootful Docker 29.9.2
// with runc on libseccomp 2.5.5).
const openShellReceipt = "_spikes/openshell/receipts/linux-2026-10-31-f04566.json (docs/plans/openshell/build/o0-receipts.md \"Live receipts\" and \"Verdict\"); internal/sandboxopenshell golden and table tests"

// openShellOwed names the live checks the OpenShell row still owes: the
// driver itself (lane O1B) has not run on a host yet.
const openShellOwed = "OpenShell O1B live checks (docs/plans/openshell/build/live-register.md)"

// OpenShellWSL2Refusal is the openshell row's reason for not running on
// WSL2: the one source of the string, read by the selector's platform rule
// S3 (through the row's HostRefusals) and by the openshell probe's P1.
const OpenShellWSL2Refusal = "OpenShell runs on native Linux only: on WSL2 the box fails closed at supervisor start (Landlock under Docker's default seccomp profile answers ENOSYS)"

// registry is the table. Adding a backend is adding a row (plus its id
// constant, its component row and its config rows, section 11.3).
var registry = map[string]Capability{
	BackendBwrap: {
		ID: BackendBwrap, Label: "Bubblewrap", Maturity: MaturityShipped, Phase: "P1a",
		Setup: []string{"bwrap", "userns"},
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
			// Observer's profile through bwrap --seccomp when
			// [terminal.sandbox].seccomp is on; the host helper reads it
			// back from /proc and refuses a run that lacks it (lane N2).
			// documented, not measured (audit N2-A5, lane FU4): the read-back
			// is wired, but no end-to-end bwrap run has read the filter back
			// yet (bwrap was not installed where lane N2 ran), and that read
			// happens after the box is released, not before the agent runs.
			// It moves to measured with the N2-L1 receipt.
			Seccomp: vocab.SeccompObserverProfile, SeccompSource: vocab.SourceDocumented,
			// --unshare-pid, emitted on every plan (internal/sandbox
			// BuildPlan); the host helper checks the command carries it
			// before it lifts PTRACE_SEIZE (sandbox.BwrapUnsharesPID).
			OwnPIDNamespace: true,
			// The SecretMask option of the plan hides workspace secret
			// files behind /dev/null (internal/sandbox secretmask.go); the
			// other rows have no such planner.
			MasksWorkspaceSecrets: true,
		},
		Control: Control{
			Interface: InterfaceCLI, Stability: StabilityVendorStable,
			Pins: DriverPins{RequiredMin: "0.4.0", TestedLow: "0.4.0", TestedHigh: "0.13.1"},
		},
		Term: Terminal{PTYOwner: PTYHost, Resize: ResizeHostPTY, Reattach: ReattachDaemonOnly, RelayReattach: RelayNotNeeded},
		Net: Network{
			Egress:   []vocab.Tier{vocab.TierHost, vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer: EnforcerObserverGateway,
			// Not host: that tier shares the host network and starts no
			// gateway (internal/sandbox egressProfiles), so nothing is
			// refused or recorded there (audit finding N4-A1).
			RefusalAuditTiers:  []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			RefusalAuditSource: refusalAuditLinux,
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
		// --unshare-pid and --die-with-parent (cmd/observer
		// terminal_sandbox.go): the box's processes stay under its root.
		TreeContained: true,
		Note:          "Linux and WSL2 only; same kernel, so hooks write the home database directly through the ~/.observer bind until the P2 relay.",
	},
	BackendProcessLite: {
		ID: BackendProcessLite, Label: "Landlock only", Maturity: MaturityPreview, Phase: "P3",
		Setup: []string{"landlock-abi"},
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
			// Observer's profile, loaded by the exec step after
			// no_new_privs when [terminal.sandbox].seccomp is on, and read
			// back from /proc by the step and the host helper (lane N2).
			// measured: the kernel test (TestSeccompKernelEPERM) loads the
			// program in a re-exec'd step and reads it back before the
			// agent's exec, on a 6.18 amd64 kernel.
			Seccomp: vocab.SeccompObserverProfile, SeccompSource: vocab.SourceMeasured,
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
			// The TCP rules allow every port but Observer's own listeners
			// (cmd/observer landlockListeners), the dashboard included.
			DeniesObserverPorts: true,
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
		Setup: []string{"container-engine", "engine-socket", "docker-group", "oci-image"},
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
			// The engine's default profile; the read-back refuses a
			// container whose seccomp is unconfined (sandboxoci.ReadBack).
			Seccomp: vocab.SeccompEngineDefault, SeccompSource: vocab.SourceMeasured,
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
			Egress:             []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer:           EnforcerObserverGateway,
			RefusalAuditTiers:  []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			RefusalAuditSource: refusalAuditLinux + refusalAuditOCIInstall,
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
		Setup: []string{"docker-engine", "docker-group", "oci-allow-rootful", "runsc", "runsc-registered", "oci-image"},
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
			// The engine's default profile, read back as for runc (the
			// same sandboxoci.ReadBack row).
			Seccomp: vocab.SeccompEngineDefault, SeccompSource: vocab.SourceMeasured,
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
			Egress:             []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer:           EnforcerObserverGateway,
			RefusalAuditTiers:  []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			RefusalAuditSource: refusalAuditLinux + refusalAuditOCIInstall,
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
		Setup: []string{"kvm-device", "kvm-group", "cloud-hypervisor", "virtiofsd", "bwrap", "e2fsprogs", "vm-image-set"},
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
			Egress:             []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer:           EnforcerObserverGateway,
			RefusalAuditTiers:  []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			RefusalAuditSource: refusalAuditLinux,
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
		Note: "Linux and WSL2 with a usable /dev/kvm (nested virtualisation inside a VM), through Cloud Hypervisor 54's REST API on a unix socket; each run is its own microVM with no network device, booted from Observer's signed guest image set (sandbox.rootfs and sandbox.guest_binary, imported from a folder with \"Import image set\" on Terminals > Settings > Sandbox (the microVM panel) or `observer sandbox content import`). Beta: built and unit-tested without /dev/kvm; its live runs are owed (register LIN-2 onward).",
	},
	BackendSeatbelt: {
		ID: BackendSeatbelt, Label: "macOS Seatbelt", Maturity: MaturityPreview, Phase: "P5",
		Setup: []string{"macos-12", "macos-sandbox-exec"},
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
			Egress:             []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer:           EnforcerObserverGateway,
			RefusalAuditTiers:  []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			RefusalAuditSource: refusalAuditMac,
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
		Setup: []string{"macos-26-arm", "apple-container-cli", "apple-container-service", "apple-container-image"},
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
			Egress:             []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer:           EnforcerObserverGateway,
			RefusalAuditTiers:  []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			RefusalAuditSource: refusalAuditMac,
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
		Setup: []string{"win-build-psec", "mxc-files"},
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
			Egress:             []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer:           EnforcerObserverGateway,
			RefusalAuditTiers:  []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			RefusalAuditSource: refusalAuditMXC,
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
		Setup: []string{"win-build-psec", "mxc-files"},
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
		SetupUnavailable: "how the wslc CLI is distributed is not determined yet, so setup cannot name its install step",
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
		SetupUnavailable: "no utility VM image is published for Hyper-V isolated containers yet, so a setup could never finish",
		SetupBeta:        setupBetaWindowsPro,
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
	// openshell (OpenShell plan doc 04 R2.5, build plan 05 section 2, lane
	// O1A): one more container row whose sandbox OpenShell's gateway and
	// supervisor run (Docker driver), external gateway mode: the user
	// installs, starts and authenticates their own gateway. Preview and
	// explicit-only (rule S1b): never picked for an automatic request or the
	// guard's enforce auto-upgrade. Linux only: on WSL2 the box fails closed
	// at supervisor start (O0 receipt wsl2-2026-10-31-8a047f, RK-02).
	BackendOpenShell: {
		ID: BackendOpenShell, Label: "OpenShell", Maturity: MaturityPreview, Phase: "O1",
		Setup: []string{"landlock-abi", "docker-engine", "docker-group", "openshell-pkg", "openshell-supervisor"},
		// doc: the mechanisms (same-path binds, the nested read-only bind,
		// the tmpfs home with mode 01777, unix sockets across the seccomp
		// broker, PTY resize and exit through the CLI, the label reap) were
		// measured by lane O0's harness; the driver (lane O1B) owes its own
		// live runs.
		Verification: []Verified{
			{Host: HostLinux, Kind: vocab.VerifiedDoc, Source: openShellReceipt, Date: "2026-10-31", RegisterRef: openShellOwed},
		},
		Iso: Isolation{
			// documented: OpenShell runs the workload in a Docker container
			// (network none) under Landlock and its own seccomp filter, but no
			// product read-back of the built box exists yet, so the class is
			// never measured.
			Class: vocab.ClassContainer, ClassSource: vocab.SourceDocumented,
			Location: vocab.LocationLocal, Tenancy: TenancyPerRun,
			Hosts: []HostKind{HostLinux},
			// WSL2 is refused by the selector's platform rule S3 with this
			// row's own reason (live check O5-L2, 2026-11-01): S3 answers
			// before the openshell probe's P1 runs, so the reason lives here.
			HostRefusals: map[HostKind]string{HostWSL2: OpenShellWSL2Refusal},
		},
		Control: Control{
			// The CLI with fixed argv (O0 R5 passed through both the CLI and
			// the Go SDK; the CLI is the plan default, no new go.mod
			// dependency). Pre-1.0 with breaking changes in patches: preview.
			// The version is trusted only from the authenticated gateway's
			// own status answer; the tested-version table is
			// internal/sandboxopenshell's.
			Interface: InterfaceCLI, Stability: StabilityVendorPreview,
			Pins: DriverPins{RequiredMin: "0.1.6", TestedLow: "0.1.6", TestedHigh: "0.1.6", RequireAuthenticatedVersion: true},
		},
		// The CLI runs under the daemon's PTY and the agent's TTY is the
		// sandbox exec's; `sandbox create --tty` forwards SIGWINCH as a
		// resize on the exec stream (O0 R5: sizes 40x100 then 50x132, exact
		// exit codes). No reattach: killing the client leaves the box
		// running (O0 R6), so the run ends and the labelled reaper (lane
		// O1B) removes it.
		Term: Terminal{PTYOwner: PTYBackendExec, Resize: ResizeBackendAPI, Reattach: ReattachNone, RelayReattach: RelayNotNeeded},
		Net: Network{
			// OpenShell's own proxy is the one egress owner on every tier
			// (rule W4): Observer's egress gateway never runs beside it. On
			// proxy_only and none the policy has no network rule, so all
			// egress is denied; the model proxy and the hooks reach the
			// daemon only through the capture relay over the same-path bind
			// of the per-run socket dir (O0 R2). On internet the network
			// rule compiler (internal/sandboxopenshell netrules.go, lane O3)
			// maps the host allow-list, the private ranges and the
			// provider-host block onto OpenShell's rules; a run with no host
			// list is refused (OpenShell cannot express every public host),
			// and a model provider's host is never listed.
			Egress:   []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			Enforcer: EnforcerOpenShellProxy,
			EgressSource: map[vocab.Tier]vocab.ClassSource{
				vocab.TierInternet: vocab.SourceDocumented, vocab.TierProxyOnly: vocab.SourceDocumented, vocab.TierNone: vocab.SourceDocumented,
			},
			// Every tier: proxy_only and none leave no way out but the relay,
			// and an internet launch is refused unless the gateway exports
			// OpenShell's OCSF events to Observer's loopback receiver, which
			// maps each denied connection into the refusal audit (lane O3).
			RefusalAuditTiers:  []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			RefusalAuditSource: refusalAuditOpenShell,
			// The tool state is bound like the OCI rows' (host_bound); the
			// relay's credential custody is internal/sandboxcred's (rule W6).
			KeyCustody: []vocab.KeyCustody{vocab.CustodyHostBound, vocab.CustodyHomeRelay},
		},
		// Same kernel, but the box never sees observer.db: hooks reach the
		// daemon through the capture relay's bound socket dir (rule W5).
		Capture:      Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay},
		ReadBack:     ReadBackNone,
		ExplicitOnly: true,
		// cli_telemetry: OpenShell's telemetry is on by default upstream and
		// an external gateway is the user's, so Observer reports it as
		// unknown. gateway_wide_bind_mounts: decision D3. home_shared_tmpfs:
		// F-017 A4.
		// The managed gateway's PKI and key-encryption key (custody
		// keychain); the driver pins it equal to its planner's constant.
		KeystoreServices: []string{"sbo-openshell-gateway-v1"},
		Discloses:        []Disclosure{DiscloseCLITelemetry, DiscloseGatewayBindMounts, DiscloseSharedHomeTmpfs},
		Note:             "Linux only, beta and used only when chosen by name: the run's container is built by your own OpenShell gateway (v0.1.6, Docker driver), which you install, start and sign in to yourself. The gateway must allow driver config and bind mounts for every sandbox it runs (allow_driver_config and enable_bind_mounts). No network but the run's own sockets on proxy_only and none; on internet only the hosts of egress_allow_hosts (never a model provider's), and only when the gateway exports its OCSF events to Observer's loopback receiver. On WSL2 the box fails closed at supervisor start. The driver's live runs are owed.",
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
	// openshell-org (tracker F-019, g1-design.md section 3.1, lane G4): the
	// fourth hosted row, whose "vendor" is the organization's own OpenShell
	// gateway reached through the org's validating front. Built with
	// hostedRow and then overridden where hostedRow does not fit
	// (orgHostedRow): phase G, no paid tier (the org pays), two org
	// disclosures, explicit-only. Selection, the picker, posture and the
	// guard read the fields, never the id.
	BackendOpenShellOrg: orgHostedRow(Capability{
		ID: BackendOpenShellOrg, Label: "OpenShell (org-hosted)",
		Setup: []string{"orgshell-login"},
		// documented: the Docker driver's container. An org's declared
		// userspace_kernel class is a per-run overlay with source claimed,
		// recorded in the run's evidence, never this static value.
		Iso: Isolation{Class: vocab.ClassContainer},
		// The tagged Go module's public generated openshellv1 client (no
		// vendored code, W9); the version is the front's report of the
		// gateway's own answer.
		Control: Control{Interface: InterfaceGoSDK, Stability: StabilityVendorPreview, Pins: DriverPins{RequiredMin: "0.1.6", TestedLow: "0.1.6", TestedHigh: "0.1.6", RequireAuthenticatedVersion: true}},
		// The agent's PTY is the gateway's interactive exec with a TTY; the
		// relay is a second, TTY-off interactive exec (G-L2 verdict
		// tty_false, OB-079). No reattach: a cut stream ends the in-box
		// process, and the org's hold policy decides what happens to the box.
		Term: Terminal{PTYOwner: PTYBackendExec, Resize: ResizeBackendAPI, Reattach: ReattachNone, RelayReattach: RelaySeparateStream, Transport: TransportExecStdio},
		Net: Network{
			Egress: []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone},
			// W4: the org gateway's supervisor proxy is the one egress owner.
			Enforcer: EnforcerOpenShellProxy,
			EgressSource: map[vocab.Tier]vocab.ClassSource{
				vocab.TierInternet: vocab.SourceDocumented, vocab.TierProxyOnly: vocab.SourceDocumented, vocab.TierNone: vocab.SourceDocumented,
			},
			// Empty in v1: denials happen on the org's machine and are not
			// carried to the node (section 6.4), so require_refusal_audit
			// refuses this row, honestly.
			// home_relay only: no model key on org compute. The org's git
			// credential is not a model-key custody (section 3.1).
			KeyCustody: []vocab.KeyCustody{vocab.CustodyHomeRelay},
		},
		LifetimeCapSeconds: 7200,
		ExplicitOnly:       true,
		// The sign-in grant handle (section 5.3).
		KeystoreServices: []string{"sbo-openshell-org-grant-v1"},
		Note:             "Beta, used only when chosen by name, and offered only when your organization publishes its own OpenShell gateway to this managed machine: the box runs on your organization's machines, through its validating front, and its administrators can see into it. Your workspace is uploaded (clone-local) or cloned in the box (clone-remote); hooks and model requests travel back through this laptop, which must stay online for the run, and only after you opt in to that. Box lifetime is at most 120 minutes, or your organization's lower cap.",
	}),
	BackendK8sAgentSandbox: planned(BackendK8sAgentSandbox, "Kubernetes agent-sandbox", "P7", vocab.ClassNone, vocab.LocationRemote,
		[]HostKind{HostRemote}, "class is the RuntimeClass's (gVisor or Kata); org provisioned", false),
	BackendAgentCore: planned(BackendAgentCore, "AWS Bedrock AgentCore Runtime", "P7", vocab.ClassHWVM, vocab.LocationRemote,
		[]HostKind{HostRemote}, "org provisioned; managed and full distros only", false),
	// docker-sandboxes (lane SBX-DOCKER): Docker's cloud sandboxes through
	// the Sandboxes API from Go (no SDK, no CLI). Built with hostedRow, then
	// dockerHostedRow records its own grounding date and the class source.
	BackendDockerSandboxes: dockerHostedRow(hostedRow(Capability{
		ID: BackendDockerSandboxes, Label: "Docker Sandboxes",
		// Docker documents hypervisor microVMs for its local sandboxes and
		// says nothing of the cloud ones' isolation: hw_vm, claimed
		// (dockerHostedRow).
		Iso: Isolation{Class: vocab.ClassHWVM},
		// The REST API is v1 and labelled experimental by Docker; an offered
		// row may not sit on an experimental surface, so it is preview (the
		// pre-1.0 Modal SDK precedent) and stays beta until a live receipt.
		Control: Control{Interface: InterfaceRESTRemote, Stability: StabilityVendorPreview, Pins: DriverPins{RequiredMin: "1", TestedLow: "1", TestedHigh: "1"}},
		// The interactive process API documents a PTY, a resize frame and a
		// resume from a stream sequence over one WebSocket per process; the
		// relay is a second, pipe process on its own stream.
		Term:               Terminal{PTYOwner: PTYBackendExec, Resize: ResizeBackendAPI, Reattach: ReattachBackendNative, RelayReattach: RelaySeparateStream, Transport: TransportWebSocketStream},
		Net:                hostedNet(vocab.SourceClaimed),
		LifetimeCapSeconds: 86400,
		Note:               "Docker's cloud sandboxes (Docker Agentic Platform) on Docker's machines, through Docker's Sandboxes API (v1, experimental) from Go (no SDK); beta: built from Docker's documentation and API reference; a client-level live smoke on 2026-11-11 created, drove and deleted three boxes, but the hosted register (REM-1 to REM-12) has not been run. The internet tier follows your Docker account's own default network policy.",
	}, 86400)),
	// InstaBox (instabox.sh): a hosted row like the three of lane SBX-P7,
	// built from InstaBox's own docs (instaBoxRow); internet tier only,
	// because InstaBox documents no network policy.
	BackendInstaBox: instaBoxRow(),
	// Daytona (a hosted row): the vendor facts behind each field
	// are internal/sandboxremote's vendor table, grounded per call in
	// docs/sandboxed-terminals.md "Hosted sandboxes" (Daytona).
	BackendDaytona: datedHostedRow(Capability{
		ID: BackendDaytona, Label: "Daytona",
		// The default sandbox class is a container (the API's SandboxClass
		// enum: container, linux-vm, windows; VM sandboxes start only from
		// VM snapshots). The driver asks for no VM snapshot, so the row is
		// the container class (plan v2 section 4.2: another class would be
		// another row).
		Iso: Isolation{Class: vocab.ClassContainer},
		// The main API (OpenAPI info.version 1.0) for the lifecycle and the
		// toolbox for files; processes run on exec channels over Daytona's
		// SSH access tokens (golang.org/x/crypto/ssh, no SDK).
		Control: Control{Interface: InterfaceRESTRemote, Stability: StabilityVendorStable, Pins: DriverPins{RequiredMin: "1", TestedLow: "1", TestedHigh: "1"}},
		// The PTY Daytona documents is a WebSocket whose framing the docs do
		// not give: the guest helper owns the PTY over an exec channel. No
		// vendor reattach; the guest helper's kept-PTY re-adoption is held
		// off (Vendor.GuestReattach false) until REM-13.
		Term:               Terminal{PTYOwner: PTYGuestHelper, Resize: ResizeGuest, Reattach: ReattachNone, RelayReattach: RelaySeparateStream, Transport: TransportExecStdio},
		Net:                hostedNet(vocab.SourceClaimed),
		LifetimeCapSeconds: 86400,
		Note:               "Daytona sandboxes (containers) on Daytona's machines, through Daytona's REST API and SSH access from Go (no SDK); beta: built from Daytona's documentation; one client-level smoke ran with a key on 2026-11-11, the register (REM-1 to REM-12 and REM-DAY-1 to REM-DAY-3) is owed. On the internet tier the box's network is your Daytona organization's tier policy (essential services only on Tier 1 and 2). No reattach.",
	}, 86400, daytonaDocSource, "2026-11-11"),
}

// dockerSourceDocs names the grounding of the docker-sandboxes row.
const dockerSourceDocs = "Docker's Sandboxes API reference (api.yaml, v1) and the Docker Sandboxes docs read 2026-11-11 (docs/sandboxed-terminals.md \"Hosted sandboxes\", Docker Sandboxes); internal/sandboxremote/dockersbx httptest fake tests"

// dockerHostedRow completes the docker-sandboxes row from hostedRow without
// changing hostedRow itself: its own grounding date and source, and the
// isolation class claimed, because Docker documents the cloud sandboxes'
// isolation nowhere (only the local sandboxes' microVMs).
func dockerHostedRow(c Capability) Capability {
	c.Verification = []Verified{
		{Host: HostLinux, Kind: vocab.VerifiedDoc, Source: dockerSourceDocs, Date: "2026-11-11", RegisterRef: hostedRegister},
		{Host: HostWSL2, Kind: vocab.VerifiedDoc, Source: dockerSourceDocs, Date: "2026-11-11", RegisterRef: hostedRegister},
	}
	c.Iso.ClassSource = vocab.SourceClaimed
	return c
}

// instaBoxDocSource names the grounding of the InstaBox row.
const instaBoxDocSource = "InstaBox's public API documentation and OpenAPI document (api.instabox.sh/v1/openapi.json 1.0.0) read 2026-11-11 (docs/sandboxed-terminals.md \"Hosted sandboxes\", InstaBox); internal/sandboxremote/instabox recorded-response and httptest fake tests; an API-level live smoke of the wire client on 2026-11-11 (no agent run, no relay, so still doc)"

// instaBoxRow is the InstaBox hosted row: hostedRow with its own dated
// grounding and a network that offers the internet tier only (InstaBox
// documents no deny-all or allowlist, so none and proxy_only would be a
// claim nothing enforces).
func instaBoxRow() Capability {
	c := hostedRow(Capability{
		ID: BackendInstaBox, Label: "InstaBox",
		// Firecracker microVMs, documented by the vendor (another kernel).
		Iso: Isolation{Class: vocab.ClassHWVM},
		// REST from Go (no SDK); an invite-gated service: preview.
		Control: Control{Interface: InterfaceRESTRemote, Stability: StabilityVendorPreview, Pins: DriverPins{RequiredMin: "1", TestedLow: "1", TestedHigh: "1"}},
		// No non-PTY exec with a streaming stdin is documented: the relay and
		// the guest helper each ride a terminal WebSocket session whose PTY
		// the start script puts in raw mode (a byte stream of one box
		// process, so exec_stdio). The guest helper owns the agent's PTY; no
		// reattach (a session's replay length is undocumented).
		Term: Terminal{PTYOwner: PTYGuestHelper, Resize: ResizeGuest, Reattach: ReattachNone, RelayReattach: RelaySeparateStream, Transport: TransportExecStdio},
		Net: Network{
			Egress:       []vocab.Tier{vocab.TierInternet},
			Enforcer:     EnforcerProvider,
			EgressSource: map[vocab.Tier]vocab.ClassSource{vocab.TierInternet: vocab.SourceClaimed},
			KeyCustody:   []vocab.KeyCustody{vocab.CustodyHomeRelay, vocab.CustodyInBoxAPIKey, vocab.CustodyInBoxOAuthSeed},
		},
		LifetimeCapSeconds: 28800,
		Note:               "InstaBox Firecracker microVMs on InstaBox's machines, through InstaBox's REST API and terminal WebSocket from Go (no SDK, no SSH); beta: built from InstaBox's documentation; its wire client passed an API-level live smoke on 2026-11-11 (create, exec, files, the raw terminal stream, delete), but no agent has run on the row (register REM-1 to REM-12). Internet tier only: InstaBox documents no way to block a machine's network. The free plan pauses a machine after 30 idle minutes and after 480 minutes of running, which ends the run; no reattach.",
	}, 28800)
	c.Verification = []Verified{
		{Host: HostLinux, Kind: vocab.VerifiedDoc, Source: instaBoxDocSource, Date: "2026-11-11", RegisterRef: hostedRegister},
		{Host: HostWSL2, Kind: vocab.VerifiedDoc, Source: instaBoxDocSource, Date: "2026-11-11", RegisterRef: hostedRegister},
	}
	return c
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
// relay as the hook path, the remote disclosures, and the hosted setup
// list (an account, a key, a consent).
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
	c.Discloses = []Disclosure{DiscloseDataLeaves, DiscloseAccountLogin, DisclosePaidTier, DiscloseNoHookGating}
	c.Setup = []string{"hosted-account", "hosted-key", "hosted-custody", "hosted-consent"}
	return c
}

// orgHostedVerifySource names the grounding of the org-hosted row.
const orgHostedVerifySource = "docs/plans/openshell/build/g1-design.md (the design of record); OpenShell 0.1.6 live gate G-L1 and G-L2 (decision log OB-077 to OB-079: EdDSA, membership by sub, the TTY-off relay, suspend unsupported); internal/sandboxremote/openshellorg bufconn fake tests"

// orgHostedRegister names the live checks the org-hosted row owes.
const orgHostedRegister = "G-L3 and G-L6 (docs/plans/openshell/build/live-register.md)"

// orgHostedRow completes the org-hosted row from hostedRow (g1-design.md
// section 3.1, G1-A5) without changing hostedRow itself: phase G, a static
// 7200 s lifetime, no paid tier (the org pays, not the developer), the two
// org disclosures, the org's own enforcer and custody (set on c), and the
// live register it owes.
func orgHostedRow(c Capability) Capability {
	net, lifetime, setup := c.Net, c.LifetimeCapSeconds, c.Setup
	c = hostedRow(c, lifetime)
	c.Phase = "G"
	c.Net = net
	c.Verification = []Verified{
		{Host: HostLinux, Kind: vocab.VerifiedDoc, Source: orgHostedVerifySource, Date: "2026-11-03", RegisterRef: orgHostedRegister},
		{Host: HostWSL2, Kind: vocab.VerifiedDoc, Source: orgHostedVerifySource, Date: "2026-11-03", RegisterRef: orgHostedRegister},
	}
	c.Discloses = []Disclosure{DiscloseDataLeaves, DiscloseAccountLogin, DiscloseOrgCompute, DiscloseOrgSharedGateway, DiscloseNoHookGating}
	c.Setup = setup
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

// KeystoreServices returns every row's OS keychain services, sorted and
// without duplicates: what `observer uninstall --all` removes for the
// sandbox drivers, read from the rows' capability fields.
func KeystoreServices() []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range IDs() {
		for _, s := range registry[id].KeystoreServices {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// daytonaDocSource names the grounding of the daytona row.
const daytonaDocSource = "Daytona's public documentation read 2026-11-11 (openapi.json and toolbox-openapi.json at www.daytona.io/docs, the sandboxes, SSH access, network limits, limits and pricing pages; docs/sandboxed-terminals.md \"Hosted sandboxes\", Daytona); internal/sandboxremote/daytona recorded-response, httptest and in-process SSH fake tests"

// daytonaRegister names the register rows the daytona row owes.
const daytonaRegister = "REM-1 to REM-12 and REM-DAY-1 to REM-DAY-3 (docs/sandboxed-terminals.md, the hosted register)"

// datedHostedRow is hostedRow for a hosted row grounded on its own date
// and source (a vendor added after the first three), without changing
// hostedRow itself.
func datedHostedRow(c Capability, lifetime int, source, date string) Capability {
	c = hostedRow(c, lifetime)
	c.Verification = []Verified{
		{Host: HostLinux, Kind: vocab.VerifiedDoc, Source: source, Date: date, RegisterRef: daytonaRegister},
		{Host: HostWSL2, Kind: vocab.VerifiedDoc, Source: source, Date: date, RegisterRef: daytonaRegister},
	}
	return c
}
