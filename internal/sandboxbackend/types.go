package sandboxbackend

import "github.com/marmutapp/superbased-observer/internal/sandboxvocab"

// RegistryVersion moves with every enum or row-shape change.
const RegistryVersion = 12

// Maturity says whether a row may be offered at all.
type Maturity string

// The closed Maturity vocabulary. A planned row is never offered.
const (
	MaturityPlanned Maturity = "planned"
	MaturityPreview Maturity = "preview"
	MaturityShipped Maturity = "shipped"
)

// HostKind is a host a row runs on.
type HostKind string

// The closed HostKind vocabulary. WSL2 is its own host because what the
// daemon can build there differs from native Linux (kernel, KVM, Landlock).
const (
	HostLinux   HostKind = "linux"
	HostWSL2    HostKind = "wsl2"
	HostMacOS   HostKind = "macos"
	HostWindows HostKind = "windows"
	HostRemote  HostKind = "remote"
)

// Verified is one grounding of a row on one host (section 4.2): the kind,
// where the proof is (a live test name or a handover receipt for live, the
// vendor document for doc) and when.
type Verified struct {
	Host   HostKind
	Kind   sandboxvocab.Verification
	Source string
	Date   string
	// RegisterRef names the verification register row still owed (MAC-n,
	// WIN-n, LIN-n) when Kind is not live.
	RegisterRef string
}

// Tenancy says whether one box serves one run.
type Tenancy string

// The closed Tenancy vocabulary. A shared VM is a host substrate, never a
// per-run hw_vm layer.
const (
	TenancyPerRun Tenancy = "per_run"
	TenancyShared Tenancy = "shared"
)

// Isolation is a row's boundary.
type Isolation struct {
	Class       sandboxvocab.IsoClass
	ClassSource sandboxvocab.ClassSource
	Location    sandboxvocab.Location
	Tenancy     Tenancy
	Hosts       []HostKind
	// HostRefusals is the reason a refusal names on a host the row does
	// not run on, when the row knows why (the selector's platform rule S3
	// reads it through HostRefusal). A host absent here gets S3's generic
	// text. Keys are never in Hosts (registry test). Data, so no consumer
	// branches on a backend id to explain a platform refusal.
	HostRefusals map[HostKind]string
	// CrossesKernel: some byte reaches another kernel or a user-space
	// kernel; then the hook path must not be direct_db (invariant I5).
	CrossesKernel bool
	// HostMutation: the row changes the host (a persistent DACL, a firewall
	// rule); such rows are disabled by default and disclose it.
	HostMutation bool
	// Seccomp is the syscall filter the layer can put on the agent (lane
	// N2); SeccompSource says how it is known: measured when an end-to-end
	// run of this row has loaded the filter and read it back from /proc (a
	// test that ran here, or a live receipt); documented when the load and
	// the read-back are wired but no such run has proven them on this row
	// yet. The zero value means not grounded. For SeccompObserverProfile
	// the filter is applied only while [terminal.sandbox].seccomp is on.
	Seccomp       sandboxvocab.Seccomp
	SeccompSource sandboxvocab.ClassSource
	// OwnPIDNamespace: the layer runs the agent in a pid namespace of its
	// own, so a process inside cannot name one outside it. Declared per row,
	// never inferred; the zero value means not grounded. The strace opt-in
	// ([terminal.sandbox].seccomp_allow_seize, lane ptrace) reads it as one
	// of its two containment grounds.
	OwnPIDNamespace bool
	// MasksWorkspaceSecrets: the layer can hide the workspace's secret files
	// (.env variants, key files, registry credentials) inside the box on
	// request, through the pure planner's SecretMask option
	// (internal/sandbox secretmask.go). Declared per row, never inferred;
	// the zero value means the layer cannot, and a caller that wants the
	// mask must fall back to a warning (a launch that asks a row without it
	// is refused, never run unmasked in silence).
	MasksWorkspaceSecrets bool
}

// CanMaskWorkspaceSecrets reports whether the layer can hide the workspace's
// secret files on request: the one predicate a caller reads, never the
// backend name.
func (c Capability) CanMaskWorkspaceSecrets() bool {
	return c.Iso.MasksWorkspaceSecrets
}

// FiltersWithObserverProfile reports whether the layer loads Observer's own
// seccomp profile when [terminal.sandbox].seccomp asks for it: the one
// predicate a driver reads, never its backend name.
func (c Capability) FiltersWithObserverProfile() bool {
	return c.Iso.Seccomp == sandboxvocab.SeccompObserverProfile
}

// Interface is the control surface the driver uses (section 4.8).
type Interface string

// The Interface values the supported set uses.
const (
	InterfaceCLI          Interface = "cli"
	InterfaceEngineAPIUDS Interface = "engine_api_uds"
	InterfaceRESTUDS      Interface = "rest_uds"
	InterfaceRESTRemote   Interface = "rest_remote"
	InterfaceCABILazyDLL  Interface = "c_abi_lazydll"
	InterfaceGoSDK        Interface = "go_sdk"
	InterfaceSSHStdio     Interface = "ssh_stdio"
	InterfaceWebSocket    Interface = "websocket"
	InterfaceInProcess    Interface = "in_process"
	// InterfaceConnectRPC: a vendor's Connect-RPC service over HTTPS (E2B's
	// envd process API, beside its REST control plane; lane SBX-P7).
	InterfaceConnectRPC Interface = "connect_rpc"
)

// Stability is the vendor stability of an interface. "beta" is never a
// Stability: it is only the label of a doc-verified row.
type Stability string

// The closed Stability vocabulary.
const (
	StabilityVendorStable  Stability = "vendor_stable"
	StabilityVendorPreview Stability = "vendor_preview"
	StabilityExperimental  Stability = "experimental"
	StabilityInternal      Stability = "internal"
)

// DriverPins separates the required minimum (below it the driver cannot
// work: refused, S2b) from the tested range (outside it the row is beta for
// that host, never refused).
type DriverPins struct {
	RequiredMin string
	TestedLow   string
	TestedHigh  string
	// RequireAuthenticatedVersion: the row trusts a version only when it is
	// read from an authenticated identity (an engine socket that passed
	// validation, a signed manifest); a bare --version from a PATH binary is
	// not one. A row that needs it refuses an unauthenticated read (S2b).
	RequireAuthenticatedVersion bool
}

// Control is the chosen interface and what it reaches.
type Control struct {
	Interface   Interface
	Stability   Stability
	Pins        DriverPins
	CGORequired bool
}

// PTYOwner says what holds the agent's own TTY inside the box.
type PTYOwner string

// The closed PTYOwner vocabulary.
const (
	PTYHost           PTYOwner = "host_pty"
	PTYBackendMainTTY PTYOwner = "backend_main_tty"
	PTYBackendExec    PTYOwner = "backend_exec"
	PTYGuestHelper    PTYOwner = "guest_helper"
)

// ResizePath is how a resize reaches the agent's TTY.
type ResizePath string

// The closed ResizePath vocabulary. ResizeNone makes a row ineligible for
// an interactive terminal (S11b).
const (
	ResizeHostPTY    ResizePath = "host_pty"
	ResizeBackendAPI ResizePath = "backend_api"
	ResizeGuest      ResizePath = "guest_helper"
	ResizeSSH        ResizePath = "ssh_window_change"
	ResizeNone       ResizePath = "none"
)

// Reattach is how the PTY comes back after a dropped host-to-box transport.
type Reattach string

// The closed Reattach vocabulary.
const (
	ReattachDaemonOnly    Reattach = "daemon_only"
	ReattachBackendNative Reattach = "backend_native"
	ReattachDetachTool    Reattach = "detach_tool"
	ReattachNone          Reattach = "none"
)

// RelayReattach is how the capture relay comes back after the same drop.
type RelayReattach string

// The closed RelayReattach vocabulary. A row whose Reattach survives a drop
// must not declare RelayReattachNone (coverage test).
const (
	RelayNotNeeded      RelayReattach = "not_needed"
	RelaySeparateStream RelayReattach = "separate_stream"
	RelayWithPTY        RelayReattach = "with_pty"
	RelayReattachNone   RelayReattach = "none"
)

// ByteTransport is how the agent's bytes reach the daemon's PTY (section
// 4.2, Terminal.Transport). The zero value means not declared (the rows
// built before lane SBX-P6 leave it so; their transport follows from
// PTYOwner).
type ByteTransport string

// The ByteTransport values declared so far.
const (
	// TransportExecUnderHostConPTY: the backend's own executor runs as a
	// console client of the daemon's ConPTY, so the agent shares that
	// pseudoconsole and its resize and Ctrl-C (section 4.6, revision 4; MXC's
	// wxc-exec, the route Microsoft's own Node SDK takes, here reading its
	// document from an owner-only file).
	TransportExecUnderHostConPTY ByteTransport = "exec_under_host_conpty"
	// TransportConnectStream: a vendor's server-streaming Connect-RPC call
	// carries the box PTY's output, and unary calls carry input and resize
	// (E2B's envd process Start and Connect; lane SBX-P7).
	TransportConnectStream ByteTransport = "connect_stream"
	// TransportExecStdio: a vendor's non-PTY exec stream (stdin and stdout
	// of one box process) carries the bytes of a PTY the box-side guest
	// helper owns, multiplexed with its resize control stream (Modal's exec
	// stdio, Vercel's command logs and stdin; lane SBX-P7).
	TransportExecStdio ByteTransport = "exec_stdio"
	// TransportVsockUDS: the bytes of a PTY the in-guest helper owns cross a
	// microVM's virtio-vsock device, which the VMM exposes on the host as a
	// unix socket (Cloud Hypervisor's hybrid vsock: `CONNECT <port>\n`, then
	// the relay mux's stream 2 with its resize control; lane SBX-P4).
	TransportVsockUDS ByteTransport = "vsock_uds"
	// TransportWebSocketStream: one vendor WebSocket per process carries the
	// box PTY's output and, in the other direction, its input and resize
	// frames, and re-attaches from a stream sequence (Docker Sandboxes'
	// interact stream, subprotocol sandboxes.v1; lane SBX-DOCKER).
	TransportWebSocketStream ByteTransport = "websocket_stream"
)

// RelayTransport is how the capture relay crosses the row's boundary
// (section 5.2, Capture.Relay). The zero value means not declared (the
// bound socket directory of the rows built before lane SBX-P6).
type RelayTransport string

// The RelayTransport values declared so far.
const (
	// RelaySingleLoopbackPortToken: one loopback port per run carries the
	// relay, the model proxy and the egress gateway, each request proving
	// the run's token (MXC allows exactly one loopback proxy endpoint).
	RelaySingleLoopbackPortToken RelayTransport = "single_loopback_port_token"
	// RelayExecStdio: a second, non-PTY exec stream into a remote box runs
	// `observer sandbox-guest --relay-stdio`, which multiplexes the box's
	// proxy, gateway and hook sockets over its stdin and stdout in the
	// relay's authenticated frames; the home side opens it and re-opens it
	// after a drop (section 5.7, lane SBX-P7).
	RelayExecStdio RelayTransport = "exec_stdio"
	// RelayVsockUDS: the relay, the model proxy and the egress gateway ride
	// the relay mux's keyed streams over the VMM's hybrid vsock socket,
	// beside the PTY (the VM has no NIC; lane SBX-P4).
	RelayVsockUDS RelayTransport = "vsock_uds"
)

// Terminal is who owns the PTY and how it survives.
type Terminal struct {
	PTYOwner      PTYOwner
	Resize        ResizePath
	Reattach      Reattach
	RelayReattach RelayReattach
	// Transport is how the agent's bytes reach the PTY (zero: not declared).
	Transport ByteTransport
}

// EgressEnforcer is who enforces a row's egress tier (section 7.1).
type EgressEnforcer string

// The closed EgressEnforcer vocabulary.
const (
	EnforcerObserverGateway EgressEnforcer = "observer_gateway"
	EnforcerProvider        EgressEnforcer = "provider"
	EnforcerK8sPolicy       EgressEnforcer = "k8s_networkpolicy"
	EnforcerNone            EgressEnforcer = "none"
	// EnforcerOpenShellProxy: the OpenShell supervisor's own egress proxy
	// owns the row's network (rule W4 of the OpenShell plan: one egress
	// owner per run, never Observer's gateway beside it). Model hosts are
	// never listed in its rules, so model traffic leaves only through the
	// capture relay to the Observer proxy.
	EnforcerOpenShellProxy EgressEnforcer = "openshell_proxy"
)

// Network is a row's egress.
type Network struct {
	Egress   []sandboxvocab.Tier
	Enforcer EgressEnforcer
	// EgressSource says per tier whether the row's tier really means what
	// the shipped tier means; floors treat claimed as unmet.
	EgressSource map[sandboxvocab.Tier]sandboxvocab.ClassSource
	KeyCustody   []sandboxvocab.KeyCustody
	// ProviderHostBlock: the row's network owner can refuse the
	// model-provider hosts by name and every literal IP (section 7.3).
	ProviderHostBlock bool
	// RefusalAuditTiers are the egress tiers on which the row's launches
	// leave the agent no way out that Observer does not see, so the floor
	// require_refusal_audit (lane N4) may pick the row on that tier: a tier
	// that runs Observer's own egress gateway hands each refusal it makes to
	// the home daemon's refusal audit (the node-local
	// sandbox_egress_refusals table, lane N1), and a private-namespace tier
	// with no gateway (proxy_only, none) has no outbound path but the
	// observer model proxy, so there is no refusal to make (a connection
	// attempt fails in the kernel with no route and is not recorded). A tier
	// that shares the host network (host) is never listed: nothing stands
	// between the agent and the network. RefusalAuditSource names the file
	// and the test. A provider-enforced row, a row with no enforcer and a row
	// whose runs are refused list none (the zero value: not grounded). The
	// audit itself records at most one row per run and host per minute and
	// drops a refusal when its report queue is full (lane N1's limiter).
	RefusalAuditTiers  []sandboxvocab.Tier
	RefusalAuditSource string
	// DeniesObserverPorts: the row's own enforcement refuses a connection
	// to every one of Observer's own TCP listeners (the dashboard first),
	// even on a tier that shares the host's network, so a box cannot reach
	// the daemon's loopback control plane (the Landlock row's TCP deny
	// list; security ledger LAUNCH-1, SBX-BE-17). Zero: not claimed.
	DeniesObserverPorts bool
}

// HookPath is how a hook event reaches the home daemon.
type HookPath string

// The closed HookPath vocabulary. Only direct_db and relay keep the guard
// verdict home-side (capture rule C1).
const (
	HookDirectDB      HookPath = "direct_db"
	HookRelay         HookPath = "relay"
	HookInBoxObserver HookPath = "in_box_observer"
)

// ReachesHome reports whether hook events are judged by the home daemon
// synchronously.
func (h HookPath) ReachesHome() bool { return h == HookDirectDB || h == HookRelay }

// Capture is a row's capture CEILING and hook path. The level of a run is
// computed (internal/sandboxselect), never read from here.
type Capture struct {
	Ceiling  sandboxvocab.CaptureLevel
	HookPath HookPath
	// Relay is how the relay crosses the boundary (zero: not declared).
	Relay RelayTransport
}

// ReadBack is what the post-build re-check reads.
type ReadBack string

// The closed ReadBack vocabulary. A row with ReadBackNone can carry at most
// a documented class, never measured.
const (
	ReadBackProcNS    ReadBack = "proc_ns"
	ReadBackEngineAPI ReadBack = "engine_api"
	ReadBackVMMInfo   ReadBack = "vmm_info"
	ReadBackSelfTest  ReadBack = "self_test"
	ReadBackProvider  ReadBack = "provider_description"
	ReadBackNone      ReadBack = "none"
)

// Disclosure is something the user is told before first use.
type Disclosure string

// The closed Disclosure vocabulary.
const (
	DiscloseAccountLogin     Disclosure = "account_login"
	DiscloseCLITelemetry     Disclosure = "cli_telemetry"
	DiscloseDataLeaves       Disclosure = "data_leaves_machine"
	DisclosePaidTier         Disclosure = "paid_tier"
	DiscloseRegionOutsideOrg Disclosure = "region_outside_org"
	DiscloseHostMutation     Disclosure = "host_mutation"
	// DiscloseGatewayBindMounts: the row needs a gateway-wide setting that
	// lets every sandbox the gateway runs ask for host bind mounts, not only
	// Observer's (OpenShell's allow_driver_config and enable_bind_mounts,
	// decision D3, risk RK-05).
	DiscloseGatewayBindMounts Disclosure = "gateway_wide_bind_mounts"
	// DiscloseSharedHomeTmpfs: the box's home is a tmpfs owned by root with
	// mode 1777 and the sticky bit, not a directory owned by the user, so a
	// second user id inside the box could create files in it (it cannot
	// delete or replace the user's own). OpenShell tracker F-017 A4.
	DiscloseSharedHomeTmpfs Disclosure = "home_shared_tmpfs"
	// DiscloseOrgCompute: the box runs on the organization's own machines,
	// and its administrators can see into it (the org-hosted OpenShell row,
	// tracker F-019, g1-design.md section 3.1).
	DiscloseOrgCompute Disclosure = "org_compute"
	// DiscloseOrgSharedGateway: several developers' boxes share one gateway
	// and one kernel on the organization's machines.
	DiscloseOrgSharedGateway Disclosure = "org_shared_gateway"
	// DiscloseNoHookGating: no hook runs in the box unless the project
	// itself commits one (the box's agent home is fresh, so this machine's
	// hook registration is not there), so guard does not check or block the
	// agent's actions in the box (every hosted row; lane UX, item H9). Since
	// lane HOOKS (SBXD-6) Observer seeds its own hooks into the box for a
	// covered tool while [terminal.sandbox.hosted].guard_hooks resolves on,
	// so this one is PerLaunch: the probe serves it per tool, only where
	// gating does not apply.
	DiscloseNoHookGating Disclosure = "no_hook_gating"
)

// perLaunchDisclosures are the disclosures whose truth depends on the
// launch (the tool, a setting, the machine's guard mode), not on the row
// alone: a surface says them per launch, never row-wide.
var perLaunchDisclosures = map[Disclosure]bool{
	DiscloseNoHookGating: true,
}

// PerLaunch reports whether d is said per launch (the New Terminal
// dialog's per-tool line) instead of with the row.
func (d Disclosure) PerLaunch() bool { return perLaunchDisclosures[d] }

// Capability is one backend row. Zero values mean "not grounded".
type Capability struct {
	ID           string
	Label        string
	Maturity     Maturity
	Phase        string
	Verification []Verified
	Iso          Isolation
	Control      Control
	Term         Terminal
	Net          Network
	Capture      Capture
	ReadBack     ReadBack
	// ExplicitOnly: never picked for an auto request or the guard's
	// enforce auto-upgrade (S1b); used only when the user names it.
	ExplicitOnly bool
	// AllowsNestedUserns: an inner process layer can create user
	// namespaces inside this layer (nesting rule N4).
	AllowsNestedUserns bool
	// PassesKVM: /dev/kvm reaches an inner layer (nesting rule N5).
	PassesKVM bool
	// Seatbelt: a process layer with Seatbelt semantics, which cannot nest
	// (N6).
	Seatbelt bool
	// ProcView is how the layer presents /proc to what runs inside it
	// (nesting rule N11): an agent-native sandbox that mounts a fresh /proc
	// cannot nest inside a layer whose /proc is ProcFreshCovered.
	ProcView ProcView
	// TreeContained: every process of a box this row builds stays a
	// descendant of the box's host-side root (the PTY's child, or the CLI
	// that built the box), declared per row, never inferred: bwrap runs the
	// box in a PID namespace of its own with --die-with-parent, so an
	// orphan is re-parented to the box's own init and the box dies with its
	// root. False for every other row: the OCI rows' processes run under
	// the container runtime's shim, not under the root, and the MXC rows
	// have no PID namespace, so an orphan leaves the tree. The loopback
	// caller check (security ledger LAUNCH-1) clears a caller by ancestry
	// only for a row that declares it; an exposed box of any other row
	// refuses every caller while it lives.
	TreeContained bool
	// DevNetTUN: /dev/net/tun is available inside the layer (N12).
	DevNetTUN bool
	// GuestUnprivUserns: the layer is a VM whose Linux guest allows
	// unprivileged user namespaces, so any agent-native sandbox nests in it
	// (N13).
	GuestUnprivUserns bool
	// AppContainer: the layer is built on Windows AppContainer (N14).
	AppContainer bool
	// Landlock: the layer is a Landlock ruleset, which stacks innermost
	// under any other layer (N9).
	Landlock bool
	// LifetimeCapSeconds is a remote box's hard lifetime; 0 means none
	// (S13).
	LifetimeCapSeconds int
	// KeystoreServices are the OS keychain services the row's driver
	// writes (custody=keychain). `observer uninstall --all` removes this
	// home's entries in them through this field, whether or not the driver
	// is compiled into the build, so no other file names the driver.
	KeystoreServices []string
	// Setup is the row's ordered prerequisite ids (sandbox installation
	// lifecycle plan section 3.2): what this host needs before the row can
	// run, each an id of internal/sandboxsetup's prerequisite table. Plain
	// strings, so this package keeps importing only internal/sandboxvocab;
	// internal/sandboxsetup's coverage test validates every id. The
	// generic steps (select the row's component first, enable the row
	// last) are not listed: the planner adds them. Nil on a planned row and
	// on a row whose SetupUnavailable says why.
	Setup []string
	// SetupUnavailable is why setup is not offered for this offered row in
	// this release (a probe-only row whose steps could never finish, plan
	// rule 4); "" when Setup is offered. A row carries Setup or this, never
	// both and never neither (coverage test).
	SetupUnavailable string
	// SetupBeta is a one-sentence reason the row's setup is beta (operator
	// ruling P-256: the setup has not been checked on a live host in the
	// sandbox installation lifecycle arc); "" when it is not beta. It is a
	// label every setup surface shows beside the row, never a gate: no
	// step is hidden or refused because of it.
	SetupBeta string
	Discloses []Disclosure
	Note      string
}

// VerificationOn returns the row's grounding on host; ok is false when the
// row has none there (which renders as beta and meets no floor).
func (c Capability) VerificationOn(h HostKind) (Verified, bool) {
	for _, v := range c.Verification {
		if v.Host == h {
			return v, true
		}
	}
	return Verified{}, false
}

// HostRefusal returns the row's own reason for not running on h, or ""
// when the row declares none (then the caller words a generic refusal).
func (c Capability) HostRefusal(h HostKind) string {
	return c.Iso.HostRefusals[h]
}

// RunsOn reports whether h is one of the row's hosts.
func (c Capability) RunsOn(h HostKind) bool {
	for _, x := range c.Iso.Hosts {
		if x == h {
			return true
		}
	}
	return false
}

// OffersTier reports whether the row supports tier t.
func (c Capability) OffersTier(t sandboxvocab.Tier) bool {
	for _, x := range c.Net.Egress {
		if x == t {
			return true
		}
	}
	return false
}

// AuditsRefusalsOn reports whether a launch on tier t is covered by the
// refusal audit (Network.RefusalAuditTiers), the one test rule S7e and the
// publish lint read.
func (n Network) AuditsRefusalsOn(t sandboxvocab.Tier) bool {
	for _, x := range n.RefusalAuditTiers {
		if x == t {
			return true
		}
	}
	return false
}

// AuditsRefusals reports whether some tier of the row is covered by the
// refusal audit.
func (n Network) AuditsRefusals() bool { return len(n.RefusalAuditTiers) > 0 }

// Offered reports whether the row may appear in a picker, a probe or the
// selector at all.
func (c Capability) Offered() bool { return c.Maturity != MaturityPlanned }

// Connector is a way of reaching a backend, with no class of its own.
type Connector struct {
	ID      string
	Reaches []string
	// Tunnel is an external tunnel process, declared in the driver's
	// Processes.
	Tunnel string
	Note   string
}

// ProcView is the closed vocabulary of how a layer presents /proc.
type ProcView string

// The ProcView values. The zero value means not grounded.
const (
	// ProcFreshFull: a fresh procfs with nothing covered.
	ProcFreshFull ProcView = "fresh_full"
	// ProcFreshCovered: a fresh procfs with parts covered (Observer's bwrap
	// plan), where the kernel refuses a further fresh procfs mount.
	ProcFreshCovered ProcView = "fresh_covered"
	// ProcInherited: the host's /proc is visible as is.
	ProcInherited ProcView = "inherited"
)
