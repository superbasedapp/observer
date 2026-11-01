package sandboxbackend

import "github.com/marmutapp/superbased-observer/internal/sandboxvocab"

// RegistryVersion moves with every enum or row-shape change.
const RegistryVersion = 4

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
	// CrossesKernel: some byte reaches another kernel or a user-space
	// kernel; then the hook path must not be direct_db (invariant I5).
	CrossesKernel bool
	// HostMutation: the row changes the host (a persistent DACL, a firewall
	// rule); such rows are disabled by default and disclose it.
	HostMutation bool
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
)

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
	Discloses          []Disclosure
	Note               string
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
