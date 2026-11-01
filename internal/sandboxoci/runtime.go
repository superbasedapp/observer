package sandboxoci

import (
	"strings"
)

// runtime.go is the OCI runtime column of the two oci-* rows (sandbox plan
// v2 sections 4.2 and 13 P3; lane SBX-P3B): one driver, the same Engine API
// client and create body, and a runtime profile per registry row. The
// oci-runc row runs the engine's default same-kernel runtime (runc or
// crun); the oci-runsc row asks for gVisor's runsc and reads it back. A
// configuration knob that changes a capability column is a separate row,
// never a field (section 4.2): runsc crosses a kernel boundary (its own
// user-space kernel serves every syscall and the files through its gofer),
// so tool state is projected rather than bound (section 5.4) and the relay
// socket needs gVisor's host unix-socket bridge.

// The runtime verdicts (section 4.7, additive; both take the 501 default).
const (
	// VerdictRuntimeMissing: the engine has no runtime of the row's name
	// configured, or the row does not run on this engine or mode.
	VerdictRuntimeMissing = "runtime_missing"
	// VerdictSocketBridgeUnavailable: the runtime cannot connect to a host
	// unix socket bound into the box, so the capture relay, the model proxy
	// and the egress gateway would be unreachable; gVisor refuses such a
	// connect unless runsc runs with --host-uds=open (or all).
	VerdictSocketBridgeUnavailable = "socket_bridge_unavailable"
)

// SocketBridge is how the box reaches the run's host sockets (section 4.2
// NetMech): the guest helper connects to the sockets in the read-only
// socket dir bound into the box.
type SocketBridge string

// The SocketBridge values.
const (
	// BridgeBoundDir: a same-kernel container connects to a bound unix
	// socket like any process (oci-runc).
	BridgeBoundDir SocketBridge = "bound_socket_dir"
	// BridgeHostUDS: gVisor connects to a bound host unix socket only
	// through its host-UDS support, enabled by runsc's --host-uds=open or
	// --host-uds=all (oci-runsc).
	BridgeHostUDS SocketBridge = "runsc_host_uds"
)

// RuntimeProfile is one oci-* row's runtime column.
type RuntimeProfile struct {
	// Backend is the registry row id (sandboxbackend.BackendOCIRunc or
	// BackendOCIRunsc; restated as text so this package imports no
	// registry, TestRuntimeProfilesMatchTheRegistry keeps them equal).
	Backend string
	// CreateRuntime is the create body's HostConfig.Runtime: "" asks for
	// the engine's default runtime.
	CreateRuntime string
	// Accept are the runtimes the read-back accepts.
	Accept []string
	// Engines and Modes restrict where the row runs (nil: any).
	Engines []Engine
	Modes   []Mode
	// CrossesKernel: the runtime serves syscalls and files from its own
	// kernel, so tool state is projected and SQLite stores are copied in
	// the guest (section 5.4, the db-copy one-shot).
	CrossesKernel bool
	// Bridge is how the box reaches the run's host sockets.
	Bridge SocketBridge
}

// RuntimeOCIRunc and RuntimeOCIRunsc are the two row ids.
const (
	RuntimeOCIRunc  = "oci-runc"
	RuntimeOCIRunsc = "oci-runsc"
)

// runtimeProfiles is the table, one row per oci-* registry row.
var runtimeProfiles = []RuntimeProfile{
	{
		Backend: RuntimeOCIRunc, Accept: []string{"runc", "crun"},
		Bridge: BridgeBoundDir,
	},
	{
		// gVisor's documented engine integration is Docker Engine with
		// runsc registered as a runtime (`runsc install`, which writes
		// daemon.json); rootless Docker and Podman are not grounded for
		// runsc, so the row refuses them by name rather than guess.
		Backend: RuntimeOCIRunsc, CreateRuntime: "runsc", Accept: []string{"runsc"},
		Engines: []Engine{EngineDocker}, Modes: []Mode{ModeRootful},
		CrossesKernel: true, Bridge: BridgeHostUDS,
	},
}

// RuntimeProfileFor returns the profile of a registry row.
func RuntimeProfileFor(backend string) (RuntimeProfile, bool) {
	for _, p := range runtimeProfiles {
		if p.Backend == backend {
			return p, true
		}
	}
	return RuntimeProfile{}, false
}

// RuntimeProfiles returns every profile, in table order.
func RuntimeProfiles() []RuntimeProfile { return append([]RuntimeProfile(nil), runtimeProfiles...) }

// accepts reports whether the read-back's runtime is one the row takes. A
// zero profile is the oci-runc row's (an older plan file carries none).
func (p RuntimeProfile) accepts(rt string) bool {
	accept := p.Accept
	if len(accept) == 0 {
		accept = runtimeProfiles[0].Accept
	}
	for _, a := range accept {
		if rt == a {
			return true
		}
	}
	return false
}

// RuntimeInfo is one entry of the engine's /info Runtimes map.
type RuntimeInfo struct {
	Path string
	Args []string
}

// HostUDSMode reads runsc's --host-uds value from runtime arguments
// ("--host-uds=open", "-host-uds=open" or the two-argument form); "" when
// the flag is absent (gVisor's default, none).
func HostUDSMode(args []string) string {
	for i, a := range args {
		a = strings.TrimSpace(a)
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if name != "host-uds" || !strings.HasPrefix(a, "-") {
			continue
		}
		if hasVal {
			return strings.ToLower(strings.TrimSpace(val))
		}
		if i+1 < len(args) {
			return strings.ToLower(strings.TrimSpace(args[i+1]))
		}
	}
	return ""
}

// hostUDSConnects are the --host-uds values under which a sandboxed
// process may connect to a host unix socket (gVisor: "open" allows
// connecting to existing host sockets, "all" also creating them).
var hostUDSConnects = map[string]bool{"open": true, "all": true}

// CheckRuntime is the probe row of a runtime profile over the engine's
// identity and /info answer: the row's engine and mode, the runtime
// configured under its name, and the socket bridge the relay needs. It
// returns the bridge the run will use.
func CheckRuntime(p RuntimeProfile, id Identity, info InfoFacts) (SocketBridge, Verdict) {
	if p.Backend == "" {
		p = runtimeProfiles[0]
	}
	if len(p.Engines) > 0 && !containsEngine(p.Engines, id.Engine) {
		return "", refuse(VerdictRuntimeMissing, "the "+p.Backend+" row runs on "+joinEngines(p.Engines)+" only (its documented integration); this socket is "+string(id.Engine))
	}
	if len(p.Modes) > 0 && !containsMode(p.Modes, id.Mode) {
		return "", refuse(VerdictRuntimeMissing, "the "+p.Backend+" row runs on a "+joinModes(p.Modes)+" engine only (gVisor's documented setup; set [terminal.sandbox.oci].allow_rootful after reading what it discloses); this engine is "+string(id.Mode))
	}
	if p.CreateRuntime == "" {
		return p.Bridge, pass()
	}
	rt, ok := info.Runtimes[p.CreateRuntime]
	if !ok {
		return "", refuse(VerdictRuntimeMissing, "the engine has no "+p.CreateRuntime+" runtime: install gVisor and register it (`sudo runsc install -- --host-uds=open`, then restart dockerd)")
	}
	if p.Bridge == BridgeHostUDS && !hostUDSConnects[HostUDSMode(rt.Args)] {
		return "", refuse(VerdictSocketBridgeUnavailable, "runsc is registered without --host-uds=open, so a box cannot connect to the run's relay, model proxy and gateway sockets; register it with `sudo runsc install -- --host-uds=open` (runtimeArgs in daemon.json) and restart dockerd. No other bridge is built for this row")
	}
	return p.Bridge, pass()
}

// runtimeHint is one known runtime issue the probe names without refusing:
// the engine, mode and runtime it was seen on, and the known-good way.
type runtimeHint struct {
	engine  Engine
	mode    Mode
	runtime string
	hint    string
}

// runtimeHints is the table, walked top-down; the first row matching the
// engine, its mode and the runtime it runs containers with names its hint.
// It is empty: its one row named crun as the known-good runtime for
// rootless Podman on runc (Linux live check 2026-10-23), until the Linux
// live re-check on the Docker sandbox the same day proved the cause, the
// create's BindOptions turning Podman's binds non-recursive, which runc
// refuses under keep-id (bindOptionsTable). With that fixed runc has no
// known gap left that a hint would name.
var runtimeHints = []runtimeHint{}

// RuntimeHint names a known runtime issue for the row on this engine, ""
// when none applies. It never refuses: the row stays available. A row that
// names its own runtime (oci-runsc) runs that one, so no hint applies.
func RuntimeHint(p RuntimeProfile, id Identity, info InfoFacts) string {
	if p.Backend == "" {
		p = runtimeProfiles[0]
	}
	if p.CreateRuntime != "" {
		return ""
	}
	for _, h := range runtimeHints {
		if h.engine == id.Engine && h.mode == id.Mode && h.runtime == info.PodmanOCIRuntime {
			return h.hint
		}
	}
	return ""
}

func containsEngine(xs []Engine, x Engine) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsMode(xs []Mode, x Mode) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func joinEngines(xs []Engine) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = string(x)
	}
	return strings.Join(s, ", ")
}

func joinModes(xs []Mode) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = string(x)
	}
	return strings.Join(s, ", ")
}
