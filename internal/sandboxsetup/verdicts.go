package sandboxsetup

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// verdictMissing is one driver probe verdict that means a prerequisite is
// missing.
type verdictMissing struct {
	Verdict string
	Prereq  string
	// ReasonHas, when set, splits one verdict by its reason: the row matches
	// only a probe reason holding this text (a driver that answers two shapes
	// with one verdict, such as /dev/kvm missing versus not openable). Rows
	// with ReasonHas sit before the verdict's plain row. A reason-split row
	// with an empty Prereq pins a shape that names no step, so the plain row
	// below it does not claim that shape.
	ReasonHas string
}

// driverVerdicts is one driver's rows of the verdict map: the driver package
// whose probe answers (named for the pin test, which holds every verdict
// string equal to that package's constant), the registry rows that driver
// probes, and the verdicts that mean one of those rows' prerequisites is
// missing. Verdicts are spelled as strings so this package does not import
// the driver packages.
type driverVerdicts struct {
	Driver   string
	Backends []string
	Missing  []verdictMissing
	// MissingPrefix are rows whose Verdict is a prefix the probe completes
	// with a field name (the hosted consent's consent_changed_<field>, one
	// verdict per bound fact that changed): each matches every verdict that
	// starts with it and is longer. Walked after Missing.
	MissingPrefix []verdictMissing
	// Ladder is the order in which the driver's probe checks the rows'
	// prerequisites (nil: not known). A probe that stops at one rung has
	// passed every rung before it, so those steps read done after a check.
	// Only prerequisites the probe itself checks are listed.
	Ladder []string
}

// verdictMap is THE verdict map (plan section 3.2, Detect.Verdicts). A
// verdict absent here (a socket that failed validation, a version outside
// the tested range, a probe that failed) maps to no prerequisite: the plan
// shows the probe's own reason and the step's passive state.
var verdictMap = []driverVerdicts{
	{
		Driver:   "sandbox",
		Backends: []string{sandboxbackend.BackendBwrap},
		Missing: []verdictMissing{
			{"backend_missing", "bwrap", ""},
			{"backend_too_old", "bwrap", ""},
			{"userns_denied", "userns", ""},
			{"netns_denied", "userns", ""},
		},
		// internal/sandbox.Probe: LookBwrap, the version floor, the canary,
		// the net canary.
		Ladder: []string{"bwrap", "userns"},
	},
	{
		Driver:   "sandboxlandlock",
		Backends: []string{sandboxbackend.BackendProcessLite},
		Missing: []verdictMissing{
			{"landlock_unavailable", "landlock-abi", ""},
			{"landlock_abi_too_old", "landlock-abi", ""},
		},
	},
	{
		Driver:   "sandboxoci",
		Backends: []string{sandboxbackend.BackendOCIRunc},
		Missing: []verdictMissing{
			// sandboxoci/socket.go: no socket at any candidate path.
			{"engine_unreachable", "engine-socket", "no Docker or Podman socket"},
			// sandboxoci/probe.go: a socket file is there but nothing
			// answers on it (a stopped socket unit leaves its file behind):
			// the socket's step, never the engine's install.
			{"engine_unreachable", "engine-socket", "did not answer: "},
			{"engine_unreachable", "container-engine", ""},
			{"engine_is_desktop_vm", "container-engine", ""},
			{"engine_mode_unsupported", "container-engine", ""},
			// sandboxoci/socket.go ValidateSocket: a root-owned socket that is
			// not group read-write for a group this user is in.
			{"socket_untrusted", "docker-group", "not group read-write for a group you are in"},
			{"image_missing", "oci-image", ""},
			{"engine_cannot_pull", "oci-image", ""},
		},
		// sandboxoci's probe: the engine and its socket (a socket that
		// answers means this user reaches it), then the image.
		Ladder: []string{"container-engine", "engine-socket", "docker-group", "oci-image"},
	},
	{
		Driver:   "sandboxoci",
		Backends: []string{sandboxbackend.BackendOCIRunsc},
		Missing: []verdictMissing{
			// A socket file nothing answers on: this row has no step that
			// starts Docker, and the engine is installed, so the shape names
			// no step (the plan shows the check's reason), never the
			// engine's install.
			{"engine_unreachable", "", "did not answer: "},
			{"engine_unreachable", "docker-engine", ""},
			{"engine_is_desktop_vm", "docker-engine", ""},
			// sandboxoci/socket.go and uid.go: a rootful socket while
			// allow_rootful is off is the config step; one this user cannot
			// open is the group step.
			{"socket_untrusted", "oci-allow-rootful", "allow_rootful = true"},
			{"socket_untrusted", "docker-group", "not group read-write for a group you are in"},
			// sandboxoci/runtime.go: the probe reached Podman's socket (a
			// rootless socket comes first), so it says nothing about
			// Docker's: the docker-group step is judged from Docker's own
			// socket and the user's groups (Detect.DockerSocketAccess), and
			// this shape names no step (the plan shows the check's reason).
			{"runtime_missing", "", "this socket is podman"},
			{"runtime_missing", "runsc-registered", ""},
			{"socket_bridge_unavailable", "runsc-registered", ""},
			{"image_missing", "oci-image", ""},
			{"engine_cannot_pull", "oci-image", ""},
		},
		Ladder: []string{"docker-engine", "docker-group", "runsc-registered", "oci-image"},
	},
	{
		Driver:   "sandboxvm",
		Backends: []string{sandboxbackend.BackendCloudHypervisor},
		Missing: []verdictMissing{
			// sandboxvm probe V3: /dev/kvm exists but this user cannot
			// open it is the group's step, not the firmware's.
			{"no_hypervisor", "kvm-group", "cannot open it"},
			{"no_hypervisor", "kvm-device", ""},
			{"nested_virt_unavailable", "kvm-device", ""},
			// V6 looks virtiofsd up with the same verdicts as V4.
			{"backend_missing", "virtiofsd", "virtiofsd"},
			{"backend_untrusted", "virtiofsd", "virtiofsd"},
			{"backend_missing", "cloud-hypervisor", ""},
			{"backend_untrusted", "cloud-hypervisor", ""},
			{"image_missing", "vm-image-set", ""},
			{"artifact_unverified", "vm-image-set", ""},
		},
		// sandboxvm's probeRows: V3 kvm, V4 and V5 cloud-hypervisor, V6
		// virtiofsd, V7 the image set.
		Ladder: []string{"kvm-device", "kvm-group", "cloud-hypervisor", "virtiofsd", "vm-image-set"},
	},
	{
		Driver:   "sandboxsbpl",
		Backends: []string{sandboxbackend.BackendSeatbelt},
		Missing: []verdictMissing{
			{"os_too_old", "macos-12", ""},
			{"backend_missing", "macos-sandbox-exec", ""},
			{"backend_untrusted", "macos-sandbox-exec", ""},
		},
		// sandboxsbpl's probeRows: P3 the macOS version, P4 sandbox-exec.
		Ladder: []string{"macos-12", "macos-sandbox-exec"},
	},
	{
		Driver:   "sandboxapple",
		Backends: []string{sandboxbackend.BackendAppleContainer},
		Missing: []verdictMissing{
			{"os_too_old", "macos-26-arm", ""},
			{"arch_unsupported", "macos-26-arm", ""},
			{"no_hypervisor", "macos-26-arm", ""},
			{"backend_missing", "apple-container-cli", ""},
			{"backend_untrusted", "apple-container-cli", ""},
			{"engine_unreachable", "apple-container-service", ""},
			{"image_missing", "apple-container-image", ""},
		},
		// sandboxapple's probeRows: arch, OS and hypervisor, the CLI and its
		// version, the service, the image.
		Ladder: []string{"macos-26-arm", "apple-container-cli", "apple-container-service", "apple-container-image"},
	},
	{
		Driver:   "sandboxmxc",
		Backends: []string{sandboxbackend.BackendMXCProcess, sandboxbackend.BackendMXCAppContainer},
		Missing: []verdictMissing{
			{"psec_unavailable", "win-build-psec", ""},
			{"psec_build_too_old", "win-build-psec", ""},
			{"artifact_missing", "mxc-files", ""},
			{"artifact_unverified", "mxc-files", ""},
		},
	},
	{
		Driver:   "sandboxopenshell",
		Backends: []string{sandboxbackend.BackendOpenShell},
		Missing: []verdictMissing{
			{"landlock_abi_too_old", "landlock-abi", ""},
			{"openshell_missing", "openshell-pkg", ""},
			{"openshell_binary_untrusted", "openshell-pkg", ""},
			{"openshell_too_old", "openshell-pkg", ""},
			{"gateway_binary_missing", "openshell-pkg", ""},
			{"gateway_supervisor_missing", "openshell-supervisor", ""},
			{"gateway_supervisor_no_docker_access", "docker-group", ""},
		},
	},
	{
		// The hosted drivers' probe ladder lives in cmd/observer
		// (terminal_sandbox_hosted.go); its credential verdict is a constant
		// there (verdictHostedCredentialMissing), which a test here cannot
		// import, so that one string is pinned by a test in cmd/observer
		// (lane daemon). The consent verdicts are internal/sandboxremote's.
		Driver:   "sandboxremote",
		Backends: []string{sandboxbackend.BackendE2B, sandboxbackend.BackendModal, sandboxbackend.BackendVercelSandbox, sandboxbackend.BackendDockerSandboxes, sandboxbackend.BackendInstaBox, sandboxbackend.BackendDaytona},
		Missing: []verdictMissing{
			{"credential_missing", "hosted-key", ""},
			{"custody_unsatisfiable", "hosted-custody", ""},
			{"consent_required", "hosted-consent", ""},
			{"consent_stale_version", "hosted-consent", ""},
			{"consent_tampered", "hosted-consent", ""},
		},
		// A recorded consent whose bound fact changed (the custody, the
		// region, the box binary, ...): the consent step reopens and names
		// the changed fact (cmd/observer consentChangeReason). Before this
		// row the verdict named no step (audit
		// sandbox-terminal-gaps-2026-11-18, H11).
		MissingPrefix: []verdictMissing{
			{"consent_changed_", "hosted-consent", ""},
		},
	},
	{
		Driver:   "openshellorg",
		Backends: []string{sandboxbackend.BackendOpenShellOrg},
		Missing: []verdictMissing{
			{"org_signin_required", "orgshell-login", ""},
			{"org_signin_expired", "orgshell-login", ""},
		},
	},
}

// missingFromVerdict returns the prerequisite a probe verdict (and its
// reason) of backend's driver says is missing ("" when the verdict names
// none). The first matching row wins, so a reason-split row sits first.
func missingFromVerdict(backend, verdict, reason string) string {
	if verdict == "" {
		return ""
	}
	for _, d := range verdictMap {
		if !stringIn(d.Backends, backend) {
			continue
		}
		for _, m := range d.Missing {
			if m.Verdict == verdict && (m.ReasonHas == "" || strings.Contains(reason, m.ReasonHas)) {
				return m.Prereq
			}
		}
		for _, m := range d.MissingPrefix {
			if len(verdict) > len(m.Verdict) && strings.HasPrefix(verdict, m.Verdict) && (m.ReasonHas == "" || strings.Contains(reason, m.ReasonHas)) {
				return m.Prereq
			}
		}
	}
	return ""
}

// rungPassed reports whether a probe that stopped at verdict (and reason)
// passed prereq on the way: both sit on the driver's Ladder and prereq's rung
// comes before the one the verdict names. A verdict that names no
// prerequisite, or a driver with no known ladder, passes nothing.
func rungPassed(backend, verdict, reason, prereq string) bool {
	stop := missingFromVerdict(backend, verdict, reason)
	if stop == "" || stop == prereq {
		return false
	}
	for _, d := range verdictMap {
		if !stringIn(d.Backends, backend) {
			continue
		}
		at, stopAt := indexOf(d.Ladder, prereq), indexOf(d.Ladder, stop)
		return at >= 0 && stopAt >= 0 && at < stopAt
	}
	return false
}

func indexOf(xs []string, s string) int {
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}

func stringIn(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
