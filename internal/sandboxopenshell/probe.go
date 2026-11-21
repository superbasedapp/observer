package sandboxopenshell

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// The probe verdicts (besides the version verdicts of version.go). Every
// one but VerdictAvailable refuses the row on this host, with Reason.
const (
	VerdictAvailable             = "available"
	VerdictGatewayModeNotBuilt   = "gateway_mode_not_built"
	VerdictUnsupportedPlatform   = "unsupported_platform"
	VerdictMissing               = "openshell_missing"
	VerdictGatewayUnreachable    = "gateway_unreachable"
	VerdictGatewayUnauthed       = "gateway_unauthenticated"
	VerdictGatewayNotLocal       = "gateway_not_local"
	VerdictDriverUntested        = "driver_untested"
	VerdictLandlockABITooOld     = "landlock_abi_too_old"
	VerdictCanaryNotRun          = "runtime_canary_not_run"
	VerdictRuntimeBlocksLandlock = "runtime_seccomp_blocks_landlock"
	VerdictCanaryFailed          = "runtime_canary_failed"
	VerdictCanaryImageMissing    = "runtime_canary_image_missing"
	VerdictCanaryNotStarted      = "runtime_canary_not_started"
	VerdictCanaryTimedOut        = "runtime_canary_timed_out"
	VerdictBindMountsDisabled    = "bind_mounts_disabled"
	VerdictBindMountsUnknown     = "bind_mounts_unknown"
)

// The [terminal.sandbox.openshell].gateway_mode values. Managed (the
// default, decision D2, lane O2): Observer runs a private gateway of its
// own (gateway.go). External (the opt-in): the user installs, starts and
// authenticates their own gateway, and Observer never holds its
// certificates. The config package resolves "" to one of the two
// (config.TerminalSandboxOpenShellConfig.EffectiveGatewayMode) before the
// probe reads it.
const (
	GatewayExternal = "external"
	GatewayManaged  = "managed"
)

// MinLandlockABI is the lowest Landlock ABI OpenShell needs (ABI 3, Linux
// 6.2; OpenShell's support matrix, doc 04 R2.5).
const MinLandlockABI = 3

// Canary is the outcome of Observer's own runtime canary: a
// landlock_create_ruleset ABI query (syscall 444) in a throwaway container
// under the runtime's DEFAULT seccomp profile, the check `openshell doctor
// check` does not make (upstream #4133; RK-02).
type Canary string

// The closed Canary vocabulary.
const (
	// CanaryNotRun: no canary result (the zero value). Never available:
	// doctor's ok alone is not enough.
	CanaryNotRun Canary = ""
	// CanaryOK: the query returned an ABI number.
	CanaryOK Canary = "ok"
	// CanaryENOSYS: the runtime's default seccomp profile answers ENOSYS for
	// the Landlock syscalls (WSL2 with runc on libseccomp 2.5.1, O0 receipts
	// wsl2-2026-10-31-03951e and -8a047f), so OpenShell's supervisor fails
	// closed at start.
	CanaryENOSYS Canary = "enosys"
	// CanaryError: the canary ran and answered something else (or
	// nothing).
	CanaryError Canary = "error"
	// CanaryImageMissing: the canary's image is not on this host (the
	// probe never pulls), so no query ran. Never read as a Landlock answer.
	CanaryImageMissing Canary = "image_missing"
	// CanaryNotStarted: docker could not run the canary container (the CLI
	// did not start, the daemon refused the run, or the entrypoint could
	// not be executed), so no query ran.
	CanaryNotStarted Canary = "not_started"
	// CanaryTimedOut: the docker call was stopped before it finished (the
	// probe's time limit), so whether the container ran is not known.
	CanaryTimedOut Canary = "timed_out"
)

// enosys is ENOSYS on Linux.
const enosys = 38

// ParseCanary reads the canary's "<syscall return> <errno>" answer (lane
// O0's form: "4 0" is ABI 4, "-1 38" is ENOSYS). It returns the outcome and
// the ABI on success.
func ParseCanary(out string) (Canary, int) {
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) != 2 {
		return CanaryError, 0
	}
	ret, err1 := strconv.Atoi(f[0])
	errno, err2 := strconv.Atoi(f[1])
	switch {
	case err1 != nil || err2 != nil:
		return CanaryError, 0
	case ret >= 1 && errno == 0:
		return CanaryOK, ret
	case ret == -1 && errno == enosys:
		return CanaryENOSYS, 0
	}
	return CanaryError, 0
}

// Tri is a fact the driver may not be able to read.
type Tri string

// The closed Tri vocabulary; the zero value is unknown.
const (
	TriUnknown Tri = ""
	TriYes     Tri = "yes"
	TriNo      Tri = "no"
)

// ProbeFacts is everything the probe verdict table reads. The driver (lane
// O1B) gathers them; this package never runs anything.
type ProbeFacts struct {
	// GatewayMode is the effective [terminal.sandbox.openshell]
	// .gateway_mode (managed or external; "" is refused at P0).
	GatewayMode string
	// Managed is the managed gateway's lifecycle answer after the driver
	// acted on it (row PG reads it in managed mode only).
	Managed GatewayDecision
	// ManagedName and ManagedServer are the private gateway's recorded
	// name and server (row P4m: in managed mode the status answer must
	// come from exactly these).
	ManagedName, ManagedServer string
	// GatewayName is the name the status answer gave (row P4m compares it
	// with ManagedName; audit finding O2-A7).
	GatewayName string
	// Host is the host kind the daemon runs on.
	Host sandboxbackend.HostKind
	// CLIFound: the openshell CLI resolved to an absolute path.
	CLIFound bool
	// CLIUntrusted is BinaryTrust's reason when the CLI was found only
	// where the user or a box could replace it ("" otherwise; row P2).
	CLIUntrusted string
	// GatewayStatus is the status field of `openshell status -o json`
	// ("connected", "connected_http", "error", "disconnected"; "" when not
	// asked).
	GatewayStatus string
	// Authentication is its authentication.status ("authenticated",
	// "not_required", "failed", "unverified").
	Authentication string
	// GatewayServer is its server field: the address of the gateway that
	// answered ("" when not read). Row P4b requires an https URL on this
	// machine's loopback (LoopbackServer).
	GatewayServer string
	// Version holds the raw version answers and the configured pin.
	Version VersionFacts
	// Driver is the gateway's compute driver ("docker", "podman").
	Driver string
	// LandlockABI is the host kernel's Landlock ABI (0: not read).
	LandlockABI int
	// Canary is Observer's own runtime canary outcome.
	Canary Canary
	// Engine is the container engine's identity and the row's record of
	// the engine it first used (row P8e).
	Engine EngineFacts
	// RuntimeImages are the registry digests of the gateway's supervisor
	// and sandbox runtime images as the engine recorded them (row P8i).
	RuntimeImages []ImageFact
	// CanaryImage is the image the canary ran in (named in a reason): the
	// gateway's supervisor image (its config's supervisor_image, else the
	// default of its version).
	CanaryImage string
	// CanaryDetail is the first line of docker's error output for a canary
	// that did not answer ("" otherwise).
	CanaryDetail string
	// BindMounts: the gateway allows driver config and bind mounts for its
	// sandboxes (allow_driver_config and enable_bind_mounts, D3).
	BindMounts Tri
	// GatewayPolicy are row PS's facts: the gateway's proposal settings
	// and global policy (effectivepolicy.go, lane FU8, OSH-40).
	GatewayPolicy GatewayPolicyFacts
	// DoctorOK is what `openshell doctor check` said. Recorded for the
	// report only: no row reads it (#4133, the WSL2 receipts: doctor said
	// ok while every box failed closed).
	DoctorOK bool
}

// ProbeResult is the probe verdict: Verdict is VerdictAvailable or the
// first failing row's verdict, Rule names that row, and Version is the
// version check (set from row P5 on).
type ProbeResult struct {
	Verdict string
	Rule    string
	Reason  string
	Version VersionResult
}

// Available reports whether the row may be used on this host.
func (r ProbeResult) Available() bool { return r.Verdict == VerdictAvailable }

// probeRule is one row of the probe verdict table.
type probeRule struct {
	id      string
	verdict func(f ProbeFacts, v VersionResult) (verdict, reason string)
}

// ok is the verdict of a row that passes.
const ok = ""

// probeRules is the probe verdict table (doc 04 R2.6 O1, refreshed with lane
// O0's live facts), walked top-down; the first row with a verdict wins.
var probeRules = []probeRule{
	{"P0", func(f ProbeFacts, _ VersionResult) (string, string) {
		switch f.GatewayMode {
		case GatewayExternal, GatewayManaged:
			return ok, ""
		}
		return VerdictGatewayModeNotBuilt, "unknown gateway_mode " + quoteOr(f.GatewayMode, "(not resolved)")
	}},
	// P1 is defence in depth: on WSL2 the selector's platform rule S3
	// answers first with the same reason (the registry row's HostRefusals,
	// live check O5-L2 2026-11-01), so this branch is reached only by a
	// caller that probes without selecting.
	{"P1", func(f ProbeFacts, _ VersionResult) (string, string) {
		switch f.Host {
		case sandboxbackend.HostLinux:
			return ok, ""
		case sandboxbackend.HostWSL2:
			return VerdictUnsupportedPlatform, sandboxbackend.OpenShellWSL2Refusal
		}
		return VerdictUnsupportedPlatform, "OpenShell runs on native Linux only"
	}},
	{"P2", func(f ProbeFacts, _ VersionResult) (string, string) {
		if !f.CLIFound {
			return VerdictMissing, "the openshell CLI is not installed or not on PATH"
		}
		// Ledger row OSH-44: a CLI found only where the user or a box
		// could replace it is never run (bintrust.go).
		if f.CLIUntrusted != "" {
			return VerdictBinaryUntrusted, f.CLIUntrusted
		}
		return ok, ""
	}},
	// PG (lane O2): in managed mode, Observer's private gateway is up
	// under its lifecycle table (gateway.go): started, restarted for an
	// upgrade, or refused with the table's reason. External mode skips it.
	{"PG", func(f ProbeFacts, _ VersionResult) (string, string) {
		if f.GatewayMode != GatewayManaged {
			return ok, ""
		}
		if f.Managed.Ready() {
			return ok, ""
		}
		if f.Managed.Verdict == "" {
			return VerdictGatewayNotReady, "Observer's private gateway is not ready (lifecycle row " + quoteOr(f.Managed.Rule, "not run") + ")"
		}
		return f.Managed.Verdict, f.Managed.Reason
	}},
	{"P3", func(f ProbeFacts, _ VersionResult) (string, string) {
		if f.GatewayStatus != "connected" {
			return VerdictGatewayUnreachable, "the OpenShell gateway is not connected (status " + quoteOr(f.GatewayStatus, "not read") + "); start it and check `openshell status`"
		}
		return ok, ""
	}},
	{"P4", func(f ProbeFacts, _ VersionResult) (string, string) {
		if f.Authentication != "authenticated" {
			return VerdictGatewayUnauthed, "the OpenShell gateway did not authenticate this user (authentication " + quoteOr(f.Authentication, "not read") + ")"
		}
		return ok, ""
	}},
	// P4b (audit findings O1B-A3 and O1B-R4): the gateway that answered
	// must be reached at a loopback address. The box's binds are same-path
	// binds of this machine's files (the workspace, the tool state, the
	// per-run socket dir), and the later rows (Landlock ABI, the runtime
	// canary, the gateway's config file) are facts of this machine; a
	// remote or shared gateway would bind its own host's paths at those
	// names. The row checks the address only: a port-forward or tunnel
	// from a loopback port to a remote gateway (or a localhost name the
	// hosts file points elsewhere) looks the same and is out of scope. The
	// configured endpoint is checked at config load; this row checks the
	// CLI's active gateway too.
	{"P4b", func(f ProbeFacts, _ VersionResult) (string, string) {
		if f.GatewayServer == "" {
			return VerdictGatewayNotLocal, "the gateway's server address was not read from `openshell status`, so Observer cannot tell that it is a loopback address"
		}
		if !LoopbackServer(f.GatewayServer) {
			return VerdictGatewayNotLocal, "the gateway's server " + strconv.Quote(f.GatewayServer) + " is not an https URL on a loopback address: the box's mounts are same-path binds of this machine's paths, so the row takes only a gateway reached at a loopback address (a port-forward or tunnel to a remote gateway is out of scope); select a local gateway, or set [terminal.sandbox.openshell].endpoint to one"
		}
		return ok, ""
	}},
	// P4m (lane O2): in managed mode the gateway that answered is
	// Observer's own: the status answer names its private gateway and its
	// recorded loopback server exactly (the run's pin is name plus server,
	// as in external mode).
	{"P4m", func(f ProbeFacts, _ VersionResult) (string, string) {
		if f.GatewayMode != GatewayManaged {
			return ok, ""
		}
		if f.ManagedName == "" || f.ManagedServer == "" || f.GatewayServer != f.ManagedServer {
			return VerdictGatewayNotLocal, "the gateway that answered (" + quoteOr(f.GatewayServer, "no server") + ") is not Observer's private gateway at its recorded server " + quoteOr(f.ManagedServer, "(none recorded)")
		}
		if f.GatewayName != f.ManagedName {
			return VerdictGatewayNotLocal, "the gateway that answered is named " + quoteOr(f.GatewayName, "nothing") + ", not Observer's private gateway " + strconv.Quote(f.ManagedName)
		}
		return ok, ""
	}},
	{"P5", func(_ ProbeFacts, v VersionResult) (string, string) { return v.Verdict, v.Reason }},
	// P6 (lane FU7, tracker F-033): a driver a live receipt measured on
	// this tested version (drivers.go): Docker everywhere, Podman where the
	// row names its O1B-L2 launch receipt.
	{"P6", func(f ProbeFacts, v VersionResult) (string, string) {
		if !DriverAccepted(f.Driver, v.Row) {
			return VerdictDriverUntested, driverRefusal(f.Driver, v.Version)
		}
		return ok, ""
	}},
	{"P7", func(f ProbeFacts, _ VersionResult) (string, string) {
		if f.LandlockABI < MinLandlockABI {
			if f.LandlockABI <= 0 {
				return VerdictLandlockABITooOld, "the kernel's Landlock ABI could not be read; OpenShell needs ABI 3 (Linux 6.2)"
			}
			return VerdictLandlockABITooOld, "the kernel's Landlock ABI is " + strconv.Itoa(f.LandlockABI) + "; OpenShell needs ABI 3 (Linux 6.2)"
		}
		return ok, ""
	}},
	// P8e (ledger row OSH-48, adversarial row A9): the engine the launch
	// drives is the one the row first used (engine.go), checked before any
	// container call of the probe.
	{"P8e", func(f ProbeFacts, _ VersionResult) (string, string) {
		if !DriverHasEngineIdentity(f.Driver) {
			return ok, ""
		}
		return EngineVerdict(f.Engine)
	}},
	// P8i (ledger row OSH-48, adversarial row A12): the supervisor and
	// sandbox runtime images the gateway uses carry a digest pinned in the
	// tested-version table, checked before the canary runs Observer's
	// binary in the supervisor image (images.go).
	{"P8i", func(f ProbeFacts, v VersionResult) (string, string) {
		return ImageVerdict(v.Row, v.Version, f.Driver, f.RuntimeImages)
	}},
	{"P8", func(f ProbeFacts, _ VersionResult) (string, string) {
		switch f.Canary {
		case CanaryOK:
			return ok, ""
		case CanaryENOSYS:
			return VerdictRuntimeBlocksLandlock, "the container runtime's default seccomp profile blocks the Landlock syscalls (ENOSYS), so OpenShell's supervisor would fail closed; `openshell doctor check` does not detect this"
		case CanaryImageMissing:
			return VerdictCanaryImageMissing, CanaryImageMissingReason(f.CanaryImage)
		case CanaryNotStarted:
			return VerdictCanaryNotStarted, "docker could not run Observer's runtime canary container, so the Landlock query did not run" + detailSuffix(f.CanaryDetail)
		case CanaryTimedOut:
			return VerdictCanaryTimedOut, "Observer's runtime canary did not finish within the probe's time limit (a slow or stuck container runtime), so no Landlock answer was read" + detailSuffix(f.CanaryDetail)
		case CanaryError:
			return VerdictCanaryFailed, "Observer's runtime canary ran but its Landlock query answered neither an ABI nor ENOSYS" + detailSuffix(f.CanaryDetail)
		}
		return VerdictCanaryNotRun, "Observer's runtime canary has not run; `openshell doctor check` alone is not enough"
	}},
	{"P9", func(f ProbeFacts, _ VersionResult) (string, string) {
		switch f.BindMounts {
		case TriYes:
			return ok, ""
		case TriNo:
			return VerdictBindMountsDisabled, "the gateway does not allow bind mounts: set allow_driver_config and enable_bind_mounts under [openshell.drivers.docker] in its gateway.toml (this applies to every sandbox it runs)"
		}
		return VerdictBindMountsUnknown, "could not tell whether the gateway allows bind mounts (allow_driver_config and enable_bind_mounts)"
	}},
	// PS (lane FU8, ledger OSH-40): the gateway must not widen a box past
	// its compiled rules on its own (a gateway-global policy, automatic
	// approval or agent proposals at gateway scope; effectivepolicy.go's
	// table). The settings read is `--global`: "<unset>" there means no
	// gateway-scope value, and a sandbox-scope auto approval or proposals
	// setting on an external box is not seen by this row; the box watch
	// catches the widening after the fact (residual, audit FU9-A1).
	{"PS", func(f ProbeFacts, _ VersionResult) (string, string) {
		v, reason, _ := GatewayPolicyVerdict(f.GatewayMode, f.GatewayPolicy)
		return v, reason
	}},
}

// ProbeRuleIndex is the position of a probe row in the verdict table (the
// driver's gathering ladder stops at the first refused row at or before
// the step it ran). The available row, P10, and any unknown id sort last.
func ProbeRuleIndex(id string) int {
	for i, r := range probeRules {
		if r.id == id {
			return i
		}
	}
	return len(probeRules)
}

// LoopbackServer reports whether raw is an https URL on a loopback address
// (localhost, 127.0.0.0/8 or ::1) with no credentials, path, query or
// fragment, and either no port or one from 1 to 65535: the loopback rule
// the config loader applies to [terminal.sandbox.openshell].endpoint,
// applied with the port check to the server a status answer names. The
// name localhost is taken as written,
// never resolved; an address says where the gateway is reached, not where
// its runtime runs (a tunnel is out of scope, audit finding O1B-R4).
func LoopbackServer(raw string) bool {
	if strings.ContainsAny(raw, " \t\n") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return false
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return false
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return false
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return false // a colon with no port
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == "" && ip.IsLoopback()
}

// detailSuffix renders a canary detail after a reason ("" for none).
func detailSuffix(d string) string {
	if d == "" {
		return ""
	}
	return " (" + strconv.Quote(d) + ")"
}

// quoteOr quotes s, or returns alt when s is empty.
func quoteOr(s, alt string) string {
	if s == "" {
		return alt
	}
	return strconv.Quote(s)
}

// Probe walks the probe verdict table.
func Probe(f ProbeFacts) ProbeResult {
	v := CheckVersion(f.Version)
	for _, r := range probeRules {
		if verdict, reason := r.verdict(f, v); verdict != ok {
			return ProbeResult{Verdict: verdict, Rule: r.id, Reason: reason, Version: v}
		}
	}
	return ProbeResult{Verdict: VerdictAvailable, Rule: "P10", Version: v}
}

// StatusAnswer is what the probe reads from `openshell status -o json`
// (o0-receipts.md, CLI table, "Gateway status").
type StatusAnswer struct {
	// Gateway is the name of the gateway that answered (the CLI's active
	// one when the question named none): the driver records it and pins
	// every later box command to it (audit finding O1A-A9).
	Gateway string
	// Server is the gateway's server address as the CLI reports it.
	Server string
	// Status is "connected", "connected_http", "error" or "disconnected".
	Status string
	// Authentication is authentication.status.
	Authentication string
	// Version is the gateway's version field.
	Version string
}

// ParseStatus decodes the answer of `openshell status -o json`.
func ParseStatus(b []byte) (StatusAnswer, error) {
	var w struct {
		Gateway        string `json:"gateway"`
		Server         string `json:"server"`
		Status         string `json:"status"`
		Version        string `json:"version"`
		Authentication struct {
			Status string `json:"status"`
		} `json:"authentication"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return StatusAnswer{}, fmt.Errorf("sandboxopenshell.ParseStatus: %w", err)
	}
	return StatusAnswer{Gateway: w.Gateway, Server: w.Server, Status: w.Status, Authentication: w.Authentication.Status, Version: w.Version}, nil
}
