package sandbox

import (
	"fmt"
	"strings"
)

// EnvMarker is the environment variable Observer sets on child processes it
// launches INSIDE the bwrap boundary, so the hook lane can honestly stamp
// Event.Caps.Sandboxed and isInternalChildEnv can strip it from inherited env
// (it must never be spoofable in). This package is the single owner of the
// wire constant; U9 (the hook posture layer) and cmd import it from here rather
// than re-declaring the literal.
const EnvMarker = "OBSERVER_SANDBOX"

// BackendBwrap is the only sandbox backend value in v1.
const BackendBwrap = "bwrap"

// minBackendVersion is the probed bwrap floor (§0/D5): 0.4.0 is the oldest
// build whose flag set (--ro-bind-try/--bind-try/--die-with-parent/--dev/
// --proc/--tmpfs/--chdir) the planner relies on. Older builds lack them.
const minBackendVersion = "0.4.0"

// Verdict is the closed vocabulary for a sandbox readiness result. This layer
// owns only the platform/backend verdicts; the tool_unmapped and workspace
// verdicts (§7) belong to the registry and workspace layers respectively and
// are NOT declared here.
const (
	// VerdictAvailable: bwrap is present, new enough, and the user-namespace
	// canary passed — a sandbox can be built.
	VerdictAvailable = "available"
	// VerdictUnsupportedPlatform: the daemon OS is not Linux; bwrap sandboxing
	// is Linux-only (incl. WSL2).
	VerdictUnsupportedPlatform = "unsupported_platform"
	// VerdictBackendMissing: bwrap was not found on PATH — install bubblewrap.
	VerdictBackendMissing = "backend_missing"
	// VerdictBackendTooOld: bwrap is present but older than the 0.4.0 floor
	// (or its version could not be determined) — the flag set is unsupported.
	VerdictBackendTooOld = "backend_too_old"
	// VerdictUserNSDenied: bwrap and its version are fine, but the ms-scale
	// canary failed — unprivileged user namespaces are disabled on this host.
	VerdictUserNSDenied = "userns_denied"
	// VerdictDisabledByConfig: [terminal.sandbox].enabled = false. Produced by
	// the config-gating layer, not by Probe (which has no config input); the
	// value lives here so the vocabulary has one owner.
	VerdictDisabledByConfig = "disabled_by_config"
	// VerdictNetNSDenied: bwrap works, but it cannot create a private
	// network namespace (`--unshare-net`), which the configured egress tier
	// needs. Never downgraded to a shared-namespace sandbox: the launch is
	// refused and the reason names the tier and the fix.
	VerdictNetNSDenied = "netns_denied"
)

// Availability is the classified readiness surface rendered identically by the
// launcher, dashboard, and doctor. Available is the single boolean gate;
// Verdict is one of the closed strings above; Reason names the exact gap in
// honest prose; Backend/BackendVersion record what was probed; HomeMode echoes
// the configured home mode ("tmpfs"|"readonly") for display and is populated by
// the caller (Probe leaves it empty — it takes no config input).
type Availability struct {
	Available      bool
	Verdict        string
	Reason         string
	Backend        string
	BackendVersion string
	HomeMode       string
	// Egress echoes the configured network tier for display (populated by
	// the caller, like HomeMode).
	Egress string
}

// Env is the injected I/O surface for Probe. Every field is data or a func so
// the package stays pure (imports_test.go pins it free of os/exec). GOOS is the
// daemon OS. LookBwrap resolves the bwrap binary (path, err). Version returns
// bwrap's reported version string (the caller runs `bwrap --version` and hands
// the raw output here; parseVersion tolerates a "bubblewrap 0.4.0" prefix).
// Canary runs the ms-scale smoke `bwrap --ro-bind / / --tmpfs /tmp
// --die-with-parent -- true` and returns its error (nil = user namespaces
// work).
//
// NetCanary, when non-nil, runs the same smoke with `--unshare-net` added; the
// caller sets it only when the configured egress tier needs a private network
// namespace, so a host that cannot build one gets netns_denied instead of a
// launch that fails later (or, worse, a silently shared namespace).
type Env struct {
	GOOS      string
	LookBwrap func() (string, error)
	Version   func() (string, error)
	Canary    func() error
	NetCanary func() error
}

// Probe walks the platform/backend readiness ladder (§7) over the injected
// probes and returns a classified Availability. It is pure and fail-closed:
// any rung it cannot positively clear yields an unavailable verdict naming the
// gap. The ladder, top to bottom:
//
//	GOOS != linux            → unsupported_platform
//	LookBwrap fails / empty   → backend_missing
//	version < 0.4.0 / unknown → backend_too_old
//	canary returns an error   → userns_denied
//	net canary returns error  → netns_denied (only when NetCanary is set)
//	otherwise                 → available
func Probe(env Env) Availability {
	if env.GOOS != "linux" {
		return Availability{
			Verdict: VerdictUnsupportedPlatform,
			Backend: BackendBwrap,
			Reason:  fmt.Sprintf("sandboxing requires a Linux daemon (incl. WSL2); this daemon runs %q", env.GOOS),
		}
	}

	if env.LookBwrap == nil {
		return Availability{
			Verdict: VerdictBackendMissing,
			Backend: BackendBwrap,
			Reason:  "no bwrap lookup was provided",
		}
	}
	path, err := env.LookBwrap()
	if err != nil || strings.TrimSpace(path) == "" {
		return Availability{
			Verdict: VerdictBackendMissing,
			Backend: BackendBwrap,
			Reason:  "bwrap was not found on PATH; install bubblewrap",
		}
	}

	var version string
	if env.Version != nil {
		raw, verr := env.Version()
		if verr != nil {
			return Availability{
				Verdict: VerdictBackendTooOld,
				Backend: BackendBwrap,
				Reason:  fmt.Sprintf("could not determine bwrap version (needs >= %s): %v", minBackendVersion, verr),
			}
		}
		version = parseVersion(raw)
	}
	if !meetsFloor(version) {
		shown := version
		if shown == "" {
			shown = "unknown"
		}
		return Availability{
			Verdict:        VerdictBackendTooOld,
			Backend:        BackendBwrap,
			BackendVersion: version,
			Reason:         fmt.Sprintf("bwrap %s is older than the required %s floor", shown, minBackendVersion),
		}
	}

	if env.Canary != nil {
		if cerr := env.Canary(); cerr != nil {
			return Availability{
				Verdict:        VerdictUserNSDenied,
				Backend:        BackendBwrap,
				BackendVersion: version,
				Reason:         fmt.Sprintf("unprivileged user namespaces appear disabled (kernel.unprivileged_userns_clone / user.max_user_namespaces): %v", cerr),
			}
		}
	}

	if env.NetCanary != nil {
		if nerr := env.NetCanary(); nerr != nil {
			return Availability{
				Verdict:        VerdictNetNSDenied,
				Backend:        BackendBwrap,
				BackendVersion: version,
				Reason:         fmt.Sprintf("bwrap could not create a private network namespace, which the configured egress tier needs (set [terminal.sandbox].egress = \"host\" to share the host network, which leaves the dashboard reachable from inside the sandbox): %v", nerr),
			}
		}
	}

	return Availability{
		Available:      true,
		Verdict:        VerdictAvailable,
		Backend:        BackendBwrap,
		BackendVersion: version,
	}
}

// meetsFloor reports whether a parsed version string is non-empty and at least
// the 0.4.0 floor. An empty string (version unknown) fails closed.
func meetsFloor(v string) bool {
	return v != "" && compareVersions(v, minBackendVersion) >= 0
}

// parseVersion extracts a dotted numeric version from bwrap's --version output,
// tolerating a leading label ("bubblewrap 0.4.0" → "0.4.0"). Returns "" when no
// digit run is present.
func parseVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	start := -1
	for i := 0; i < len(raw); i++ {
		if raw[i] >= '0' && raw[i] <= '9' {
			start = i
			break
		}
	}
	if start < 0 {
		return ""
	}
	end := start
	for end < len(raw) {
		c := raw[end]
		if (c >= '0' && c <= '9') || c == '.' {
			end++
			continue
		}
		break
	}
	return strings.Trim(raw[start:end], ".")
}

// compareVersions compares two dotted numeric version strings component-wise,
// returning -1, 0, or 1 for a<b, a==b, a>b. Missing components read as 0, so
// "0.11.0" > "0.4.0" (11 > 4) and "0.4" == "0.4.0". It is numeric-aware, not a
// full semver comparison: any trailing non-digit run in a component is ignored.
func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av := versionComponent(as, i)
		bv := versionComponent(bs, i)
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// versionComponent returns the numeric value of the i-th dotted component, or 0
// when the component is absent.
func versionComponent(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	return atoiPrefix(parts[i])
}

// atoiPrefix reads the leading ASCII-digit run of s as an int, stopping at the
// first non-digit (so "11" → 11, "4rc1" → 4, "" → 0).
func atoiPrefix(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			break
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}
