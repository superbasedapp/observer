package sandboxmxc

// The closed verdict vocabulary of the MXC driver (sandbox plan v2 section
// 4.7). Each value is a copy key a surface renders. The selection table
// passes a probe verdict through at S4, and the HTTP mapping gives every one
// of them the 501 default.
const (
	// VerdictAvailable: every ladder row passed; ProcessContainer (the PSEC
	// BaseContainer tier) is offered on this host.
	VerdictAvailable = "available"
	// VerdictUnsupportedPlatform: the daemon is not on native Windows.
	VerdictUnsupportedPlatform = "unsupported_platform"
	// VerdictDisabledByConfig: the sandbox is off, the driver is inactive,
	// or mxc-process is not in [terminal.sandbox].backends. Nothing was
	// probed and no MXC file was opened.
	VerdictDisabledByConfig = "disabled_by_config"
	// VerdictPSECBuildTooOld: the Windows build is below ProcessContainer's
	// floor (26100.9278, 26200.9278, 26300.9550 or 28000.2804).
	VerdictPSECBuildTooOld = "psec_build_too_old"
	// VerdictPSECUnavailable: the build is new enough but MXC's own probe
	// or its create-and-close check did not offer the PSEC BaseContainer
	// tier with an identity-less loopback proxy (Windows Home may not offer
	// it); MXC's weaker tiers are never used.
	VerdictPSECUnavailable = "psec_unavailable"
	// VerdictArtifactMissing: a bundled MXC file (mxc_ffi.dll or
	// wxc-exec.exe) is not where this build installs it.
	VerdictArtifactMissing = "artifact_missing"
	// VerdictArtifactUnverified: a bundled MXC file's hash does not match
	// the pin compiled into this build, or its Authenticode signature does
	// not verify. The library is never loaded.
	VerdictArtifactUnverified = "artifact_unverified"
	// VerdictBackendVersionUntested: mxc_version() is below the required
	// minimum or unreadable, or the library does not take the "1.0.0"
	// contract.
	VerdictBackendVersionUntested = "backend_version_untested"
	// VerdictProbeFailed: the helper that runs the probe could not run it
	// (it crashed, timed out or answered nothing readable).
	VerdictProbeFailed = "probe_failed"
	// VerdictRequestRejected: MXC refused the request this build sent
	// (status malformed_request, or policy_validation at create): a fault
	// in Observer's own document, not
	// a feature the platform lacks, so it is never reported as
	// psec_unavailable. The reason carries MXC's own message (live check
	// 2026-10-22, finding L2).
	VerdictRequestRejected = "request_rejected"
	// VerdictDenyPathsUnsupported: this host's BaseContainer cannot deny
	// paths (MXC's probe fact baseContainerSupportsDenyPaths is false), and
	// the run's plan hides at least one path (the observer directory's
	// secrets, a protected file): the run is refused rather than started
	// with those paths visible (audit finding F4).
	VerdictDenyPathsUnsupported = "deny_paths_unsupported"
)

// Verdict is one ladder answer: a code from the vocabulary above and a
// one-line reason naming the gap and, where there is one, the fix.
type Verdict struct {
	Code   string `json:"code"`
	Reason string `json:"reason,omitempty"`
}

// OK reports whether v passes.
func (v Verdict) OK() bool { return v.Code == VerdictAvailable }

// Error makes a refused verdict usable as an error.
func (v Verdict) Error() string {
	if v.Reason == "" {
		return v.Code
	}
	return v.Code + ": " + v.Reason
}

// Verdicts lists every code, for coverage tests and copy tables.
func Verdicts() []string {
	return []string{
		VerdictAvailable, VerdictUnsupportedPlatform, VerdictDisabledByConfig, VerdictPSECBuildTooOld,
		VerdictPSECUnavailable, VerdictArtifactMissing, VerdictArtifactUnverified,
		VerdictBackendVersionUntested, VerdictProbeFailed, VerdictRequestRejected,
		VerdictDenyPathsUnsupported,
	}
}
