package sandboxoci

// The closed verdict vocabulary of the OCI driver (sandbox plan v2 section
// 4.7). Each value is a copy key a surface renders; the selection table
// passes a probe verdict through at S4, and the HTTP mapping gives every one
// of them the 501 default (section 4.7: socket_untrusted and
// engine_mode_unsupported are classified 501).
const (
	// VerdictAvailable: the engine answers, passed every rule, and the
	// run's image is present.
	VerdictAvailable = "available"
	// VerdictUnsupportedPlatform: the daemon is not on Linux or WSL2.
	VerdictUnsupportedPlatform = "unsupported_platform"
	// VerdictDisabledByConfig: the sandbox is off, the driver is inactive,
	// or oci-runc is not in [terminal.sandbox].backends. Nothing was probed.
	VerdictDisabledByConfig = "disabled_by_config"
	// VerdictEngineUnreachable: no engine socket, or it did not answer.
	VerdictEngineUnreachable = "engine_unreachable"
	// VerdictSocketUntrusted: the socket failed validation (a symlink, a
	// TCP or SSH endpoint, a wrong owner, a rootful socket without the
	// opt-in, or a daemon whose identity changed since first use).
	VerdictSocketUntrusted = "socket_untrusted"
	// VerdictEngineModeUnsupported: the engine's user-namespace mode has no
	// row in the uid table (userns-remap, an unknown engine).
	VerdictEngineModeUnsupported = "engine_mode_unsupported"
	// VerdictEngineIsDesktopVM: the socket is Docker Desktop's integration,
	// not a same-kernel engine (G30).
	VerdictEngineIsDesktopVM = "engine_is_desktop_vm"
	// VerdictBackendVersionUntested: the engine or its API is below the
	// required minimum, or its version could not be read.
	VerdictBackendVersionUntested = "backend_version_untested"
	// VerdictImageMissing: no image is configured, it is not pinned by
	// digest, or it is not present in the engine.
	VerdictImageMissing = "image_missing"
	// VerdictEngineCannotPull: a rootless engine answers but cannot
	// resolve names, and the image the run needs is not present (rootless
	// Docker on slirp4netns under WSL2 DNS tunnelling, JSP-4).
	VerdictEngineCannotPull = "engine_cannot_pull"
	// VerdictBuiltBelowPlan: the read-back found the container weaker than
	// planned; it is torn down before the agent starts.
	VerdictBuiltBelowPlan = "built_below_plan"
	// VerdictArtifactUnverified: Observer's default image is installed but
	// its signed manifest, descriptor or engine copy failed the trust check,
	// or the configured image is one the project revoked (plan 12.3, lane
	// SBX-P3B). Nothing installed keeps image_missing.
	VerdictArtifactUnverified = "artifact_unverified"
)

// Verdict is one ladder answer: a code from the vocabulary above and a
// one-line reason naming the gap and, where there is one, the fix.
type Verdict struct {
	Code   string
	Reason string
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

func pass() Verdict { return Verdict{Code: VerdictAvailable} }

func refuse(code, reason string) Verdict { return Verdict{Code: code, Reason: reason} }
