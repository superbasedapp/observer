package sandboxvm

// The verdict codes of the ladder and the read-back (the section 4.7
// vocabulary; existing spellings reused: no_hypervisor is the Apple row's
// spelling of plan 4.7's hypervisor_missing, recorded as the same verdict).
const (
	VerdictAvailable           = "available"
	VerdictUnsupportedPlatform = "unsupported_platform"
	VerdictDisabledByConfig    = "disabled_by_config"
	// VerdictNoHypervisor: /dev/kvm is missing, not a character device or
	// not openable by this user (the reason says which).
	VerdictNoHypervisor = "no_hypervisor"
	// VerdictNestedVirtUnavailable: the host is itself a VM (WSL2, a cloud
	// VM) that exposes no /dev/kvm, so nested virtualisation is off.
	VerdictNestedVirtUnavailable = "nested_virt_unavailable"
	VerdictBackendMissing        = "backend_missing"
	VerdictBackendUntrusted      = "backend_untrusted"
	VerdictVersionUntested       = "backend_version_untested"
	VerdictImageMissing          = "image_missing"
	VerdictArtifactUnverified    = "artifact_unverified"
	VerdictBuiltBelowPlan        = "built_below_plan"
	VerdictSourceUnsupported     = "source_unsupported"
	VerdictToolUnavailable       = "tool_unavailable_in_image"
	// VerdictSocketPathTooLong: no directory can hold the run's sockets
	// within Linux's socket path limit (MaxSocketPath).
	VerdictSocketPathTooLong = "socket_path_too_long"
)

// Verdict is a probe, plan or read-back answer.
type Verdict struct {
	Code   string
	Reason string
}

// OK reports whether the verdict is available.
func (v Verdict) OK() bool { return v.Code == VerdictAvailable }

// Error renders a refusal.
func (v Verdict) Error() string { return v.Code + ": " + v.Reason }

func pass() Verdict { return Verdict{Code: VerdictAvailable} }

func refuse(code, reason string) Verdict { return Verdict{Code: code, Reason: reason} }
