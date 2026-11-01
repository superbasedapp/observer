package sandboxhcs

import (
	"fmt"
	"strings"
)

// The verdict spellings (the shared probe vocabulary).
const (
	VerdictAvailable           = "available"
	VerdictUnsupportedPlatform = "unsupported_platform"
	VerdictDisabledByConfig    = "disabled_by_config"
	VerdictEditionUnsupported  = "edition_unsupported"
	VerdictNoHypervisor        = "no_hypervisor"
	VerdictBackendMissing      = "backend_missing"
	VerdictVersionUntested     = "backend_version_untested"
	VerdictImageMissing        = "image_missing"
)

// Verdict is a probe outcome.
type Verdict struct {
	Code   string `json:"code"`
	Reason string `json:"reason,omitempty"`
}

// OK reports an available verdict.
func (v Verdict) OK() bool { return v.Code == VerdictAvailable }

// Facts are what the probe gathered. The loader facts are gathered only in
// a helper process, and only once every earlier row passed.
type Facts struct {
	Windows, Active bool
	// Edition is the registry's EditionID (Professional, Enterprise,
	// Education, ServerStandard ...).
	Edition string
	// HyperV: the Hyper-V hypervisor service is installed; Containers: the
	// Containers feature's compute service (vmcompute) is installed.
	HyperV, Containers bool
	// UVMImage is the configured utility VM image folder; UVMVerified that
	// its digest verified against a signed manifest (never true in this
	// release: there is no published image).
	UVMImage    string
	UVMVerified bool
	// Loader is the computecore.dll load result (nil: not loaded yet).
	Loader *LoaderFacts
	// SchemaMinor is the HCS schema 2.x minor the service reports.
	SchemaMinor int
}

// editions are the Windows editions with the Containers and Hyper-V
// features (Home has neither).
var editions = []string{"Professional", "ProfessionalWorkstation", "Enterprise", "Education", "ServerStandard", "ServerDatacenter"}

// MinSchemaMinor is the HCS schema 2.x the planner writes.
const MinSchemaMinor = 1

type rule struct {
	code  string
	fails func(Facts) (bool, string)
}

var rules = []rule{
	{VerdictUnsupportedPlatform, func(f Facts) (bool, string) { return !f.Windows, "HCS runs on Windows only" }},
	{VerdictDisabledByConfig, func(f Facts) (bool, string) { return !f.Active, "the hcs row is not selected or not listed" }},
	{VerdictEditionUnsupported, func(f Facts) (bool, string) {
		for _, e := range editions {
			if strings.EqualFold(f.Edition, e) {
				return false, ""
			}
		}
		return true, fmt.Sprintf("Windows edition %q has no Hyper-V isolated containers (Pro, Enterprise or Education needed)", f.Edition)
	}},
	{VerdictNoHypervisor, func(f Facts) (bool, string) { return !f.HyperV, "the Hyper-V feature is not installed" }},
	{VerdictBackendMissing, func(f Facts) (bool, string) { return !f.Containers, "the Containers feature is not installed" }},
	{VerdictImageMissing, func(f Facts) (bool, string) {
		if strings.TrimSpace(f.UVMImage) == "" {
			return true, "no utility VM image is configured, and Observer publishes none yet (a signed release artifact is needed); the row is probe-only in this release"
		}
		return !f.UVMVerified, "the utility VM image at " + f.UVMImage + " is not verified against a signed manifest"
	}},
	{VerdictBackendMissing, func(f Facts) (bool, string) {
		if f.Loader == nil {
			return true, "computecore.dll was not loaded (the probe helper loads it)"
		}
		return !f.Loader.Loaded, "computecore.dll could not be loaded: " + f.Loader.Err
	}},
	{VerdictVersionUntested, func(f Facts) (bool, string) {
		return len(f.Loader.Missing) > 0, "computecore.dll lacks " + strings.Join(f.Loader.Missing, ", ")
	}},
	{VerdictVersionUntested, func(f Facts) (bool, string) {
		return f.SchemaMinor < MinSchemaMinor, fmt.Sprintf("the HCS service reports schema 2.%d, below 2.%d", f.SchemaMinor, MinSchemaMinor)
	}},
}

// Probe walks the ladder; the first failing row is the verdict.
func Probe(f Facts) Verdict {
	for _, r := range rules {
		if bad, why := r.fails(f); bad {
			return Verdict{Code: r.code, Reason: why}
		}
	}
	return Verdict{Code: VerdictAvailable}
}
