package sandboxsbpl

import (
	"strconv"
	"strings"
)

// probe.go is the Seatbelt probe ladder (sandbox plan v2 section 4.7): a
// pure ordered table over injected facts, first failing row wins. It never
// runs sandbox-exec: it reads the macOS version and stats Apple's binary,
// and only when the driver is active and "seatbelt" is listed.

// The verdict codes the ladder returns (the closed section 4.7
// vocabulary; os_too_old and backend_untrusted take the 501 default).
const (
	VerdictAvailable           = "available"
	VerdictUnsupportedPlatform = "unsupported_platform"
	VerdictDisabledByConfig    = "disabled_by_config"
	VerdictVersionUntested     = "backend_version_untested"
	VerdictOSTooOld            = "os_too_old"
	VerdictBackendMissing      = "backend_missing"
	VerdictBackendUntrusted    = "backend_untrusted"
	VerdictBuiltBelowPlan      = "built_below_plan"
	VerdictSelfTestFailed      = "self_test_failed"
	// VerdictFallbackDriverUnavailable: the configured driver is the
	// declared fallback mxc-exec-mac, which is not built (MAC-10).
	VerdictFallbackDriverUnavailable = "fallback_driver_unavailable"
)

// Verdict is a probe or self-test answer.
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

// The macOS version pins of the Seatbelt row. RequiredMin is the floor below
// which nothing runs (Go 1.27's own macOS floor: the observer binary cannot
// start below it). The documented range is the macOS releases the vendor
// and open-source SBPL sources this generator follows were written for;
// outside it the row stays usable and is beta for this host. No version has
// been tested live (register MAC-1).
const (
	SeatbeltRequiredMin = "12.0"
	SeatbeltDocLow      = "14.0"
	SeatbeltDocHigh     = "26.99"
	// SandboxInitTightened is the first macOS major that tightened
	// sandbox_init named profiles for apps built against its SDK.
	SandboxInitTightened = 27
)

// FallbackDriver is the declared fallback if Apple removes or breaks
// sandbox-exec: Microsoft's MXC for macOS. It is declared, not built.
const FallbackDriver = "mxc-exec-mac"

// DriverSandboxExec is the built Seatbelt driver (the default; an empty
// [terminal.sandbox.seatbelt].driver means it).
const DriverSandboxExec = "sandbox-exec"

// The fallback binary as the pinned MXC package publishes it (lane
// SBX-UPD, register MAC-10). @microsoft/mxc-sdk 1.0.1, the package the
// Windows row already pins by sha256 (scripts/mxc-files.sh), ships an
// arm64-only Mach-O at this path; the package documents the Node SDK, not
// this program's command line, and no Mac has run it, so the driver is not
// built and the probe refuses it by name. The facts are recorded so the
// later driver pins exactly this file (never run unverified).
const (
	FallbackPackage      = "@microsoft/mxc-sdk@1.0.1"
	FallbackBinaryPath   = "package/bin/arm64/mxc-exec-mac"
	FallbackBinarySHA256 = "c54390e48a25187fdae10758c6a286bede49416cb610c88c6705fd8445e97f60"
	FallbackBinarySize   = 3947232
)

// FallbackRefusal is the reason the fallback driver is refused.
const FallbackRefusal = FallbackDriver + " is the declared fallback driver and is not built: " + FallbackPackage +
	" publishes it (" + FallbackBinaryPath + ", arm64 only) but documents only its Node SDK, not the program's command line, and no Mac has run it (register MAC-10); set [terminal.sandbox.seatbelt].driver = \"" + DriverSandboxExec + "\""

// VersionStatus is how the macOS version stands against the pins.
type VersionStatus string

// The VersionStatus values.
const (
	VersionOK      VersionStatus = "ok"
	VersionBeta    VersionStatus = "beta"
	VersionRefused VersionStatus = "refused"
)

// ExecFacts are what a no-follow stat of sandbox-exec established.
type ExecFacts struct {
	Regular  bool
	OwnerUID uint32
	// Perm is the permission bits (mode & 0o777).
	Perm uint32
}

// ProbeEnv is the injected I/O. A nil func the ladder reaches is a refusal.
type ProbeEnv struct {
	// GOOS is runtime.GOOS.
	GOOS string
	// Active: [terminal.sandbox].enabled, the module and the driver
	// active, and seatbelt listed in [terminal.sandbox].backends.
	Active bool
	// OSVersion reads the macOS product version (kern.osproductversion).
	OSVersion func() (string, error)
	// StatExec stats a path without following a symlink.
	StatExec func(path string) (ExecFacts, error)
	// Driver is [terminal.sandbox.seatbelt].driver ("" = sandbox-exec).
	Driver string
}

// ProbeResult is the ladder's answer.
type ProbeResult struct {
	Verdict   Verdict
	OSVersion string
	Version   VersionStatus
	// Note is shown with an available row (a version outside the
	// documented range, the macOS 27 sandbox_init change).
	Note string
	Rule string
}

type probeRow struct {
	id  string
	run func(env ProbeEnv, r *ProbeResult) Verdict
}

var probeRows = []probeRow{
	{"P1 platform", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if env.GOOS != "darwin" {
			return refuse(VerdictUnsupportedPlatform, "the Seatbelt backend runs on macOS only")
		}
		return pass()
	}},
	{"P2 active", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if !env.Active {
			return refuse(VerdictDisabledByConfig, "the Seatbelt driver is not active, or seatbelt is not in [terminal.sandbox].backends; nothing was probed")
		}
		return pass()
	}},
	{"P2b driver", func(env ProbeEnv, _ *ProbeResult) Verdict {
		switch env.Driver {
		case "", DriverSandboxExec:
			return pass()
		case FallbackDriver:
			return refuse(VerdictFallbackDriverUnavailable, FallbackRefusal)
		}
		return refuse(VerdictDisabledByConfig, "[terminal.sandbox.seatbelt].driver "+strconv.Quote(env.Driver)+" is not a Seatbelt driver")
	}},
	{"P3 macOS version", func(env ProbeEnv, r *ProbeResult) Verdict {
		if env.OSVersion == nil {
			return refuse(VerdictVersionUntested, "the macOS version could not be read")
		}
		v, err := env.OSVersion()
		if err != nil || ParseVersion(v) == nil {
			return refuse(VerdictVersionUntested, "the macOS version could not be read")
		}
		r.OSVersion = strings.TrimSpace(v)
		r.Version, r.Note = JudgeOSVersion(r.OSVersion)
		if r.Version == VersionRefused {
			return refuse(VerdictOSTooOld, "macOS "+r.OSVersion+" is below the Seatbelt row's floor "+SeatbeltRequiredMin)
		}
		return pass()
	}},
	{"P4 sandbox-exec", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if env.StatExec == nil {
			return refuse(VerdictBackendMissing, SandboxExecPath+" could not be inspected")
		}
		f, err := env.StatExec(SandboxExecPath)
		if err != nil {
			return refuse(VerdictBackendMissing, SandboxExecPath+" is not present ("+err.Error()+"); Apple may have removed it, and the declared fallback "+FallbackDriver+" is not built")
		}
		if !f.Regular || f.OwnerUID != 0 || f.Perm&0o022 != 0 {
			return refuse(VerdictBackendUntrusted, SandboxExecPath+" is not a root-owned regular file that only root can write; it is never run")
		}
		return pass()
	}},
}

// Probe walks the ladder.
func Probe(env ProbeEnv) ProbeResult {
	var r ProbeResult
	for _, row := range probeRows {
		v := row.run(env, &r)
		r.Rule = row.id
		if !v.OK() {
			r.Verdict = v
			return r
		}
	}
	r.Verdict = pass()
	return r
}

// JudgeOSVersion places a macOS version against the pins.
func JudgeOSVersion(v string) (VersionStatus, string) {
	parts := ParseVersion(v)
	if parts == nil || CompareVersions(parts, ParseVersion(SeatbeltRequiredMin)) < 0 {
		return VersionRefused, ""
	}
	var notes []string
	status := VersionOK
	if CompareVersions(parts, ParseVersion(SeatbeltDocLow)) < 0 || CompareVersions(parts, ParseVersion(SeatbeltDocHigh)) > 0 {
		status = VersionBeta
		notes = append(notes, "macOS "+v+" is outside the versions this profile was written for ("+SeatbeltDocLow+" to 26)")
	}
	if parts[0] >= SandboxInitTightened {
		notes = append(notes, "macOS 27 tightened sandbox_init named profiles for apps built against its SDK; sandbox-exec -p with a custom profile is expected to keep working, and "+FallbackDriver+" is the declared fallback (not built)")
	}
	return status, strings.Join(notes, "; ")
}

// ParseVersion parses "26", "26.1" or "15.6.1" into numbers; nil when any
// part is not a number.
func ParseVersion(v string) []int {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// CompareVersions compares two parsed versions, missing parts as zero.
func CompareVersions(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
