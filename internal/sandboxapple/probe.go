package sandboxapple

import (
	"strconv"
	"strings"
)

// probe.go is the Apple container probe ladder (sandbox plan v2 section
// 4.7): a pure ordered table over injected facts, the first failing row
// wins. Nothing below the active row runs unless the driver is active and
// apple-container is listed. An Intel Mac and a macOS below 26 are refused
// with their own named verdicts.

// The verdict codes the ladder returns (the section 4.7 vocabulary; the
// new arch_unsupported takes the 501 default).
const (
	VerdictAvailable           = "available"
	VerdictUnsupportedPlatform = "unsupported_platform"
	VerdictDisabledByConfig    = "disabled_by_config"
	VerdictArchUnsupported     = "arch_unsupported"
	VerdictOSTooOld            = "os_too_old"
	VerdictBackendMissing      = "backend_missing"
	VerdictBackendUntrusted    = "backend_untrusted"
	VerdictVersionUntested     = "backend_version_untested"
	VerdictEngineUnreachable   = "engine_unreachable"
	VerdictImageMissing        = "image_missing"
	// VerdictNoHypervisor: the Mac exposes no hypervisor (kern.hv_support
	// is 0 or an unknown oid, as inside a macOS virtual machine without
	// nested virtualisation), so no container VM can start.
	VerdictNoHypervisor = "no_hypervisor"
)

// Verdict is a probe or read-back answer.
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

// The pins of the row. MinMacOS is Apple container's documented floor;
// RequiredMin is the CLI release whose documented flags (--network none,
// labels, ls --format json) this driver uses; the run options the 1.6.0
// fixes add are required by name by row A6b. DocLow to DocHigh is the
// range checked live through Observer on a bare-metal Mac (1.6.0,
// 2026-10-24, register MAC-11 to MAC-18, MAC-33, MAC-36, MAC-39); a
// version outside it runs as beta.
const (
	MinMacOS    = 26
	RequiredMin = "0.5.0"
	DocLow      = "1.6.0"
	DocHigh     = "1.6.99"
)

// RequiredRunFlags are the `container run` options the driver composes that
// an older CLI may not have (row A6b): the row is refused at the probe, by
// name, when `container run --help` lacks one, never launched without it.
var RequiredRunFlags = []struct {
	Flag string
	Why  string
}{
	{"--publish-socket", "the capture relay's only transport into the guest (a host unix socket mounted with -v does not connect from the guest, live 2026-10-23)"},
	{"--read-only-path", "the git-dir and other protected paths inside the mounts are made read-only with it (a file mounted with -v under a mounted directory drops that mount, live 2026-10-23)"},
	{"--entrypoint", "the in-image init must be the entrypoint whatever the image sets"},
	{"--progress", "the CLI's progress output would otherwise land in the agent's terminal"},
}

// CLIFacts are what a no-follow stat of the resolved CLI established.
type CLIFacts struct {
	Regular bool
	// OwnerOK: owned by this user or by root.
	OwnerOK bool
	// Perm is the permission bits.
	Perm uint32
}

// ProbeEnv is the injected I/O. A nil func the ladder reaches is a refusal.
type ProbeEnv struct {
	GOOS   string
	Active bool
	// Arm64 reads whether the Mac is Apple silicon (hw.optional.arm64, true
	// also for an x86 binary under Rosetta on Apple silicon).
	Arm64     func() (bool, error)
	OSVersion func() (string, error)
	// Hypervisor reads kern.hv_support: ok is false when the oid is unknown
	// (a macOS VM without nested virtualisation), which counts as absent.
	Hypervisor func() (supported bool, ok bool)
	// LookCLI resolves the container CLI to an absolute path.
	LookCLI func() (string, error)
	StatCLI func(path string) (CLIFacts, error)
	// Version runs `container --version` (a bare version from a PATH
	// binary: inferred, never authenticated).
	Version func(cli string) (string, error)
	// RunHelp runs `container run --help` (row A6b reads its option names).
	RunHelp func(cli string) (string, error)
	// SystemRunning runs `container system status`.
	SystemRunning func(cli string) error
	// Image is [terminal.sandbox.apple_container].image.
	Image string
	// ImagePresent asks the CLI whether the image is present locally.
	ImagePresent func(cli, ref string) (bool, error)
}

// ProbeResult is the ladder's answer and what it established.
type ProbeResult struct {
	Verdict   Verdict
	CLI       string
	Version   string
	OSVersion string
	// Beta: the CLI version is outside the documented range (usable).
	Beta bool
	Rule string
}

type probeRow struct {
	id  string
	run func(env ProbeEnv, r *ProbeResult) Verdict
}

var probeRows = []probeRow{
	{"A1 platform", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if env.GOOS != "darwin" {
			return refuse(VerdictUnsupportedPlatform, "the Apple container backend runs on macOS only")
		}
		return pass()
	}},
	{"A2 active", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if !env.Active {
			return refuse(VerdictDisabledByConfig, "the Apple container driver is not active, or apple-container is not in [terminal.sandbox].backends; nothing was probed")
		}
		return pass()
	}},
	{"A3 Apple silicon", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if env.Arm64 == nil {
			return refuse(VerdictArchUnsupported, "the processor could not be read")
		}
		arm, err := env.Arm64()
		if err != nil || !arm {
			return refuse(VerdictArchUnsupported, "Apple container needs Apple silicon; this is an Intel Mac, where only the Seatbelt backend (process class) is offered")
		}
		return pass()
	}},
	{"A4 macOS 26", func(env ProbeEnv, r *ProbeResult) Verdict {
		if env.OSVersion == nil {
			return refuse(VerdictOSTooOld, "the macOS version could not be read")
		}
		v, err := env.OSVersion()
		major := majorOf(v)
		if err != nil || major < 0 {
			return refuse(VerdictOSTooOld, "the macOS version could not be read")
		}
		r.OSVersion = strings.TrimSpace(v)
		if major < MinMacOS {
			return refuse(VerdictOSTooOld, "Apple container needs macOS 26 or later; this Mac runs macOS "+r.OSVersion+", where only the Seatbelt backend (process class) is offered")
		}
		return pass()
	}},
	{"A4b hypervisor", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if env.Hypervisor == nil {
			return refuse(VerdictNoHypervisor, "whether this Mac offers a hypervisor (kern.hv_support) could not be read")
		}
		if on, ok := env.Hypervisor(); !ok || !on {
			return refuse(VerdictNoHypervisor, "this Mac exposes no hypervisor (kern.hv_support is 0 or unknown, as inside a macOS virtual machine), so no container VM can start; the Apple container row needs bare-metal Apple silicon, the Seatbelt row still works")
		}
		return pass()
	}},
	{"A5 container CLI", func(env ProbeEnv, r *ProbeResult) Verdict {
		if env.LookCLI == nil || env.StatCLI == nil {
			return refuse(VerdictBackendMissing, "the container CLI could not be looked up")
		}
		p, err := env.LookCLI()
		if err != nil || !strings.HasPrefix(p, "/") {
			return refuse(VerdictBackendMissing, "Apple's container CLI is not installed (install it from github.com/apple/container, then run `container system start`)")
		}
		f, err := env.StatCLI(p)
		if err != nil || !f.Regular || !f.OwnerOK || f.Perm&0o022 != 0 {
			return refuse(VerdictBackendUntrusted, p+" is not a regular file owned by you or root that only its owner can write; it is never run")
		}
		r.CLI = p
		return pass()
	}},
	{"A6 version", func(env ProbeEnv, r *ProbeResult) Verdict {
		if env.Version == nil {
			return refuse(VerdictVersionUntested, "the container CLI version could not be read")
		}
		raw, err := env.Version(r.CLI)
		v := ParseCLIVersion(raw)
		if err != nil || v == "" {
			return refuse(VerdictVersionUntested, "the container CLI version could not be read")
		}
		r.Version = v
		if compare(v, RequiredMin) < 0 {
			return refuse(VerdictVersionUntested, "container "+v+" is below "+RequiredMin+", the first release with the flags this driver uses")
		}
		r.Beta = compare(v, DocLow) < 0 || compare(v, DocHigh) > 0
		return pass()
	}},
	{"A6b run flags", func(env ProbeEnv, r *ProbeResult) Verdict {
		if env.RunHelp == nil {
			return refuse(VerdictVersionUntested, "the container CLI's run options could not be read")
		}
		help, err := env.RunHelp(r.CLI)
		if err != nil {
			return refuse(VerdictVersionUntested, "the container CLI's run options could not be read: "+err.Error())
		}
		for _, f := range RequiredRunFlags {
			if !hasFlag(help, f.Flag) {
				return refuse(VerdictVersionUntested, "container "+r.Version+" has no `container run "+f.Flag+"`, "+f.Why+"; the row is not offered on this CLI")
			}
		}
		return pass()
	}},
	{"A7 system service", func(env ProbeEnv, r *ProbeResult) Verdict {
		if env.SystemRunning == nil || env.SystemRunning(r.CLI) != nil {
			return refuse(VerdictEngineUnreachable, "the container system service is not running; start it with `container system start` (its first start fetches a kernel, your own network action)")
		}
		return pass()
	}},
	{"A8 image", func(env ProbeEnv, r *ProbeResult) Verdict {
		img := strings.TrimSpace(env.Image)
		if !DigestRE.MatchString(img) {
			return refuse(VerdictImageMissing, "[terminal.sandbox.apple_container].image must name a linux/arm64 image pinned by digest (name@sha256:<64 hex>) holding the agent and a linux/arm64 observer")
		}
		if env.ImagePresent == nil {
			return refuse(VerdictImageMissing, "the CLI could not be asked for the image")
		}
		ok, err := env.ImagePresent(r.CLI, img)
		if err != nil {
			return refuse(VerdictEngineUnreachable, "the container CLI did not answer about the image: "+err.Error())
		}
		if !ok {
			return refuse(VerdictImageMissing, "the image "+img+" is not present; pull it first with `container image pull`")
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

// hasFlag reports whether help text names flag as an option: a field equal
// to it (a trailing comma trimmed) or starting with it and '=', never a
// longer flag that merely starts with it.
func hasFlag(help, flag string) bool {
	for _, f := range strings.Fields(help) {
		f = strings.TrimRight(f, ",")
		if f == flag || strings.HasPrefix(f, flag+"=") {
			return true
		}
	}
	return false
}

// ParseCLIVersion reads the CLI's version line ("container CLI version
// 0.5.0 (build: release, commit: abc)", or a bare "0.5.0"): the first
// dotted numeric field, without a leading v. Empty when there is none.
func ParseCLIVersion(raw string) string {
	for _, f := range strings.Fields(raw) {
		f = strings.TrimPrefix(strings.Trim(f, "(),"), "v")
		if parts := strings.Split(f, "."); len(parts) >= 2 && len(parts) <= 3 && allNumeric(parts) {
			return f
		}
	}
	return ""
}

func allNumeric(parts []string) bool {
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil || p == "" {
			return false
		}
	}
	return true
}

func majorOf(v string) int {
	v = strings.TrimSpace(v)
	head, _, _ := strings.Cut(v, ".")
	n, err := strconv.Atoi(head)
	if err != nil || v == "" {
		return -1
	}
	return n
}

// compare compares dotted numeric versions, missing parts as zero.
func compare(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := 0, 0
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
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
