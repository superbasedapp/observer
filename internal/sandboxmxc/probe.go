package sandboxmxc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// probe.go is the MXC probe ladder (sandbox plan v2 section 4.7): a pure
// ordered table over the facts the probe helper gathered. Each row reads
// only what the rows before it established, so the library is never
// loaded before the platform, the build and the bundled files passed, and
// the first failing row is the verdict. MXC's own outputs (the request
// probe's JSON, the create-and-close result) are read as data here.

// TierBaseContainer is the PSEC tier MXC's probe reports for
// ProcessContainer; the two AppContainer tiers it may report instead
// ("appcontainer-bfs", "appcontainer-dacl") are weaker and never used.
const TierBaseContainer = "base-container"

// ProbeOutput is mxc_probe_request_json_with_error's answer (the SDK's
// ProbeOutput, read with the same strictness as MXC's Node SDK).
type ProbeOutput struct {
	Tier                  string     `json:"tier,omitempty"`
	NeedsDaclAugmentation *bool      `json:"needsDaclAugmentation,omitempty"`
	Warnings              []string   `json:"warnings"`
	Probes                ProbeFacts `json:"probes"`
	Error                 string     `json:"error,omitempty"`
}

// ProbeFacts are the raw host facts behind MXC's tier choice. Only the
// booleans this driver reads are modelled; the decoder ignores the rest.
type ProbeFacts struct {
	BaseContainerAPIPresent                        bool `json:"baseContainerApiPresent"`
	BaseContainerSupportsDenyPaths                 bool `json:"baseContainerSupportsDenyPaths"`
	BaseContainerSupportsEnumeratePaths            bool `json:"baseContainerSupportsEnumeratePaths"`
	BaseContainerSupportsIngressHostLoopbackAllow  bool `json:"baseContainerSupportsIngressHostLoopbackAllow"`
	BaseContainerSupportsIdentitylessLoopbackProxy bool `json:"baseContainerSupportsIdentitylessLoopbackProxy"`
}

// maxProbeJSON caps the probe answer the helper hands back.
const maxProbeJSON = 256 << 10

// ParseProbeOutput reads the probe's JSON. A result with a tier must also
// say whether it needs DACL augmentation and carry no error; a result
// without one must carry an error (MXC's own isProbeOutput rule).
func ParseProbeOutput(b []byte) (ProbeOutput, error) {
	if len(b) == 0 || len(b) > maxProbeJSON {
		return ProbeOutput{}, fmt.Errorf("sandboxmxc: probe answer of %d bytes", len(b))
	}
	var out ProbeOutput
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&out); err != nil {
		return ProbeOutput{}, fmt.Errorf("sandboxmxc: probe answer: %w", err)
	}
	if out.Warnings == nil {
		return ProbeOutput{}, fmt.Errorf("sandboxmxc: probe answer has no warnings array")
	}
	if out.Tier != "" {
		if out.NeedsDaclAugmentation == nil || out.Error != "" {
			return ProbeOutput{}, fmt.Errorf("sandboxmxc: probe answer names a tier with an error or without needsDaclAugmentation")
		}
		switch out.Tier {
		case TierBaseContainer, "appcontainer-bfs", "appcontainer-dacl":
		default:
			return ProbeOutput{}, fmt.Errorf("sandboxmxc: probe answer names an unknown tier %q", out.Tier)
		}
		return out, nil
	}
	if out.Error == "" || out.NeedsDaclAugmentation != nil {
		return ProbeOutput{}, fmt.Errorf("sandboxmxc: probe answer has neither a tier nor an error")
	}
	return out, nil
}

// FileFact is what the helper found for one bundled file.
type FileFact struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	SHA256  string `json:"sha256,omitempty"`
	// SignatureChecked: the Authenticode check ran; Signed is its answer.
	SignatureChecked bool   `json:"signature_checked"`
	Signed           bool   `json:"signed"`
	SignatureError   string `json:"signature_error,omitempty"`
}

// CreateClose is the create-and-close check's result: a one-shot
// ProcessContainer run of a command that exits at once.
type CreateClose struct {
	Ran      bool   `json:"ran"`
	Status   int    `json:"status"`
	ExitCode int    `json:"exit_code"`
	TimedOut bool   `json:"timed_out"`
	Error    string `json:"error,omitempty"`
}

// HostFacts are everything the ladder reads. The probe helper fills them
// in order and stops at the first gap, so a later field is zero when an
// earlier row will refuse.
type HostFacts struct {
	// Windows: the helper runs on native Windows.
	Windows bool `json:"windows"`
	// Active: [terminal.sandbox].enabled, the module and the driver active,
	// and mxc-process listed. Nothing below is gathered otherwise.
	Active  bool   `json:"active"`
	Build   int    `json:"build"`
	UBR     int    `json:"ubr"`
	Edition string `json:"edition,omitempty"`
	// Files are the bundled files, in Manifest order.
	Files []FileFact `json:"files,omitempty"`
	// LibraryError is why the verified library could not be loaded.
	LibraryError string `json:"library_error,omitempty"`
	// LibraryVersion is mxc_version()'s answer.
	LibraryVersion string `json:"library_version,omitempty"`
	// ProbeJSON is the raw probe answer; ProbeError a native failure.
	ProbeJSON  string `json:"probe_json,omitempty"`
	ProbeError string `json:"probe_error,omitempty"`
	// CreateClose is the create-and-close check (nil: not run).
	CreateClose *CreateClose `json:"create_close,omitempty"`
}

// ProbeResult is the ladder's answer plus what it established.
type ProbeResult struct {
	Verdict Verdict `json:"verdict"`
	// Rule is the id of the row that decided.
	Rule string `json:"rule"`
	// Version is the library version (empty below the library row).
	Version       string        `json:"version,omitempty"`
	VersionStatus VersionStatus `json:"version_status,omitempty"`
	// Tier is MXC's tier for the run's policy.
	Tier     string   `json:"tier,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	// DenyPaths is MXC's baseContainerSupportsDenyPaths fact: false means a
	// plan that hides a path is refused (DenyPathsVerdict, finding F4).
	DenyPaths bool `json:"deny_paths,omitempty"`
	// EnumeratePaths is MXC's baseContainerSupportsEnumeratePaths fact: true
	// lets a run's document list its grants' parent directories
	// enumerate-only (ancestors.go, Windows 11 Pro run 4).
	EnumeratePaths bool `json:"enumerate_paths,omitempty"`
}

// ladderRow is one row: a name and a check that returns a refusal, or ok.
type ladderRow struct {
	id    string
	check func(f HostFacts, m Manifest, r *ProbeResult) (Verdict, bool)
}

// ladder is the ordered table.
var ladder = []ladderRow{
	{"platform", func(f HostFacts, _ Manifest, _ *ProbeResult) (Verdict, bool) {
		if !f.Windows {
			return Verdict{Code: VerdictUnsupportedPlatform, Reason: "MXC ProcessContainer runs only on native Windows 11; on WSL2 use the Linux backends (bubblewrap, containers)"}, false
		}
		return Verdict{}, true
	}},
	{"active", func(f HostFacts, _ Manifest, _ *ProbeResult) (Verdict, bool) {
		if !f.Active {
			return Verdict{Code: VerdictDisabledByConfig, Reason: "mxc-process is not in [terminal.sandbox].backends, or the terminals.sandbox.mxc component is not selected"}, false
		}
		return Verdict{}, true
	}},
	{"build", func(f HostFacts, _ Manifest, _ *ProbeResult) (Verdict, bool) {
		v := CheckBuild(f.Build, f.UBR)
		return v, v.OK()
	}},
	{"files_present", func(f HostFacts, m Manifest, _ *ProbeResult) (Verdict, bool) {
		for _, want := range m.Files {
			ff, ok := findFile(f.Files, want.Name)
			if !ok || !ff.Present {
				return Verdict{Code: VerdictArtifactMissing, Reason: want.Name + " is not installed beside the observer binary; this build or distro does not carry the MXC files (reinstall a Windows package that includes them)"}, false
			}
		}
		return Verdict{}, true
	}},
	{"files_hash", func(f HostFacts, m Manifest, _ *ProbeResult) (Verdict, bool) {
		for _, want := range m.Files {
			ff, _ := findFile(f.Files, want.Name)
			if !strings.EqualFold(ff.SHA256, want.SHA256) {
				return Verdict{Code: VerdictArtifactUnverified, Reason: want.Name + " does not match the hash pinned in this build (MXC " + m.Version + "); it was replaced or corrupted, and is never loaded"}, false
			}
		}
		return Verdict{}, true
	}},
	{"files_signed", func(f HostFacts, m Manifest, _ *ProbeResult) (Verdict, bool) {
		for _, want := range m.Files {
			ff, _ := findFile(f.Files, want.Name)
			if !ff.SignatureChecked || !ff.Signed {
				why := "its Authenticode signature does not verify"
				if ff.SignatureError != "" {
					why += " (" + ff.SignatureError + ")"
				}
				return Verdict{Code: VerdictArtifactUnverified, Reason: want.Name + ": " + why}, false
			}
		}
		return Verdict{}, true
	}},
	{"library", func(f HostFacts, _ Manifest, _ *ProbeResult) (Verdict, bool) {
		if f.LibraryError != "" {
			return Verdict{Code: VerdictProbeFailed, Reason: "mxc_ffi.dll could not be loaded: " + f.LibraryError}, false
		}
		return Verdict{}, true
	}},
	{"version", func(f HostFacts, _ Manifest, r *ProbeResult) (Verdict, bool) {
		r.Version = f.LibraryVersion
		r.VersionStatus = CheckVersion(f.LibraryVersion, Pins)
		if r.VersionStatus == VersionUntested {
			return Verdict{Code: VerdictBackendVersionUntested, Reason: fmt.Sprintf("mxc_version() reports %q, below the required %s", f.LibraryVersion, Pins.RequiredMin)}, false
		}
		return Verdict{}, true
	}},
	{"request_probe", func(f HostFacts, _ Manifest, r *ProbeResult) (Verdict, bool) {
		if f.ProbeError != "" {
			return nativeVerdict("MXC's request probe", f.ProbeError), false
		}
		out, err := ParseProbeOutput([]byte(f.ProbeJSON))
		if err != nil {
			return Verdict{Code: VerdictProbeFailed, Reason: err.Error()}, false
		}
		r.Tier, r.Warnings, r.DenyPaths = out.Tier, out.Warnings, out.Probes.BaseContainerSupportsDenyPaths
		r.EnumeratePaths = out.Probes.BaseContainerSupportsEnumeratePaths
		if out.Tier == "" {
			return Verdict{Code: VerdictPSECUnavailable, Reason: "MXC found no ProcessContainer tier on this host: " + out.Error}, false
		}
		if out.Tier != TierBaseContainer {
			return Verdict{Code: VerdictPSECUnavailable, Reason: "MXC offers only its " + out.Tier + " tier here, not the PSEC BaseContainer tier; the weaker tiers are not used (Windows Home may not offer PSEC)"}, false
		}
		if out.NeedsDaclAugmentation != nil && *out.NeedsDaclAugmentation {
			return Verdict{Code: VerdictPSECUnavailable, Reason: "MXC needs to change host ACLs for this policy, and allowDaclMutation is false"}, false
		}
		// The run reaches its one loopback port through host loopback, not
		// through MXC's runtime proxy (document.go, finding L1), so host
		// loopback "allow" is the one network capability the row needs.
		if !out.Probes.BaseContainerSupportsIngressHostLoopbackAllow {
			return Verdict{Code: VerdictPSECUnavailable, Reason: "this build's BaseContainer cannot allow host loopback, which the run's one loopback port needs"}, false
		}
		return Verdict{}, true
	}},
	{"create_close", func(f HostFacts, _ Manifest, _ *ProbeResult) (Verdict, bool) {
		cc := f.CreateClose
		switch {
		case cc == nil || !cc.Ran:
			return Verdict{Code: VerdictProbeFailed, Reason: "MXC's create-and-close check did not run"}, false
		case cc.Status != 0:
			v := nativeVerdict("MXC's create-and-close check", cc.Error)
			if v.Code == VerdictPSECUnavailable {
				v.Reason = fmt.Sprintf("MXC could not create a ProcessContainer (status %d): %s", cc.Status, cc.Error)
			}
			return v, false
		case cc.TimedOut || cc.ExitCode != 0:
			return Verdict{Code: VerdictPSECUnavailable, Reason: fmt.Sprintf("a ProcessContainer was created but its check command did not finish cleanly (exit %d, timed out %v)", cc.ExitCode, cc.TimedOut)}, false
		}
		return Verdict{}, true
	}},
}

// statusMalformed is the code name a native error renders first when MXC
// refused the request itself (sandboxmxcdll.NativeError: "<status>:
// <message>").
const statusMalformed = "malformed_request"

// statusPolicyValidation is the code name of MXC_STATUS 11: MXC refused a
// policy this build wrote (the laptop re-run of 2026-10-22: a process.env
// without SYSTEMROOT and LOCALAPPDATA at create), a fault in Observer's
// document like malformed_request, never a missing Windows feature.
const statusPolicyValidation = "policy_validation"

// contractRefusal reports whether a native error names the contract: MXC
// refused the request on its "version" field.
func contractRefusal(msg string) bool {
	m := strings.ToLower(msg)
	return strings.HasPrefix(m, statusMalformed) && strings.Contains(m, "version") && (strings.Contains(m, "unsupported") || strings.Contains(m, "unknown") || strings.Contains(m, "malformed"))
}

// nativeVerdicts classifies a native MXC failure, first match wins: a
// refused contract version, a request MXC rejected as malformed (a fault in
// this build, never a missing platform feature, finding L2), or anything
// else, which is the platform not offering PSEC.
var nativeVerdicts = []struct {
	match  func(msg string) bool
	code   string
	reason string
}{
	{contractRefusal, VerdictBackendVersionUntested, " refused the 1.0.0 contract: "},
	{func(m string) bool { return strings.HasPrefix(strings.ToLower(m), statusMalformed) }, VerdictRequestRejected, " rejected the request this build sent (a fault in Observer's document, not a missing Windows feature): "},
	{func(m string) bool { return strings.HasPrefix(strings.ToLower(m), statusPolicyValidation) }, VerdictRequestRejected, " rejected the policy this build sent (a fault in Observer's document, not a missing Windows feature): "},
	{func(string) bool { return true }, VerdictPSECUnavailable, " failed: "},
}

// nativeVerdict is the verdict for a native failure of call.
func nativeVerdict(call, msg string) Verdict {
	for _, nv := range nativeVerdicts {
		if nv.match(msg) {
			return Verdict{Code: nv.code, Reason: call + nv.reason + msg}
		}
	}
	return Verdict{Code: VerdictPSECUnavailable, Reason: call + " failed: " + msg}
}

// Probe walks the ladder over f against the manifest m.
func Probe(f HostFacts, m Manifest) ProbeResult {
	return ProbeThrough(f, m, "")
}

// ProbeThrough walks the ladder up to and including the row last (every
// row when last is "" or names no row). A staged live check judges only
// what its stage gathered: the version stage never runs the request probe,
// so the request rows are not read (finding L3). When every row through
// last passes, the verdict is available and Rule is "through:<last>".
func ProbeThrough(f HostFacts, m Manifest, last string) ProbeResult {
	var r ProbeResult
	for _, row := range ladder {
		v, ok := row.check(f, m, &r)
		if !ok {
			r.Verdict, r.Rule = v, row.id
			return r
		}
		if row.id == last {
			r.Verdict = Verdict{Code: VerdictAvailable, Reason: "every row through " + last + " passed; the later rows were not run at this stage"}
			r.Rule = "through:" + last
			return r
		}
	}
	r.Verdict, r.Rule = Verdict{Code: VerdictAvailable}, "available"
	return r
}

// DenyPathsVerdict is the deny-paths rule (finding F4): a plan that hides
// any path runs only on a BaseContainer that can deny paths.
func DenyPathsVerdict(hidden int, supported bool) Verdict {
	if hidden > 0 && !supported {
		return Verdict{Code: VerdictDenyPathsUnsupported, Reason: fmt.Sprintf("this host's BaseContainer cannot deny paths (MXC reports baseContainerSupportsDenyPaths false) and the run's plan hides %d path(s), the observer directory's secrets and protected files among them; the run is refused rather than started with them visible", hidden)}
	}
	return Verdict{Code: VerdictAvailable}
}

// runPolicyRules judge MXC's answer for a run's own document (the helper's
// request probe of the exact policy), first refusal wins: the PSEC tier,
// no host ACL change, the deny-paths rule and the enumerate-paths rule.
var runPolicyRules = []func(d Document, po ProbeOutput) Verdict{
	func(_ Document, po ProbeOutput) Verdict {
		if po.Tier != TierBaseContainer {
			return Verdict{Code: VerdictPSECUnavailable, Reason: fmt.Sprintf("MXC would not run this policy in the PSEC tier (it chose %q)", po.Tier)}
		}
		return Verdict{Code: VerdictAvailable}
	},
	func(_ Document, po ProbeOutput) Verdict {
		if po.NeedsDaclAugmentation != nil && *po.NeedsDaclAugmentation {
			return Verdict{Code: VerdictPSECUnavailable, Reason: "MXC would change host ACLs for this policy, and allowDaclMutation is false"}
		}
		return Verdict{Code: VerdictAvailable}
	},
	func(d Document, po ProbeOutput) Verdict {
		return DenyPathsVerdict(len(d.Filesystem.DeniedPaths), po.Probes.BaseContainerSupportsDenyPaths)
	},
	func(d Document, po ProbeOutput) Verdict {
		if d.ProcessContainer != nil && d.ProcessContainer.Filesystem != nil && len(d.ProcessContainer.Filesystem.EnumeratePaths) > 0 && !po.Probes.BaseContainerSupportsEnumeratePaths {
			return Verdict{Code: VerdictPSECUnavailable, Reason: "the run's policy lists enumerate-only paths and this host's BaseContainer does not support them (MXC reports baseContainerSupportsEnumeratePaths false)"}
		}
		return Verdict{Code: VerdictAvailable}
	},
}

// CheckRunPolicy judges MXC's request-probe answer po for the run's own
// document d.
func CheckRunPolicy(d Document, po ProbeOutput) Verdict {
	for _, rule := range runPolicyRules {
		if v := rule(d, po); !v.OK() {
			return v
		}
	}
	return Verdict{Code: VerdictAvailable}
}

// LadderRules lists the row ids in order (coverage tests).
func LadderRules() []string {
	out := make([]string, len(ladder))
	for i, row := range ladder {
		out[i] = row.id
	}
	return out
}

func findFile(fs []FileFact, name string) (FileFact, bool) {
	for _, f := range fs {
		if strings.EqualFold(f.Name, name) {
			return f, true
		}
	}
	return FileFact{}, false
}
