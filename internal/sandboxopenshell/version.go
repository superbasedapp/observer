package sandboxopenshell

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Version is a parsed OpenShell version (MAJOR.MINOR.PATCH, with an
// optional pre-release tag and optional build metadata).
type Version struct {
	Major, Minor, Patch int
	// Pre is the pre-release tag after "-" ("" for a release).
	Pre string
	// Build is the build metadata after "+" ("" for none): a locally
	// patched or dirty build such as 0.1.6+local is not the binary a
	// receipt ran, so it is never tested (audit finding O1A-A10).
	Build string
}

// String renders the version as MAJOR.MINOR.PATCH[-PRE][+BUILD].
func (v Version) String() string {
	s := strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	if v.Build != "" {
		s += "+" + v.Build
	}
	return s
}

// less reports whether v orders before w by its numbers (a pre-release is
// never tested, so its order against a release does not matter here).
func (v Version) less(w Version) bool {
	if v.Major != w.Major {
		return v.Major < w.Major
	}
	if v.Minor != w.Minor {
		return v.Minor < w.Minor
	}
	return v.Patch < w.Patch
}

// versionRE finds the first MAJOR.MINOR.PATCH in a version answer: the bare
// number, a leading "v", or a program name before it ("openshell 0.1.6",
// "openshell-gateway 0.1.6").
var versionRE = regexp.MustCompile(`(?:^|[\s(])v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})(?:-([0-9A-Za-z.]+))?(?:\+([0-9A-Za-z.-]+))?(?:$|[\s),])`)

// ParseVersion reads the version from the output of `openshell --version`,
// `openshell-gateway --version` or the version field of `openshell status
// -o json`. An answer with no version in it is an error.
func ParseVersion(out string) (Version, error) {
	m := versionRE.FindStringSubmatch(strings.TrimSpace(out))
	if m == nil {
		return Version{}, fmt.Errorf("sandboxopenshell.ParseVersion: no version in %q", firstLine(out))
	}
	var v Version
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	v.Patch, _ = strconv.Atoi(m[3])
	v.Pre, v.Build = m[4], m[5]
	return v, nil
}

// firstLine is the first line of s, cut to 80 bytes, for an error message.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// TestedVersion is one row of the tested-version table: a version a live
// receipt ran (CLI and gateway at the same version), and the CLI texts that
// version prints which a driver may classify.
type TestedVersion struct {
	Version Version
	// Receipt is the live receipt that grounds the row.
	Receipt string
	// NotFoundText is the exact text `openshell sandbox get NAME` prints
	// for a missing sandbox at this version (ClassifyGet).
	NotFoundText string
	// Supervisor and Sandbox are the registry digests of this version's
	// supervisor and sandbox runtime images (images.go, ledger row OSH-48):
	// the managed gateway is written with the index digests, and probe row
	// P8i refuses an image that carries none of them. A row with no
	// digest refuses at P8i (fail closed).
	Supervisor ImageDigests
	Sandbox    ImageDigests
	// PodmanReceipt is the passing O1B-L2 launch receipt that measured a
	// box through the Podman driver at this version ("" for none: probe
	// row P6 refuses the Podman driver here; drivers.go).
	PodmanReceipt string
}

// podmanLaunchReceipt grounds the Podman driver on v0.1.6 (the P6 lift,
// lane FU7, tracker F-033). This commit is merged only on a passing
// `scripts/sandbox/o1b-openshell-live.sh --expect-podman --podman-launch`
// receipt; the orchestrator replaces this text with that receipt's path
// when it merges. While it starts with PENDING, P6 refuses the Podman
// driver (receiptSet, audit finding FU7-A1), so the lift is safe to merge
// before the receipt. A var only so the O1B-L2 launch half can build the
// binary it measures with a run marker set at link time (`-ldflags -X`,
// scripts/sandbox/o1b-openshell-live.sh --podman-launch); nothing assigns
// it at run time.
var podmanLaunchReceipt = "PENDING: the passing O1B-L2 --podman-launch receipt (docs/plans/openshell/receipts/o1b/o1b-openshell-live-podman-launch-o1b-l2-<UTC stamp>.json)"

// FloorVersion is the lowest OpenShell version the row accepts at all
// (doc 04 R2.6: the floor is v0.1.6, which made gateway authentication
// mandatory).
var FloorVersion = Version{Major: 0, Minor: 1, Patch: 6}

// testedVersions is the tested-version table (risk RK-01: upstream ships
// breaking changes in patches, so only a version a receipt ran is used).
// Adding a version is adding a row with its receipt and its texts.
var testedVersions = []TestedVersion{
	{
		// Lane O0, native Linux, 2026-10-31: the GO receipt. The not-found
		// text was settled live on the first VM receipt (abdac8): the CLI
		// exits 1 and miette prints this (o0-receipts.md, CLI table, "Get").
		Version:      Version{Major: 0, Minor: 1, Patch: 6},
		Receipt:      "_spikes/openshell/receipts/linux-2026-10-31-f04566.json",
		NotFoundText: `code: 'Some requested entity was not found', message: "sandbox not found"`,
		// The Podman driver (decision D4's preferred path), grounded by
		// O1B-L2's launch half (F-033).
		PodmanReceipt: podmanLaunchReceipt,
		// The vendor's published v0.1.6 manifests on ghcr.io, read by lane
		// FU7 on 2026-11-02 (anonymous registry token, the index served
		// for tag 0.1.6 and the linux/amd64 and linux/arm64 manifests it
		// lists; build/fu7-image-digests.md). The tag is the one the O0
		// receipt pulled; a host re-run (O1B-L2 launch half, O2-L1)
		// confirms the engine records the same index digest.
		Supervisor: ImageDigests{
			Index: "sha256:ce859a7d77ee515d3fe0b3c7dc61286516f402eb1d25c761d806d9ae5ed96c0b",
			Platforms: []string{
				"sha256:8128d88fb564497d6c0281295e87eae57f11d21cdc95ac69025a670de5e52c7d", // linux/amd64
				"sha256:818465ae6590e3d22ff2e90a1ff07160493a47ea5be93ef09aeac341d02132cd", // linux/arm64
			},
		},
		Sandbox: ImageDigests{
			Index: "sha256:1038eb5c1f191fa3c34684fd7041b891c78ec570979d487f36e06e08f91bfb63",
			Platforms: []string{
				"sha256:c931744fd5755e714972f594dc3d65f917bf41fb89af81d0f8ecad66cdc2adc0", // linux/amd64
				"sha256:1779a9cc83994b280663ee17415bbc24dd4bfae3ade881d0cf0cfbdf09878c4a", // linux/arm64
			},
		},
	},
}

// TestedVersions returns a copy of the tested-version table.
func TestedVersions() []TestedVersion { return append([]TestedVersion(nil), testedVersions...) }

// testedRow returns the table row of v; ok is false when v is not tested
// (a pre-release or a build with metadata never is).
func testedRow(v Version) (TestedVersion, bool) {
	if v.Pre != "" || v.Build != "" {
		return TestedVersion{}, false
	}
	for _, r := range testedVersions {
		if r.Version == v {
			return r, true
		}
	}
	return TestedVersion{}, false
}

// The version verdicts (the probe's version rows).
const (
	VerdictVersionUnknown     = "openshell_version_unknown"
	VerdictVersionMismatch    = "openshell_version_mismatch"
	VerdictVersionTooOld      = "openshell_too_old"
	VerdictVersionPinMismatch = "openshell_version_pin_mismatch"
	VerdictVersionUntested    = "openshell_untested"
)

// VersionFacts are the raw version answers and the configured pin.
type VersionFacts struct {
	// CLI is the output of `openshell --version`.
	CLI string
	// Gateway is the version the authenticated gateway reports (the
	// version field of `openshell status -o json`).
	Gateway string
	// Pin is [terminal.sandbox.openshell].version ("" for none).
	Pin string
}

// VersionResult is the version check: Verdict "" means the version may be
// used, and Row is its tested-version row.
type VersionResult struct {
	Verdict string
	Reason  string
	Version Version
	Row     TestedVersion
}

// versionCheck is the parsed state the version rules read.
type versionCheck struct {
	cli, gw       Version
	cliOK, gwOK   bool
	pin           Version
	pinSet, pinOK bool
}

// versionRule is one row of the version table, walked top-down.
type versionRule struct {
	verdict string
	fails   func(c versionCheck) bool
	reason  func(c versionCheck) string
}

// versionRules is the version table, first failing row wins.
var versionRules = []versionRule{
	{VerdictVersionUnknown, func(c versionCheck) bool { return !c.cliOK }, func(versionCheck) string {
		return "could not read the openshell CLI version"
	}},
	{VerdictVersionUnknown, func(c versionCheck) bool { return !c.gwOK }, func(versionCheck) string {
		return "could not read the OpenShell gateway version"
	}},
	{VerdictVersionUnknown, func(c versionCheck) bool { return c.pinSet && !c.pinOK }, func(versionCheck) string {
		return "[terminal.sandbox.openshell].version is not a version"
	}},
	// The CLI and the gateway (with its supervisor) are upgraded together;
	// a mixed pair was never run.
	{VerdictVersionMismatch, func(c versionCheck) bool { return c.cli != c.gw }, func(c versionCheck) string {
		return "the openshell CLI is " + c.cli.String() + " but the gateway is " + c.gw.String() + "; upgrade both to the same version"
	}},
	{VerdictVersionTooOld, func(c versionCheck) bool { return c.gw.less(FloorVersion) }, func(c versionCheck) string {
		return "OpenShell " + c.gw.String() + " is older than the floor " + FloorVersion.String()
	}},
	{VerdictVersionPinMismatch, func(c versionCheck) bool { return c.pinSet && c.pin != c.gw }, func(c versionCheck) string {
		return "OpenShell is " + c.gw.String() + " but [terminal.sandbox.openshell].version pins " + c.pin.String()
	}},
	{VerdictVersionUntested, func(c versionCheck) bool { _, ok := testedRow(c.gw); return !ok }, func(c versionCheck) string {
		return "OpenShell " + c.gw.String() + " is not a tested version (tested: " + testedList() + ")"
	}},
}

// testedList renders the tested versions for a reason.
func testedList() string {
	parts := make([]string, 0, len(testedVersions))
	for _, r := range testedVersions {
		parts = append(parts, r.Version.String())
	}
	return strings.Join(parts, ", ")
}

// CheckVersion walks the version table over the raw answers.
func CheckVersion(f VersionFacts) VersionResult {
	var c versionCheck
	var err error
	c.cli, err = ParseVersion(f.CLI)
	c.cliOK = err == nil
	c.gw, err = ParseVersion(f.Gateway)
	c.gwOK = err == nil
	if p := strings.TrimSpace(f.Pin); p != "" {
		c.pinSet = true
		c.pin, err = ParseVersion(p)
		c.pinOK = err == nil
	}
	for _, r := range versionRules {
		if r.fails(c) {
			return VersionResult{Verdict: r.verdict, Reason: r.reason(c), Version: c.gw}
		}
	}
	row, _ := testedRow(c.gw)
	return VersionResult{Version: c.gw, Row: row}
}
