package depscan

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// The two inventory drivers' ids and components (security plan section 4.2).
const (
	ScalibrID        = "scalibr"
	ScalibrComponent = "security.scan.scalibr"
	OSVID            = "osv"
	OSVComponent     = "security.scan.osv"
)

// OSVScannerPinned is the reviewed osv-scanner release (JSP-8): v2.6.0,
// linux amd64 sha256. Other platforms' digests come from the vendor's
// SHA256SUMS through the signed content channel (section 8.5).
const (
	OSVScannerMinVersion = "2.6.0"
	// OSVScannerTestedBelow is the tested range's exclusive upper bound:
	// a newer release runs, labelled untested (osvscanner.VersionVerdict).
	OSVScannerTestedBelow = "2.7.0"
	OSVScannerTested      = ">=" + OSVScannerMinVersion + " <" + OSVScannerTestedBelow
	OSVScannerLinuxAMD64  = "ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108"
)

// NotIsolatedPrefix starts the run note of a SCALIBR child that ran
// without an isolation provider (ledger SECP-8: the child then has the
// network); the CLI labels such a run "not isolated".
const NotIsolatedPrefix = "Not isolated"

// UntestedVersionPrefix starts the run note of an osv-scanner release
// newer than the tested range; the CLI labels such a run "untested
// version".
const UntestedVersionPrefix = "Untested engine version"

// runLabels are the run label suffixes a note adds, by the note's fixed
// prefix. The CLI and the dashboard's Scanners card both read this one
// table (lane SEC-DEPS3 item 6).
var runLabels = []struct{ prefix, words string }{
	{NotIsolatedPrefix, "not isolated"},
	{UntestedVersionPrefix, "untested engine version"},
}

// RunLabels returns the labels a run's notes carry, in table order, each
// once.
func RunLabels(notes []string) []string {
	var out []string
	for _, l := range runLabels {
		for _, n := range notes {
			if strings.HasPrefix(n, l.prefix) {
				out = append(out, l.words)
				break
			}
		}
	}
	return out
}

// Attribution is the attribution text the OSV data's licences require
// wherever scan results are shown (security plan section 8.7): the CLI's
// status and every result, the Code security page's Scanners card, the
// docs.
const Attribution = "Vulnerability data: OSV (osv.dev), from GitHub Security Advisories, the Python Packaging " +
	"Advisory Database, the Go Vulnerability Database and OSS-Fuzz (CC-BY 4.0), RustSec (CC0) and others, " +
	"each under its own licence. Observer downloads it; it never ships it."

// SCALIBRVersion is the linked module's pinned version (section 8.4).
const SCALIBRVersion = "0.5.3"

// platformCell is one row of the per-platform support table.
type platformCell struct {
	OS, Arch string
	Support  secscan.Support
}

// scalibrPlatforms: every extractor in the facade's table declares itself
// OS-independent and cross-compiles CGO-free (JSP-9b section 2), but only
// linux amd64 has run the extractors; linux arm64, windows and darwin stay
// "untested" until
// _spikes/jsp-9b/run-elsewhere.sh has run there (D-764 Q25: beta on
// Windows, untested coverage is never shown as supported).
var scalibrPlatforms = []platformCell{
	{"linux", "amd64", secscan.SupportSupported},
	{"linux", "arm64", secscan.SupportUntested},
	{"windows", "amd64", secscan.SupportUntested},
	{"darwin", "amd64", secscan.SupportUntested},
	{"darwin", "arm64", secscan.SupportUntested},
}

// osvPlatforms: osv-scanner publishes binaries for every platform; JSP-8
// ran it on linux only.
var osvPlatforms = []platformCell{
	{"linux", "amd64", secscan.SupportSupported},
	{"linux", "arm64", secscan.SupportUntested},
	{"windows", "amd64", secscan.SupportUntested},
	{"darwin", "amd64", secscan.SupportUntested},
	{"darwin", "arm64", secscan.SupportUntested},
}

func platformRows(cells []platformCell, extractors []string) []secscan.PlatformRow {
	var out []secscan.PlatformRow
	for _, c := range cells {
		out = append(out, secscan.PlatformRow{Platform: secscan.Platform{OS: c.OS, Arch: c.Arch}, Support: c.Support})
		for _, e := range extractors {
			out = append(out, secscan.PlatformRow{Platform: secscan.Platform{OS: c.OS, Arch: c.Arch}, Extractor: e, Support: c.Support})
		}
	}
	return out
}

// PlatformSupport returns a row's support cell for goos/goarch and an
// extractor ("" for the whole engine). A platform the row does not name is
// unsupported: its coverage is "not scanned".
func PlatformSupport(row secscan.DriverRow, goos, goarch, extractor string) secscan.Support {
	for _, p := range row.Platforms {
		if p.Platform.OS == goos && p.Platform.Arch == goarch && p.Extractor == extractor {
			return p.Support
		}
	}
	if extractor != "" {
		return PlatformSupport(row, goos, goarch, "")
	}
	return secscan.SupportUnsupported
}

// Beta reports whether the driver is labelled beta on goos/goarch: any
// cell short of "supported" (D-764 Q25).
func Beta(row secscan.DriverRow, goos, goarch string) bool {
	return PlatformSupport(row, goos, goarch, "") != secscan.SupportSupported
}

var depTriggers = []secfinding.Scope{policy.FindingScopeScheduled, policy.FindingScopeManual}

// ScalibrRow is the linked driver's registry row. extractors are the
// facade's extractor names (scalibrfacade.Extractors), for the
// per-extractor Platforms cells.
func ScalibrRow(extractors []string) secscan.DriverRow {
	return secscan.DriverRow{
		ID: ScalibrID, Kind: secscan.KindLinked, ComponentID: ScalibrComponent,
		Categories: []secfinding.Category{policy.FindingVulnerableDependency},
		Triggers:   depTriggers,
		Platforms:  platformRows(scalibrPlatforms, extractors),
		Offline:    secscan.Offline{NoNetwork: true, Database: "OSV per-ecosystem exports, downloaded by Observer (internal/secscan/osvdb)"},
		Processes:  []secscan.ProcessDecl{{Binary: "observer (the scan child: `observer security scan-child`)"}},
		Egress: []secscan.EgressDecl{
			{Host: "osv-vulnerabilities.storage.googleapis.com", Trigger: "database refresh (Observer's download, never SCALIBR's)"},
			{Host: "api.osv.dev", Trigger: "online matching, a user command only"},
		},
		MinVersion: SCALIBRVersion, TestedRange: SCALIBRVersion,
		SemanticAdapter: "osv",
		Licence:         "Apache-2.0 (OSV-SCALIBR) and its 43 linked modules (MIT, Apache-2.0, BSD-3-Clause, BSD-2-Clause, ISC)",
	}
}

// OSVScannerFlags are the flags every osv-scanner run passes and never
// passes (JSP-8): offline after Observer's own database download, call
// analysis off (it runs the repository's Go toolchain and peaked at 8.9 GB).
var OSVScannerFlags = secscan.FlagRule{
	Always: []string{"scan", "source", "-r", "--offline", "--no-call-analysis=all", "--format", "json"},
	Never:  []string{"--download-offline-databases", "--experimental-call-analysis", "--licenses", "--serve"},
}

// OSVScannerExitCodes is osv-scanner's exit-code table (JSP-8).
var OSVScannerExitCodes = []secscan.ExitCode{
	{Code: 0, Meaning: secscan.ExitOK},
	{Code: 1, Meaning: secscan.ExitFindings},
	{Code: 128, Meaning: secscan.ExitNothingToScan},
	{Code: 127, Meaning: secscan.ExitCrash},
}

// OSVRow is the subprocess driver's registry row.
func OSVRow() secscan.DriverRow {
	return secscan.DriverRow{
		ID: OSVID, Kind: secscan.KindProcess, ComponentID: OSVComponent,
		Categories: []secfinding.Category{policy.FindingVulnerableDependency},
		Triggers:   depTriggers,
		Platforms:  platformRows(osvPlatforms, nil),
		Offline:    secscan.Offline{NoNetwork: true, Database: "OSV per-ecosystem exports, downloaded by Observer (internal/secscan/osvdb); osv-scanner runs --offline"},
		Processes:  []secscan.ProcessDecl{{Binary: "osv-scanner"}},
		// osv-scanner itself runs --offline; the database it reads is
		// Observer's download, declared here like the SCALIBR row's.
		Egress: []secscan.EgressDecl{
			{Host: "osv-vulnerabilities.storage.googleapis.com", Trigger: "database refresh (Observer's download, never osv-scanner's)"},
		},
		MinVersion: OSVScannerMinVersion, TestedRange: OSVScannerTested,
		PinnedDigests:   []string{OSVScannerLinuxAMD64},
		SemanticAdapter: "osv",
		Flags:           OSVScannerFlags,
		ExitCodes:       OSVScannerExitCodes,
		Licence:         "Apache-2.0; never bundled, used if installed",
	}
}
