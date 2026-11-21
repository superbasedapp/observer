package trivyimage

import (
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// mapping.go maps a report's os-pkgs results onto dependency findings in
// route A's shape (docs/dependency-scanning.md "Scanning an image"), so the
// Code security page, the CLI and the org posture read both drivers the
// same way. What differs is named here: the driver id (trivy-image, so a
// finding of one driver is closed only by a full scan of the same driver),
// Trivy's own severity, a fix hint naming the fixed version, and a "no fix
// available yet" note. Every string a finding carries is a template, an id
// or a version checked against a charset; Trivy's titles and descriptions
// are never read.

// The driver's ids.
const (
	// DriverID is the findings' driver name and the run's engine name.
	DriverID = "trivy-image"
	// ComponentID is the catalog row that owns the driver.
	ComponentID = "security.scan.image.trivy"
	// EngineComponentID is the catalog row that owns the Trivy binary and
	// its guided install.
	EngineComponentID = "security.scan.trivy"
	// RulePack is the findings' rule pack.
	RulePack = "trivy-db"
)

// MaxFindings caps one run's findings (depscan's cap).
const MaxFindings = depscan.MaxFindings

// Location is where an image's findings point (the Dockerfile's last FROM
// line, or the image file).
type Location struct {
	RelPath string
	Line    int
}

// MapInput is what Map needs besides the report.
type MapInput struct {
	Report Report
	// Label is the release label findings and coverage carry ("Debian:12",
	// "Ubuntu:24.04:LTS"); "" asks LabelFor, then ReleaseLabel of the
	// report's OS.
	Label string
	// LabelFor maps Trivy's detected OS onto Observer's release label (the
	// release table's, "" when it holds none); nil uses ReleaseLabel.
	LabelFor func(*OSInfo) string
	// RootHash is the project root hash of the image's project key.
	RootHash string
	Scope    secfinding.Scope
	Engine   secscan.EngineIdentity
	// Epoch is the database epoch the run matched against.
	Epoch    string
	Location Location
}

// MapOutput is the mapped run.
type MapOutput struct {
	Label    string
	Findings []secfinding.Finding
	// Packages are the image's OS packages (kernel packages included), in
	// depscan's shape, for the kernel note and the inventory record.
	Packages []depscan.Package
	// Matched counts the packages matched (kernel packages left out).
	Matched int
	// KernelNote names the kernel packages left out ("" for none).
	KernelNote string
	// NoFix counts findings with no fixed version.
	NoFix int
	// Unreadable counts advisories whose id or package could not be
	// carried (an id outside the rule-id charset).
	Unreadable int
	Truncated  bool
}

// ReleaseLabel is the label of a release Observer's release table does not
// hold: "<Family>:<Name>" of Trivy's detected OS ("amazon:2023", "wolfi:"),
// "" when none was detected or the spelling is outside the label charset.
func ReleaseLabel(o *OSInfo) string {
	if !o.Detected() {
		return ""
	}
	l := o.Family + ":" + o.Name
	if !validID(strings.ReplaceAll(l, " ", "_")) {
		return ""
	}
	return l
}

// severities maps Trivy's severity onto the finding vocabulary; anything
// else (UNKNOWN) takes the osv adapter row's default.
var severities = map[string]secfinding.Severity{
	"CRITICAL": policy.FindingSeverityCritical,
	"HIGH":     policy.FindingSeverityHigh,
	"MEDIUM":   policy.FindingSeverityMedium,
	"LOW":      policy.FindingSeverityLow,
}

// noFixWords are the fixed sentences of Trivy's no-fix states (a closed
// vocabulary; an unknown state says nothing more than "no fix available
// yet").
var noFixWords = map[string]string{
	"affected":            "",
	"fix_deferred":        " (the distribution deferred the fix)",
	"will_not_fix":        " (the distribution will not fix it)",
	"under_investigation": " (the distribution is investigating)",
	"end_of_life":         " (the release is past its end of life)",
}

// NoFixNote is the sentence a finding with no fixed version carries.
const NoFixNote = "No fix available yet"

// extractors maps Trivy's result type onto the depscan extractor name an
// OS package carries (the kernel rule and the inventory read it).
var extractors = map[string]string{
	"debian": "os/dpkg", "ubuntu": "os/dpkg",
	"alpine": "os/apk", "wolfi": "os/apk", "chainguard": "os/apk",
	"redhat": "os/rpm", "rocky": "os/rpm", "alma": "os/rpm", "centos": "os/rpm", "amazon": "os/rpm",
	"oracle": "os/rpm", "fedora": "os/rpm", "photon": "os/rpm", "azurelinux": "os/rpm", "cbl-mariner": "os/rpm",
	"opensuse": "os/rpm", "opensuse.leap": "os/rpm", "opensuse.tumbleweed": "os/rpm", "sles": "os/rpm", "suse linux enterprise server": "os/rpm",
}

func extractorFor(typ string) string {
	if e, ok := extractors[strings.ToLower(typ)]; ok {
		return e
	}
	return "os/" + strings.ToLower(strings.ReplaceAll(typ, " ", "-"))
}

// validID reports whether s fits the rule-id charset (letters, digits,
// '.', '_', '-', ':'; at most secfinding.MaxRuleID bytes).
func validID(s string) bool {
	if s == "" || len(s) > secfinding.MaxRuleID {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == ':':
		default:
			return false
		}
	}
	return true
}

// validVersion reports whether a package version or fixed version fits the
// version charset (dpkg, apk and rpm versions: letters, digits and
// ".+~:_-"; a fixed version may list several, comma separated), at most
// 128 bytes.
func validVersion(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte(".+~:_-, ", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// validPkgName reports whether a package name fits the package-name
// charset.
func validPkgName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte(".+~:_-", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// ruleID is the rule id of one advisory: the CVE when Trivy names one, else
// the distribution's advisory id (DSA, DLA, USN, RHSA, ALSA), else Trivy's
// own id.
func ruleID(v Vulnerability) string {
	if strings.HasPrefix(v.VulnerabilityID, "CVE-") && validID(v.VulnerabilityID) {
		return v.VulnerabilityID
	}
	for _, id := range v.VendorIDs {
		if validID(id) {
			return id
		}
	}
	if validID(v.VulnerabilityID) {
		return v.VulnerabilityID
	}
	return ""
}

// idsOf are every carried id of an advisory, the rule id first.
func idsOf(v Vulnerability, rule string) []string {
	out := []string{rule}
	seen := map[string]bool{rule: true}
	for _, id := range append([]string{v.VulnerabilityID}, v.VendorIDs...) {
		if validID(id) && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// pkgKey joins a package to its advisories: the identifier's UID when
// Trivy states one, else the name and version.
func pkgKey(uid, name, version string) string {
	if uid != "" {
		return "uid:" + uid
	}
	return "nv:" + name + "@" + version
}

// Map maps the report's OS package results onto findings.
func Map(in MapInput) MapOutput {
	out := MapOutput{Label: in.Label}
	if out.Label == "" && in.LabelFor != nil && in.Report.Metadata.OS.Detected() {
		out.Label = in.LabelFor(in.Report.Metadata.OS)
	}
	if out.Label == "" {
		out.Label = ReleaseLabel(in.Report.Metadata.OS)
	}
	row, _ := secscan.Adapter("osv")
	kernel := map[string]bool{}
	for _, res := range in.Report.OSResults() {
		ext := extractorFor(res.Type)
		for _, p := range res.Packages {
			if !validPkgName(p.Name) || !validVersion(p.Version) {
				continue
			}
			dp := depscan.Package{Ecosystem: out.Label, Name: p.Name, Version: p.Version, Extractor: ext, Path: in.Location.RelPath, Line: in.Location.Line}
			if p.SrcName != "" && p.SrcName != p.Name && validPkgName(p.SrcName) {
				dp.Name, dp.Binary = p.SrcName, p.Name
			}
			out.Packages = append(out.Packages, dp)
			if depscan.KernelPackage(dp) {
				kernel[pkgKey(p.Identifier.UID, p.Name, p.Version)] = true
				kernel[pkgKey("", p.Name, p.Version)] = true
				continue
			}
			out.Matched++
		}
	}
	out.KernelNote = depscan.KernelNote(out.Packages)
	seen := map[string]bool{}
	for _, res := range in.Report.OSResults() {
		ext := extractorFor(res.Type)
		for _, v := range res.Vulnerabilities {
			if kernel[pkgKey(v.PkgIdentifier.UID, v.PkgName, v.InstalledVersion)] || kernel[pkgKey("", v.PkgName, v.InstalledVersion)] {
				continue
			}
			if depscan.KernelPackage(depscan.Package{Name: v.PkgName, Extractor: ext}) {
				continue
			}
			rule := ruleID(v)
			if rule == "" || !validPkgName(v.PkgName) || !validVersion(v.InstalledVersion) || out.Label == "" {
				out.Unreadable++
				continue
			}
			if len(out.Findings) >= MaxFindings {
				out.Truncated = true
				break
			}
			f := buildFinding(in, out.Label, row, v, rule)
			if seen[f.LocalKey] {
				continue
			}
			seen[f.LocalKey] = true
			if !validVersion(v.FixedVersion) {
				out.NoFix++
			}
			out.Findings = append(out.Findings, f)
		}
	}
	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if a.EvidenceRedacted != b.EvidenceRedacted {
			return a.EvidenceRedacted < b.EvidenceRedacted
		}
		return a.Rule.ID < b.Rule.ID
	})
	return out
}

// identityEcosystem is the ecosystem part of a Trivy finding's match
// identity: the driver id joined to the release, so a Trivy finding never
// shares a lifecycle row with route A's finding of the same advisory (each
// is closed only by its own driver's full scan).
func identityEcosystem(label string) string { return DriverID + "|" + label }

func buildFinding(in MapInput, label string, row secscan.AdapterRow, v Vulnerability, rule string) secfinding.Finding {
	id := secfinding.DependencyIdentity(identityEcosystem(label), v.PkgName, v.InstalledVersion, rule)
	evidence := secfinding.Clip(label+" "+v.PkgName+"@"+v.InstalledVersion, secfinding.MaxEvidence)
	sev, ok := severities[strings.ToUpper(strings.TrimSpace(v.Severity))]
	if !ok {
		sev = row.Default
	}
	ids := idsOf(v, rule)
	more := ""
	if len(ids) > 6 {
		more = fmt.Sprintf(" and %d more", len(ids)-6)
		ids = ids[:6]
	}
	msg := fmt.Sprintf("Known vulnerability in a %s OS package (%s%s), reported by Trivy.", label, strings.Join(ids, ", "), more)
	var fix string
	if validVersion(v.FixedVersion) {
		fix = "Fixed in " + v.FixedVersion + " in your distribution, not in your image: rebuild the image on an updated base image, or upgrade the package with the distribution's package manager."
	} else {
		msg += " " + NoFixNote + noFixWords[strings.ToLower(strings.TrimSpace(v.Status))] + "."
		fix = NoFixNote + " in your distribution: watch for an update, or remove the package if the image does not need it."
	}
	f := secfinding.Finding{
		LocalKey:         secfinding.LocalKey(in.RootHash, rule, id),
		Location:         secfinding.Location{RelPath: strings.ReplaceAll(in.Location.RelPath, `\`, "/"), StartLine: in.Location.Line, EndLine: in.Location.Line},
		Rule:             secfinding.Rule{ID: rule, Pack: RulePack},
		Category:         row.Category,
		Severity:         sev,
		Confidence:       row.Confidence,
		Scope:            in.Scope,
		Project:          secfinding.Project{RootHash: in.RootHash},
		EvidenceRedacted: evidence,
		EvidenceHash:     secfinding.EvidenceHash(evidence),
		Message:          secfinding.Clip(msg, secfinding.MaxMessage),
		FixHint:          secfinding.Clip(fix, secfinding.MaxMessage),
		Engine: secfinding.Engine{
			Driver: DriverID, DriverVersion: in.Engine.Version, EngineDigest: in.Engine.Digest, DatabaseEpoch: in.Epoch,
		},
		Status: policy.FindingStatusOpen,
	}
	return f
}
