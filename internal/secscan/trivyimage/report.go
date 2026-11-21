package trivyimage

import (
	"encoding/json"
	"errors"
	"fmt"
)

// report.go reads Trivy's JSON report (`--format json`, schema version 2
// at v0.75.0). Only the fields the mapping reads are decoded; everything
// else (descriptions, references, CVSS vectors, installed files) is never
// carried, so no engine prose reaches a finding.

// SchemaVersion is the report schema the driver was built against.
const SchemaVersion = 2

// MaxReportBytes caps the report a run may write (buildpack-deps:noble, 414
// packages with --list-all-pkgs, is the largest the spike measured).
const MaxReportBytes = 256 << 20

// ClassOSPackages is the Result.Class of an OS package result.
const ClassOSPackages = "os-pkgs"

// Report is the subset of Trivy's JSON report the driver reads.
type Report struct {
	SchemaVersion int `json:"SchemaVersion"`
	Trivy         struct {
		Version string `json:"Version"`
	} `json:"Trivy"`
	ArtifactType string   `json:"ArtifactType"`
	Metadata     Metadata `json:"Metadata"`
	Results      []Result `json:"Results"`
}

// Metadata is the report's metadata block.
type Metadata struct {
	// OS is the detected operating system; nil, or Family "none", when
	// Trivy detected none.
	OS *OSInfo `json:"OS"`
}

// OSInfo is Trivy's detected operating system ("debian" / "12.15").
type OSInfo struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
	// EOSL: the release is past its end of service life.
	EOSL bool `json:"EOSL"`
}

// Detected reports whether Trivy detected an operating system.
func (o *OSInfo) Detected() bool {
	return o != nil && o.Family != "" && o.Family != "none"
}

// Result is one result block (one target and class).
type Result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Packages        []Package       `json:"Packages"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

// Identifier is a package's identifier block.
type Identifier struct {
	UID string `json:"UID"`
}

// Package is one installed package (--list-all-pkgs).
type Package struct {
	ID         string     `json:"ID"`
	Name       string     `json:"Name"`
	Version    string     `json:"Version"`
	SrcName    string     `json:"SrcName"`
	SrcVersion string     `json:"SrcVersion"`
	Identifier Identifier `json:"Identifier"`
}

// Vulnerability is one advisory on one installed package.
type Vulnerability struct {
	VulnerabilityID  string     `json:"VulnerabilityID"`
	VendorIDs        []string   `json:"VendorIDs"`
	PkgID            string     `json:"PkgID"`
	PkgName          string     `json:"PkgName"`
	PkgIdentifier    Identifier `json:"PkgIdentifier"`
	InstalledVersion string     `json:"InstalledVersion"`
	FixedVersion     string     `json:"FixedVersion"`
	// Status is Trivy's fix state: fixed, affected, fix_deferred,
	// will_not_fix, under_investigation, end_of_life, unknown.
	Status string `json:"Status"`
	// Severity is CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN.
	Severity string `json:"Severity"`
}

// ErrReport is a report that cannot be read.
var ErrReport = errors.New("trivyimage: the report is unreadable")

// Parse decodes a report of at most MaxReportBytes and checks its schema
// version.
func Parse(b []byte) (Report, error) {
	var r Report
	if len(b) == 0 || len(b) > MaxReportBytes {
		return r, fmt.Errorf("%w: %d bytes", ErrReport, len(b))
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return Report{}, fmt.Errorf("%w: %w", ErrReport, err)
	}
	if r.SchemaVersion != SchemaVersion {
		return Report{}, fmt.Errorf("%w: schema version %d, want %d", ErrReport, r.SchemaVersion, SchemaVersion)
	}
	return r, nil
}

// OSResults returns the report's OS package results.
func (r Report) OSResults() []Result {
	var out []Result
	for _, res := range r.Results {
		if res.Class == ClassOSPackages {
			out = append(out, res)
		}
	}
	return out
}
