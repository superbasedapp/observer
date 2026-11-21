package osvdb

import (
	"fmt"
	"time"
)

// trivyconsent.go is the developer's one accept of Trivy's vulnerability
// database (OS and CI vulnerability scanning plan section 6.7, operator
// ruling Q6, lane OS-2 T): the image driver security.scan.image.trivy
// matches an image's OS packages with Trivy, offline, against Trivy's own
// database, which Observer (never Trivy) downloads from the GitHub
// container registry. It is a third signed record beside the language and
// OS accepts (the same shape and signing as Consent), with its own file,
// MAC domain and version, so neither of the other accepts is bumped and
// none stands in for this one. Like them it is given only on the dashboard
// or with `observer security scan trivy-db accept`, never by an agent
// (guard rule R-165 denies the verb, the route and a write to the record),
// and a managed node has nothing to accept: its organization's mirror does
// not serve Trivy's database yet, so a managed node's Trivy image scans
// read not scanned and nothing is downloaded.
//
// The record lives here, beside the other two, so every reader (the scan
// command, the status lines, the dashboard seam) reads it without linking
// the download lane (internal/secscan/trivydb, the security.scan.trivy.db
// egress lane). The hosts below are that lane's allow-list; its test pins
// that the text names every one of them.

// TrivyConsentVersion is bumped when TrivyConsentText changes materially
// (a new source, a much larger download); a record of an older version
// reads not accepted.
const TrivyConsentVersion = 1

// TrivyConsentFile is the Trivy accept record's name in the security
// directory.
const TrivyConsentFile = "trivy-db-consent.json"

// trivyConsentMACDomain separates the Trivy record's MAC from the other
// accept records' and from every other use of the posture key.
const trivyConsentMACDomain = "sbo-trivy-db-consent-v1"

// The download's hosts, sizes and cadence, as the accept text states them.
const (
	// TrivyRegistryHost serves the anonymous pull token, the manifest of
	// ghcr.io/aquasecurity/trivy-db:2 and the layer request.
	TrivyRegistryHost = "ghcr.io"
	// TrivyBlobHost is where the registry redirects the layer download.
	TrivyBlobHost = "pkg-containers.githubusercontent.com"
	// TrivyApproxDownloadMB is the compressed layer, about (138,593,574
	// bytes on 2026-11-04).
	TrivyApproxDownloadMB = 140
	// TrivyApproxDiskMB is the unpacked database, about (1,691,385,856
	// bytes on 2026-11-04, spike JSP-OS S7); a refresh briefly holds two.
	TrivyApproxDiskMB = 1700
	// TrivyRefreshHours is the refresh cadence after the accept.
	TrivyRefreshHours = 6
)

// TrivySource names where Trivy's database comes from, as the surfaces
// print it.
const TrivySource = TrivyRegistryHost + " (ghcr.io/aquasecurity/trivy-db:2, its layer served from " + TrivyBlobHost + ")"

// TrivyConsentText is what the developer accepts for Trivy's database, on
// both surfaces (version TrivyConsentVersion).
var TrivyConsentText = fmt.Sprintf("Observer's Trivy image driver matches the operating system packages inside your container images "+
	"against a local copy of Trivy's vulnerability database, offline: Trivy itself never downloads anything. Accepting lets "+
	"Observer download that database, the public artifact ghcr.io/aquasecurity/trivy-db:2, anonymously from the GitHub "+
	"container registry (%s, which redirects the download to %s): about %d MB to download, which unpacks to about %d MB "+
	"(about 1.7 GB) on disk, briefly twice that while a refresh replaces it. After the first download Observer checks every "+
	"%d hours, and only downloads again when a newer database is published (Trivy publishes one about daily). The download "+
	"sends nothing about your projects or images: it fetches the same public files for everyone, and both hosts can see your "+
	"IP address and the time. Until you accept, Trivy image scans show as not scanned.",
	TrivyRegistryHost, TrivyBlobHost, TrivyApproxDownloadMB, TrivyApproxDiskMB, TrivyRefreshHours)

// TrivyConsent is the node's record of the Trivy accept: the same shape and
// signing as Consent, under its own file, domain and version.
type TrivyConsent struct {
	Consent
}

// Accepted reports whether c is a verified record that covers the current
// Trivy text and was given on a surface that records consent.
func (c TrivyConsent) Accepted() bool {
	return c.Verified && c.Version >= TrivyConsentVersion && !c.AcceptedAt.IsZero() && ConsentSurfaces[c.Surface]
}

// ReadTrivyConsent reads the Trivy record in the security directory and
// verifies its MAC under key; anything missing, unreadable or unverified
// reads not accepted.
func ReadTrivyConsent(securityDir string, key []byte) TrivyConsent {
	return TrivyConsent{readConsentRecord(securityDir, TrivyConsentFile, trivyConsentMACDomain, key)}
}

// RecordTrivyConsent records the Trivy accept given on surface by the
// account by at at, signed under key, atomically (0600, the directory
// 0700).
func RecordTrivyConsent(securityDir, surface, by string, at time.Time, key []byte) (TrivyConsent, error) {
	c, err := writeConsentRecord(securityDir, TrivyConsentFile, trivyConsentMACDomain, TrivyConsentVersion, surface, by, at, key)
	if err != nil {
		return TrivyConsent{}, fmt.Errorf("osvdb.RecordTrivyConsent: %w", err)
	}
	return TrivyConsent{c}, nil
}
