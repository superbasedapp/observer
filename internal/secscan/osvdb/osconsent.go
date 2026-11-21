package osvdb

import (
	"fmt"
	"strings"
	"time"
)

// osconsent.go is the developer's one accept of the OS release databases
// (OS and CI vulnerability scanning plan section 6.4, operator ruling Q1
// (b), section 6.6.1 change 2): one accept covers every distribution
// release the developer's scanned images use, each fetched on demand from
// SuperBased's signed mirror on superbased.app only (the
// security.osv_os_export content kind; there is no bucket fallback for OS
// databases). It is a separate signed record beside the language accept
// (ConsentFile), with its own MAC domain and version, so the language
// accept's ConsentVersion is not bumped and nobody is asked again for the
// languages. Like the language accept it is given only on the dashboard or
// with `observer security scan db accept --os`, never by an agent (guard
// rule R-165 denies the verb, the route and a write to the record), and a
// managed node has nothing to accept: its OS databases come from its org
// mirror only.

// OSConsentVersion is bumped when OSConsentText changes materially (a new
// source, a much larger download); a record of an older version reads not
// accepted.
const OSConsentVersion = 1

// OSConsentFile is the OS accept record's name in the security directory.
const OSConsentFile = "osv-os-db-consent.json"

// osConsentMACDomain separates the OS record's MAC from the language
// record's and from every other use of the posture key.
const osConsentMACDomain = "sbo-osv-os-db-consent-v1"

// OSSource names where the OS release databases come from, as the
// surfaces print it: the signed mirror only.
const OSSource = FeedHost

// OSDistroSize is one distribution's approximate per-release download.
type OSDistroSize struct {
	// Name is the distribution as the text names it (the OSV base
	// ecosystem: "Debian", "Red Hat").
	Name string `json:"name"`
	// ApproxMB is the largest release's stripped file, about, in MB.
	ApproxMB int64 `json:"approx_mb"`
}

// OSDistroSizes returns each distribution of OSReleases once, in table
// order, with its largest release's approximate size.
func OSDistroSizes() []OSDistroSize {
	var out []OSDistroSize
	idx := map[string]int{}
	for _, r := range OSReleases {
		mb := (r.ApproxBytes + (1<<20 - 1)) >> 20
		if i, ok := idx[r.Base]; ok {
			if mb > out[i].ApproxMB {
				out[i].ApproxMB = mb
			}
			continue
		}
		idx[r.Base] = len(out)
		out = append(out, OSDistroSize{Name: r.Base, ApproxMB: mb})
	}
	return out
}

// osSizeWords spells OSDistroSizes as "Debian up to 62 MB, ..., and Rocky
// Linux up to 3 MB".
func osSizeWords() string {
	sizes := OSDistroSizes()
	parts := make([]string, len(sizes))
	for i, s := range sizes {
		parts[i] = fmt.Sprintf("%s up to %d MB", s.Name, s.ApproxMB)
	}
	if len(parts) < 2 {
		return strings.Join(parts, "")
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// OSConsentText is what the developer accepts for the OS release
// databases, on both surfaces (version OSConsentVersion).
var OSConsentText = "Observer's image scanner matches the operating system packages inside your container images " +
	"against a local copy of the OSV vulnerability database of each distribution release. Accepting lets " +
	"Observer download, when a scanned image needs it, the database of each distribution release your " +
	"scanned images use, from superbased's signed mirror on " + FeedHost + " only: there is no other source, " +
	"and a release the mirror cannot serve shows as not scanned. One accept covers every release; a release " +
	"your images start to use later downloads without asking again. Each release's database is: " + osSizeWords() +
	". After a release is downloaded Observer checks it every 6 hours and fetches only what changed. The " +
	"download sends nothing about your projects or images: it fetches the same public files for everyone, " +
	"named by release, and " + FeedHost + " can see your IP address, the time and which releases are fetched. " +
	"Until you accept, the operating system packages in your images show as not scanned."

// OSConsent is the node's record of the OS accept: the same shape and
// signing as Consent, under its own file, domain and version.
type OSConsent struct {
	Consent
}

// Accepted reports whether c is a verified record that covers the current
// OS text and was given on a surface that records consent.
func (c OSConsent) Accepted() bool {
	return c.Verified && c.Version >= OSConsentVersion && !c.AcceptedAt.IsZero() && ConsentSurfaces[c.Surface]
}

// ReadOSConsent reads the OS record in the security directory and verifies
// its MAC under key; anything missing, unreadable or unverified reads not
// accepted.
func ReadOSConsent(securityDir string, key []byte) OSConsent {
	return OSConsent{readConsentRecord(securityDir, OSConsentFile, osConsentMACDomain, key)}
}

// RecordOSConsent records the OS accept given on surface by the account by
// at at, signed under key, atomically (0600, the directory 0700).
func RecordOSConsent(securityDir, surface, by string, at time.Time, key []byte) (OSConsent, error) {
	c, err := writeConsentRecord(securityDir, OSConsentFile, osConsentMACDomain, OSConsentVersion, surface, by, at, key)
	if err != nil {
		return OSConsent{}, fmt.Errorf("osvdb.RecordOSConsent: %w", err)
	}
	return OSConsent{c}, nil
}
