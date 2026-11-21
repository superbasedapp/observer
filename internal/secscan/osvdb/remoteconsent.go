package osvdb

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// remoteconsent.go holds the two signed records of the SuperBased package
// lookup (OS and CI vulnerability scanning plan sections 13.4, 13.10 and
// 13.11, lane RM-2): instead of downloading the OSV databases, a node in
// lookup mode "remote" (or "both", for the ecosystems with no local
// database) asks SuperBased for the advisory shards its packages fall in.
//
//   - RemoteConsent (osv-remote-consent.json) is the lookup itself: what
//     leaves the machine is a short hash prefix per package name, never a
//     name, a version or code. It is its own record, never the database
//     accept and never the install gate's disclosure.
//   - RemotePrivateConsent (osv-remote-private-consent.json) is the separate
//     choice to look up private and internal package names too: sending
//     them never rides the lookup consent.
//
// Both have the shape and signing of Consent (guardposture.RecordMAC under
// the node's posture key, each with its own MAC domain and version), are
// given only on the dashboard or the CLI, never by an agent (guard rule
// R-165 denies the verbs, the posture route and a write to either record),
// and can be withdrawn: WithdrawRemoteConsent and WithdrawRemotePrivate
// remove the record, which takes effect at the next lookup. A managed node
// has nothing to accept: its organization decides the lookup posture.
//
// The records live here, beside the other accepts, so every reader (the
// scan command, the status lines, the dashboard seam) reads them without
// linking the lookup lane (internal/secscan/osvshard/shardnet, the
// security.scan.osv.shards egress lane). RemoteShardHost is that lane's one
// allow-listed host; its test pins that RemoteConsentText names it.

// RemoteConsentVersion is bumped when RemoteConsentText changes materially;
// a record of an older version reads not accepted.
const RemoteConsentVersion = 1

// RemoteConsentFile is the lookup consent record's name in the security
// directory.
const RemoteConsentFile = "osv-remote-consent.json"

// remoteConsentMACDomain separates the lookup record's MAC from every other
// accept record's.
const remoteConsentMACDomain = "sbo-osv-remote-consent-v1"

// RemotePrivateConsentVersion is the private-names record's version.
const RemotePrivateConsentVersion = 1

// RemotePrivateConsentFile is the private-names consent record's name.
const RemotePrivateConsentFile = "osv-remote-private-consent.json"

// remotePrivateMACDomain separates the private-names record's MAC.
const remotePrivateMACDomain = "sbo-osv-remote-private-consent-v1"

// RemoteShardHost serves the advisory shards and their index files (plan
// section 13.11 item 5: a public bucket on its own custom domain); the
// signed shard manifest and set descriptors come from FeedHost, like every
// other content kind.
const RemoteShardHost = "shards." + FeedHost

// RemoteSource names where a remote lookup goes, as the surfaces print it.
const RemoteSource = FeedHost + " (the signed shard manifest) and " + RemoteShardHost + " (the shards)"

// RemoteConsentText is what the developer accepts for the SuperBased lookup,
// on both surfaces (version RemoteConsentVersion;
// docs/dependency-scanning.md "Remote lookup" quotes it).
var RemoteConsentText = fmt.Sprintf("Instead of downloading the OSV vulnerability databases, Observer looks your dependencies up at superbased. "+
	"For each dependency scan it asks %s for the advisory shards your packages fall in: it sends a short hash prefix of each "+
	"package name (a number shared by hundreds of other names), never a package name or version, and never code. It first "+
	"reads the signed list of shards from %s. Shards already on this machine are not asked for again. The kinds of packages "+
	"looked up are the ones you choose (language packages, GitHub Actions). Both hosts can see your IP address and the time, "+
	"and a party watching the requests could recognise the same set of prefixes asked for again. Private and internal "+
	"package names are never looked up unless you separately choose to send them.",
	RemoteShardHost, FeedHost)

// RemotePrivateConsentText is what the developer accepts to look private and
// internal package names up too (version RemotePrivateConsentVersion).
var RemotePrivateConsentText = "Observer normally never looks up a package name it cannot prove is public (a private registry, a scope " +
	"routed elsewhere): those packages stay unmatched and the scan is never clean. Choosing to send them looks them up like " +
	"public ones, as a short hash prefix of the name, never the name itself. A private name has no public advisory, but a " +
	"name that also exists publicly (dependency confusion) can match one."

// RemoteConsent is the node's record of the lookup consent.
type RemoteConsent struct {
	Consent
}

// Accepted reports whether c is a verified record that covers the current
// lookup text and was given on a surface that records consent.
func (c RemoteConsent) Accepted() bool {
	return c.Verified && c.Version >= RemoteConsentVersion && !c.AcceptedAt.IsZero() && ConsentSurfaces[c.Surface]
}

// RemotePrivateConsent is the node's record of the private-names consent.
type RemotePrivateConsent struct {
	Consent
}

// Accepted reports whether c is a verified record that covers the current
// private-names text.
func (c RemotePrivateConsent) Accepted() bool {
	return c.Verified && c.Version >= RemotePrivateConsentVersion && !c.AcceptedAt.IsZero() && ConsentSurfaces[c.Surface]
}

// ReadRemoteConsent reads the lookup record and verifies its MAC under key;
// anything missing, unreadable or unverified reads not accepted.
func ReadRemoteConsent(securityDir string, key []byte) RemoteConsent {
	return RemoteConsent{readConsentRecord(securityDir, RemoteConsentFile, remoteConsentMACDomain, key)}
}

// RecordRemoteConsent records the lookup consent given on surface by the
// account by at at, signed under key, atomically.
func RecordRemoteConsent(securityDir, surface, by string, at time.Time, key []byte) (RemoteConsent, error) {
	c, err := writeConsentRecord(securityDir, RemoteConsentFile, remoteConsentMACDomain, RemoteConsentVersion, surface, by, at, key)
	if err != nil {
		return RemoteConsent{}, fmt.Errorf("osvdb.RecordRemoteConsent: %w", err)
	}
	return RemoteConsent{c}, nil
}

// ReadRemotePrivateConsent reads the private-names record.
func ReadRemotePrivateConsent(securityDir string, key []byte) RemotePrivateConsent {
	return RemotePrivateConsent{readConsentRecord(securityDir, RemotePrivateConsentFile, remotePrivateMACDomain, key)}
}

// RecordRemotePrivateConsent records the private-names consent.
func RecordRemotePrivateConsent(securityDir, surface, by string, at time.Time, key []byte) (RemotePrivateConsent, error) {
	c, err := writeConsentRecord(securityDir, RemotePrivateConsentFile, remotePrivateMACDomain, RemotePrivateConsentVersion, surface, by, at, key)
	if err != nil {
		return RemotePrivateConsent{}, fmt.Errorf("osvdb.RecordRemotePrivateConsent: %w", err)
	}
	return RemotePrivateConsent{c}, nil
}

// WithdrawRemoteConsent removes the lookup record; withdrawing one that is
// not there is not an error. The next lookup reads not accepted.
func WithdrawRemoteConsent(securityDir string) error {
	return removeRecord(securityDir, RemoteConsentFile)
}

// WithdrawRemotePrivate removes the private-names record.
func WithdrawRemotePrivate(securityDir string) error {
	return removeRecord(securityDir, RemotePrivateConsentFile)
}

func removeRecord(securityDir, file string) error {
	if securityDir == "" {
		return errors.New("osvdb: no security directory")
	}
	if err := os.Remove(filepath.Join(securityDir, file)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("osvdb: withdraw %s: %w", file, err)
	}
	return nil
}
