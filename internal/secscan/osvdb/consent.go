package osvdb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
)

// consent.go is the developer's one-time accept of the OSV database
// download (operator ruling PT-19 (2), decision log P-036): nothing is
// downloaded into the store until the developer accepts, once, in the
// dashboard (a confirm dialog that shows the size and the source) or the
// CLI (`observer security scan db accept`); after that the refreshes are
// automatic. The record is node-local and kept beside the online checks'
// disclosure record in the security directory, so deleting the database
// store to reclaim space does not ask again. An agent can never give the
// accept: guard rule R-165 denies the CLI verb, its HTTP route and a write
// to the record file, and the record is signed under the node's posture
// key (guardposture.RecordMAC), so a hand-written file reads not accepted
// (lane sec-deps4 audit finding 1). A record an earlier plan-branch build
// wrote carries no MAC and reads not accepted, so a tester accepts once
// more; no released build ever wrote one.

// ConsentVersion is bumped when the accept text changes materially (a new
// source, a much larger download); a record of an older version reads not
// accepted, so the developer is asked again.
//
// Version 2 (2026-11-03, static feed mirroring plan section 8): the
// databases come from SuperBased's signed mirror on superbased.app first,
// with the OSV bucket as the fallback, so every individual node is asked
// once more.
const ConsentVersion = 2

// ConsentFile is the record's name in the security directory.
const ConsentFile = "osv-db-consent.json"

// consentMACDomain separates the record's MAC from every other use of the
// posture key.
const consentMACDomain = "sbo-osv-db-consent-v1"

// ApproxDownloadMB is the first download's size, about (npm is about 220
// MB of it); later refreshes fetch only the changed records or deltas.
//
// Recomputed 2026-11-06 when Pub, SwiftURL, Hex, Hackage, Julia and CRAN
// joined the mirror: the fifteen exports' Content-Length on the OSV bucket
// that day sum to 307.0 MB (the nine earlier ones 303.8 MB, the six new
// ones 3.2 MB together, Julia's 2.1 MB the largest of them), so "about
// 300 MB" still holds and the accept text (which names no ecosystem, so
// it covers every one the store downloads) needs no new version: a node
// that accepted already fetches the new ecosystems on its next refresh.
// TestApproxDownloadMBHonest holds the sum.
const ApproxDownloadMB = 300

// FeedHost serves SuperBased's signed mirror of the exports (source
// SourceFeed).
const FeedHost = "superbased.app"

// UpstreamHost is the OSV project's public export bucket (source
// SourceUpstream, the fallback).
const UpstreamHost = "osv-vulnerabilities.storage.googleapis.com"

// Source names where the databases come from, as the surfaces print it.
const Source = FeedHost + " (falling back to " + UpstreamHost + ")"

// ConsentText is what the developer accepts, on both surfaces (version
// ConsentVersion; docs/dependency-scanning.md "The one-time accept" quotes
// it verbatim).
var ConsentText = fmt.Sprintf("Observer's dependency scanners match your projects' lockfiles against a local copy of the OSV "+
	"vulnerability database. Accepting downloads it, about %d MB at first, from superbased's signed mirror on %s, "+
	"falling back to the OSV project's public export bucket (%s) when the mirror is unavailable, unless you turn "+
	"the fallback off. After the first download Observer checks every 6 hours and fetches only the changed records "+
	"or deltas. The download sends nothing about your projects: it fetches the same public files for everyone, and "+
	"both hosts can see your IP address and the time. Until you accept, your projects' dependencies show as not "+
	"scanned.", ApproxDownloadMB, FeedHost, UpstreamHost)

// ConsentSurfaces are the places that may record the accept: each is an
// explicit action by the developer (the dashboard's confirm dialog, the
// CLI's question or its --yes flag).
var ConsentSurfaces = map[string]bool{"dashboard": true, "cli": true}

// Consent is the node's record of the accept.
type Consent struct {
	Version    int       `json:"version"`
	AcceptedAt time.Time `json:"accepted_at"`
	// Surface is where it was accepted: "cli" or "dashboard".
	Surface string `json:"surface"`
	// By is the local account the accepting process ran as, when known.
	By string `json:"by,omitempty"`
	// MAC is the record's MAC under the posture key (canonical).
	MAC string `json:"mac,omitempty"`
	// Verified is set only by ReadConsent, when the MAC verified, and by
	// RecordConsent; it is never read from the file.
	Verified bool `json:"-"`
}

// canonical is the MAC input: every field but the MAC, in a fixed order
// and spelling.
func (c Consent) canonical() []byte {
	var b bytes.Buffer
	b.WriteString(strconv.Itoa(c.Version))
	b.WriteByte('\n')
	b.WriteString(c.AcceptedAt.UTC().Format(time.RFC3339Nano))
	b.WriteByte('\n')
	b.WriteString(strconv.Quote(c.Surface))
	b.WriteByte('\n')
	b.WriteString(strconv.Quote(c.By))
	return b.Bytes()
}

// Accepted reports whether c is a verified record that covers the current
// text and was given on a surface that records consent.
func (c Consent) Accepted() bool {
	return c.Verified && c.Version >= ConsentVersion && !c.AcceptedAt.IsZero() && ConsentSurfaces[c.Surface]
}

// ReadConsent reads the record in the security directory and verifies its
// MAC under key; anything missing or unreadable is "not accepted", and a
// record with no MAC or one that does not verify reads back unverified
// (Accepted false).
func ReadConsent(securityDir string, key []byte) Consent {
	return readConsentRecord(securityDir, ConsentFile, consentMACDomain, key)
}

// RecordConsent records the accept given on surface by the account by at
// at, signed under key, atomically (0600, the directory 0700).
func RecordConsent(securityDir, surface, by string, at time.Time, key []byte) (Consent, error) {
	c, err := writeConsentRecord(securityDir, ConsentFile, consentMACDomain, ConsentVersion, surface, by, at, key)
	if err != nil {
		return Consent{}, fmt.Errorf("osvdb.RecordConsent: %w", err)
	}
	return c, nil
}

// readConsentRecord reads one signed accept record (file, MAC domain) in
// the security directory; see ReadConsent.
func readConsentRecord(securityDir, file, domain string, key []byte) Consent {
	f, err := os.Open(filepath.Join(securityDir, file))
	if err != nil {
		return Consent{}
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) == 0 || len(b) > 4096 {
		return Consent{}
	}
	var c Consent
	if json.Unmarshal(b, &c) != nil {
		return Consent{}
	}
	c.Verified = guardposture.VerifyRecordMAC(domain, c.canonical(), key, c.MAC)
	return c
}

// writeConsentRecord records one signed accept record (file, MAC domain,
// version) atomically; see RecordConsent.
func writeConsentRecord(securityDir, file, domain string, version int, surface, by string, at time.Time, key []byte) (Consent, error) {
	if !ConsentSurfaces[surface] || at.IsZero() {
		return Consent{}, errors.New("an accepting surface and a time are required")
	}
	if len(key) == 0 {
		return Consent{}, errors.New("no signing key")
	}
	if len(by) > 128 {
		by = by[:128]
	}
	c := Consent{Version: version, AcceptedAt: at.UTC(), Surface: surface, By: by}
	c.MAC = guardposture.RecordMAC(domain, c.canonical(), key)
	b, err := json.Marshal(c)
	if err != nil {
		return Consent{}, err
	}
	if err := os.MkdirAll(securityDir, 0o700); err != nil {
		return Consent{}, err
	}
	tmp, err := os.CreateTemp(securityDir, ".tmp-osv-consent-*")
	if err != nil {
		return Consent{}, err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, 0o600)
	}
	if werr == nil {
		werr = os.Rename(name, filepath.Join(securityDir, file))
	}
	if werr != nil {
		_ = os.Remove(name)
		return Consent{}, werr
	}
	c.Verified = true
	return c, nil
}
