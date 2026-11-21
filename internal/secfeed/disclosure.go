package secfeed

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
)

// disclosure.go is the online checks' first-run disclosure (security plan
// section 8.3 "Disclosure text"; D-759, D-764 Q23): shown once on every
// node when online checks first become active, which on the developer and
// full distros is first run, and kept on the Package checks card of the
// Code security page. No online query is sent before it has been shown
// (plans decision log P-011: a config with no [components] block resolves
// every compiled module active, so the disclosure, not the component
// state, is what stands between a fresh install and its first query).

// DisclosureVersion is bumped when the text changes materially; a node
// that saw an older version is shown the new one before its next query.
// Version 2 (lane sec-d1fix) names superbased.app and the control that
// exists. Version 3 (spike CPP-0, 2026-11-06) adds a data class: when you
// run `observer security scan --online`, the commit ids your git
// submodules are pinned to; an accept of version 2 no longer counts, so
// the text is shown and accepted again before any query (the install
// gate's included) is sent. On 2026-11-06 (dashboard CLI parity, decision
// P-1) the dashboard's scan dialog gained an "Also check online" option, so
// the text names it beside the CLI flag. That is not a material change: the
// same data class goes to the same service, still only on an explicit
// request, so the version stays 3.
const DisclosureVersion = 3

// DisclosureText is the individual-node text.
const DisclosureText = "Observer checks packages your AI agent tries to install, and the packages your projects use, " +
	"against public vulnerability and malware databases, so it can warn you about bad packages with the latest data. " +
	"To do that it sends the package's ecosystem, name and version to the OSV database (api.osv.dev) and to the " +
	"package's public registry. When you ask for an online scan (\"Also check online\" in the Code security scan " +
	"dialog, or `observer security scan --online`), it also sends api.osv.dev the commit " +
	"ids your project's git submodules are pinned to, and only those ids: never a submodule's URL, path or name. " +
	"It never sends file paths, repository names, your organization, your name, or the " +
	"names of packages from private registries. The services can see your IP address and the time of the check. " +
	"Separately, Observer downloads its signed lists of malicious and popular package names from superbased.app; " +
	"that download sends nothing about your packages. You can turn the online checks off at any time on the " +
	"Code security page (Package checks) or with the security.deps.online setting; Observer then uses its offline lists only."

// DisclosureTextManaged is the managed-node variant.
const DisclosureTextManaged = "Observer checks packages your AI agent tries to install, and the packages your projects use, " +
	"against vulnerability and malware data. To do that it sends the package's ecosystem, name and version to your " +
	"organization's server, which checks them on its own behalf (or against its own mirror). It never sends file " +
	"paths, repository names, your name, or the names of packages from private registries. Your organization " +
	"requires (or allows) this setting."

// DisclosureSurfaces are the places that may record the disclosure as
// read: each is an explicit action by the developer (the dashboard's
// button, the CLI's --accept or its yes). A terminal start shows the text
// and records nothing.
var DisclosureSurfaces = map[string]bool{"dashboard": true, "cli": true}

// Disclosure is the node's record that the text was shown.
type Disclosure struct {
	Version int       `json:"version"`
	ShownAt time.Time `json:"shown_at"`
	// Surface is where it was accepted: "cli" (observer security deps
	// disclosure) or "dashboard" (the Code security page).
	Surface string `json:"surface"`
	// MAC is the record's MAC under the node's posture key
	// (guardposture.RecordMAC): the record is the developer's consent, so
	// a hand-written file must not count as one (lane sec-deps4 audit
	// finding 1). A record an earlier plan-branch build wrote has none and
	// reads not shown, so a tester accepts once more.
	MAC string `json:"mac,omitempty"`
	// Verified is set only by DecodeDisclosure, when the MAC verified, and
	// by EncodeDisclosure's caller; it is never read from the file.
	Verified bool `json:"-"`
}

// disclosureMACDomain separates the record's MAC from every other use of
// the posture key.
const disclosureMACDomain = "sbo-online-disclosure-v1"

// canonical is the MAC input: every field but the MAC, in a fixed order
// and spelling.
func (d Disclosure) canonical() []byte {
	var b bytes.Buffer
	b.WriteString(strconv.Itoa(d.Version))
	b.WriteByte('\n')
	b.WriteString(d.ShownAt.UTC().Format(time.RFC3339Nano))
	b.WriteByte('\n')
	b.WriteString(strconv.Quote(d.Surface))
	return b.Bytes()
}

// Shown reports whether d is a verified record that covers the current
// text and was accepted on a surface that records consent (a record from
// a terminal start, which an earlier build wrote, does not count).
func (d Disclosure) Shown() bool {
	return d.Verified && d.Version >= DisclosureVersion && !d.ShownAt.IsZero() && DisclosureSurfaces[d.Surface]
}

// DecodeDisclosure reads the record and verifies its MAC under key;
// anything unreadable is "not shown", and a record with no MAC or one
// that does not verify reads back unverified (Shown false).
func DecodeDisclosure(b, key []byte) Disclosure {
	var d Disclosure
	if len(b) == 0 || len(b) > 4096 || json.Unmarshal(b, &d) != nil {
		return Disclosure{}
	}
	d.Verified = guardposture.VerifyRecordMAC(disclosureMACDomain, d.canonical(), key, d.MAC)
	return d
}

// EncodeDisclosure writes the record, signed under key.
func EncodeDisclosure(d Disclosure, key []byte) ([]byte, error) {
	if !DisclosureSurfaces[d.Surface] || d.ShownAt.IsZero() {
		return nil, errors.New("secfeed.EncodeDisclosure: an accepting surface and a time are required")
	}
	if len(key) == 0 {
		return nil, errors.New("secfeed.EncodeDisclosure: no signing key")
	}
	d.MAC = guardposture.RecordMAC(disclosureMACDomain, d.canonical(), key)
	return json.Marshal(d)
}
