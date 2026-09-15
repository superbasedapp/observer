package orgclient

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// FetchOrgAnnouncement pulls the org's latest announcement document
// (rail R3 of docs/plans/dashboard-announcements-banner-plan-2026-07-31.md
// §4) over the enrolment credential, and caches it node-side after
// verifying:
//
//   - the document is exactly ONE JSON value within the cap
//     (orgcontract.DecodeCapped — trailing documents are refused),
//   - body hash matches,
//   - the offered key agrees with any key ANOTHER rail has already
//     pinned (orgpin.go — one org, one distribution identity), so a
//     first announcement on a long-enrolled node cannot introduce a new
//     key by TOFU,
//   - the Ed25519 signature verifies against the PINNED server key —
//     TOFU: the first received key is pinned with the cache row; a
//     later key change is REFUSED loudly (re-enrol to rotate trust) —
//     and it covers the DOMAIN-TAGGED, VERSION-BOUND message
//     (orgcontract.VerifyAnnouncement), so a captured document cannot be replayed
//     at a bumped version and a routing-policy document signed by the
//     same org key cannot be presented here.
//
// The discipline mirrors FetchRoutingPolicy by design, down to the
// refusal wording, and the same org signing key covers both rails —
// but NOT the signed message: see orgcontract.VerifyAnnouncement and the
// ROUTING-SIG-1 row in docs/security.md.
//
// This adds NO network behaviour: it rides the push cycle the node
// already runs (client.go PushLoop), on the connection it already
// makes, to the server it is already enrolled with. That is the whole
// reason rail R3 is conformant with the product's zero-unsolicited-
// egress claims (plan §0) — a new timer or a new host would not be.
//
// Nothing is sent about the node: this is a GET, and there is no
// acknowledgment wire (plan §6 rules read receipts out as telemetry).
//
// Returns (false, nil) when nothing is published or the cache is
// already current; (true, nil) when a new version was cached —
// INCLUDING a retraction (empty body), which is a real published
// version whose whole purpose is to clear a banner.
func (c *Client) FetchOrgAnnouncement(ctx context.Context) (bool, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return false, fmt.Errorf("orgclient.FetchOrgAnnouncement: enrolment: %w", err)
	}
	if enr == nil {
		return false, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return false, fmt.Errorf("orgclient.FetchOrgAnnouncement: bearer: %w", err)
	}
	url := strings.TrimRight(enr.OrgServerURL, "/") + "/api/agent/announcement"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return false, fmt.Errorf("orgclient.FetchOrgAnnouncement: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil // nothing published — fine (also: older server)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("orgclient.FetchOrgAnnouncement: server returned %d", resp.StatusCode)
	}
	var doc orgcontract.OrgAnnouncementDoc
	if err := orgcontract.DecodeCapped(resp.Body, maxOrgDocBytes, &doc); err != nil {
		return false, fmt.Errorf("orgclient.FetchOrgAnnouncement: decode: %w", err)
	}

	cached, hasCached, err := c.store.GetOrgAnnouncement(ctx)
	if err != nil {
		return false, err
	}
	pinned := doc.PublicKey // TOFU on first receipt
	// repinned: this cycle ADOPTED a changed key because it is the key this
	// node was enrolled with (R1(c), the same rule the routing rail applies).
	// It must reach the cache write even when the version did not move, or
	// the rail would accept the new key and keep serving itself the old one.
	repinned := false
	if hasCached {
		if cached.ServerPubkey != doc.PublicKey {
			if err := c.acceptOfferedKeyChange(ctx, announcementRail, cached.ServerPubkey, doc.PublicKey); err != nil {
				return false, fmt.Errorf("orgclient.FetchOrgAnnouncement: %w", err)
			}
			repinned = true
		}
		pinned = doc.PublicKey
		if !repinned {
			pinned = cached.ServerPubkey
		}
		if cached.Version >= doc.Version && !(repinned && doc.Version >= cached.Version) {
			return false, nil // already current
		}
	}
	// ONE org distribution identity across rails (see orgpin.go): a
	// first announcement must present the key the routing rail already
	// pinned, not merely SOME key. Without this, a node that has been
	// enrolled for months (routing key pinned) would TOFU-accept a
	// different key the very first time it fetched an announcement.
	if err := c.checkOrgKeyIdentity(ctx, announcementRail, doc.PublicKey); err != nil {
		return false, fmt.Errorf("orgclient.FetchOrgAnnouncement: %w", err)
	}
	if err := orgcontract.VerifyAnnouncement(doc, pinned); err != nil {
		return false, fmt.Errorf("orgclient.FetchOrgAnnouncement: %w", err)
	}
	if err := c.store.UpsertOrgAnnouncement(ctx, store.OrgAnnouncementRow{
		Version: doc.Version, Body: doc.Body, BodyHash: doc.BodyHash,
		Signature: doc.Signature, ServerPubkey: pinned, ReceivedAt: time.Now().UTC(),
	}); err != nil {
		return false, err
	}
	// M3: same ordering rule as the routing rail — the trust root is written
	// only after this document verified and its cache write succeeded.
	if repinned || !hasCached {
		c.adoptEnrolmentKeyMaterial(ctx, pinned)
	}
	c.logger.Info("org announcement cached", "version", doc.Version, "retracted", strings.TrimSpace(doc.Body) == "")
	return true, nil
}
