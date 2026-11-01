package orgclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The node half of the Cloud Intelligence parity CONSENT rails (design
// docs/plans/cloud-intelligence-parity-design-2026-10-03.md section 3.7).
//
//   - FetchIntelRequirement pulls the org's signed org-plane posture /
//     consent requirement on the push cycle, verifies it against the pinned
//     org key exactly like the display-policy rail, and caches it. It NEVER
//     writes a consent: on an individual-tenancy node a requirement the
//     developer has not accepted stays PENDING (INV-13).
//   - ReportIntelConsent posts the node's OWN consent posture (enum + digest)
//     over the same bearer + per-request proof the result rail uses, with the
//     body hash bound into the proof.
//
// Neither adds a timer, a host or a connection: both ride the existing cycle.

// intelRequirementRail names this rail in cross-rail key-identity refusals.
const intelRequirementRail = "intel-requirement"

// intelConsentMaxReplyBytes bounds the consent reply read.
const intelConsentMaxReplyBytes = 16 << 10

// SetIntelConsentSource installs the callback that resolves the node's current
// consent posture for the report rail (cmd/observer composes it from the live
// config and the store). nil disables reporting.
func (c *Client) SetIntelConsentSource(src func(ctx context.Context) (orgcontract.IntelConsentReport, bool)) {
	if c == nil {
		return
	}
	c.intelConsentSource = src
}

// FetchIntelRequirement pulls, verifies and caches the requirement document.
// The STATE RULES are the display-policy rail's: a 404 (a server that predates
// the rail) and every refusal leave the cached row untouched; the version is
// monotonic. Returns (true, nil) when a new version was cached.
func (c *Client) FetchIntelRequirement(ctx context.Context) (bool, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return false, fmt.Errorf("orgclient.FetchIntelRequirement: enrolment: %w", err)
	}
	if enr == nil {
		return false, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if errors.Is(err, ErrNoSecret) {
		return false, ErrNotEnrolled
	}
	if err != nil {
		return false, fmt.Errorf("orgclient.FetchIntelRequirement: bearer: %w", err)
	}
	url := strings.TrimRight(enr.OrgServerURL, "/") + orgcontract.IntelRequirementPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return false, fmt.Errorf("orgclient.FetchIntelRequirement: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if c.classifyRail(intelRequirementRail, resp) == railReplyNotSupported {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("orgclient.FetchIntelRequirement: server returned %d", resp.StatusCode)
	}
	var doc orgcontract.IntelRequirementDoc
	if err := orgcontract.DecodeCapped(resp.Body, maxOrgDocBytes, &doc); err != nil {
		return false, fmt.Errorf("orgclient.FetchIntelRequirement: decode: %w", err)
	}
	if doc.OrgID != enr.OrgID {
		return false, fmt.Errorf("orgclient.FetchIntelRequirement: document is for org %q, this node is enrolled with %q, refusing", doc.OrgID, enr.OrgID)
	}
	cached, hasCached, err := c.store.GetOrgIntelRequirement(ctx)
	if err != nil {
		return false, err
	}
	if hasCached && cached.OrgID != enr.OrgID {
		hasCached = false
	}
	pinned := doc.PublicKey
	repinned := false
	if hasCached {
		if cached.ServerPubkey != doc.PublicKey {
			if err := c.acceptOfferedKeyChange(ctx, intelRequirementRail, cached.ServerPubkey, doc.PublicKey); err != nil {
				return false, fmt.Errorf("orgclient.FetchIntelRequirement: %w", err)
			}
			repinned = true
		}
		if !repinned {
			pinned = cached.ServerPubkey
		}
	}
	// T-390: verify FIRST, then compare versions. A document's version is
	// only a fact once its signature (bound to this org and member) holds,
	// so an unsigned, tampered or another member's document is refused even
	// when it claims a version at or below the cached one, rather than being
	// read as "unchanged".
	if err := c.checkOrgKeyIdentity(ctx, intelRequirementRail, doc.PublicKey); err != nil {
		return false, fmt.Errorf("orgclient.FetchIntelRequirement: %w", err)
	}
	if err := orgcontract.VerifyIntelRequirement(doc, enr.OrgID, enr.UserID, pinned); err != nil {
		return false, fmt.Errorf("orgclient.FetchIntelRequirement: %w", err)
	}
	if hasCached && cached.Version >= doc.Version && !(repinned && doc.Version >= cached.Version) {
		return false, nil
	}
	if _, err := orgcontract.DecodeIntelRequirementBody(doc.Body); err != nil {
		return false, fmt.Errorf("orgclient.FetchIntelRequirement: %w", err)
	}
	if err := c.store.UpsertOrgIntelRequirement(ctx, store.OrgIntelRequirementRow{
		OrgID: doc.OrgID, Version: doc.Version, Body: doc.Body, BodyHash: doc.BodyHash,
		Signature: doc.Signature, ServerPubkey: pinned, ReceivedAt: time.Now().UTC(),
	}); err != nil {
		return false, err
	}
	if repinned || !hasCached {
		c.adoptEnrolmentKeyMaterial(ctx, pinned)
	}
	c.logger.Info("org intelligence requirement cached", "version", doc.Version)
	return true, nil
}

// RefreshIntelRequirement runs FetchIntelRequirement under railsMu (the rails'
// shared key-pin state), for the push cycle and for an on-demand refresh from
// the dashboard or `observer intel`.
func (c *Client) RefreshIntelRequirement(ctx context.Context) (bool, error) {
	c.railsMu.Lock()
	defer c.railsMu.Unlock()
	return c.FetchIntelRequirement(ctx)
}

// IntelRequirement returns the cached requirement document for the CURRENT
// enrolment (ok=false when none, or when the cached row belongs to another
// org).
func (c *Client) IntelRequirement(ctx context.Context) (store.OrgIntelRequirementRow, bool, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return store.OrgIntelRequirementRow{}, false, err
	}
	row, ok, err := c.store.GetOrgIntelRequirement(ctx)
	if err != nil || !ok || row.OrgID != enr.OrgID {
		return store.OrgIntelRequirementRow{}, false, err
	}
	return row, true, nil
}

// ErrIntelConsentNotSupported is returned when the org server does not offer
// the consent rail (404): an older server. Nothing local changes.
var ErrIntelConsentNotSupported = errors.New("orgclient: the organization's server does not offer the Cloud Intelligence consent rail yet")

// ReportIntelConsent posts the node's own consent posture. The subject is the
// enrolment bearer's; the body is bound into the per-request proof.
func (c *Client) ReportIntelConsent(ctx context.Context, rep orgcontract.IntelConsentReport) (orgcontract.IntelConsentReply, error) {
	ident, err := c.resolveIntelRailIdentity(ctx)
	if err != nil {
		return orgcontract.IntelConsentReply{}, err
	}
	if rep.AcceptedPurposes == nil {
		rep.AcceptedPurposes = []string{}
	}
	body, err := json.Marshal(rep)
	if err != nil {
		return orgcontract.IntelConsentReply{}, fmt.Errorf("orgclient.ReportIntelConsent: %w", err)
	}
	status, raw, err := c.postIntelRail(ctx, ident, orgcontract.IntelConsentPath, body)
	if err != nil {
		return orgcontract.IntelConsentReply{}, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return orgcontract.IntelConsentReply{}, ErrIntelConsentNotSupported
	default:
		return orgcontract.IntelConsentReply{}, fmt.Errorf("orgclient.ReportIntelConsent: server returned %d: %s", status, serverError(raw, status))
	}
	var reply orgcontract.IntelConsentReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return orgcontract.IntelConsentReply{}, fmt.Errorf("orgclient.ReportIntelConsent: decode: %w", err)
	}
	return reply, nil
}

// postIntelRail signs and sends one intel POST, returning the status and the
// bounded reply body.
func (c *Client) postIntelRail(ctx context.Context, ident intelRailIdentity, path string, body []byte) (int, []byte, error) {
	ts := time.Now().Unix()
	sig := ed25519.Sign(ident.SignKey, orgcontract.IntelRailSigningMessage(
		ts, http.MethodPost, path, orgcontract.IntelBodyCanonical(body), ident.OrgID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(ident.ServerURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+ident.Bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(orgcontract.HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(orgcontract.HeaderAgentSignature, base64.RawURLEncoding.EncodeToString(sig))
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return 0, nil, fmt.Errorf("orgclient: %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw := make([]byte, 0, 512)
	buf := bytes.NewBuffer(raw)
	if _, err := buf.ReadFrom(http.MaxBytesReader(nil, resp.Body, intelConsentMaxReplyBytes)); err != nil {
		return resp.StatusCode, nil, fmt.Errorf("orgclient: %s: read reply: %w", path, err)
	}
	return resp.StatusCode, buf.Bytes(), nil
}

// intelConsentReportKey is the dedup identity of one report: the cycle only
// re-sends when the posture changed (or after a restart).
func intelConsentReportKey(orgID string, rep orgcontract.IntelConsentReport) string {
	raw, _ := json.Marshal(rep)
	return orgID + "|" + string(raw)
}

// sweepUnconsentedIntelCache runs the T-155d sweep on a node that is not
// managed. A managed node keeps its cache (the org is the controller), a
// node its org switched to enterprise included (P-205); the store's own
// check covers a managed enrolment only, so a read error here falls through
// to it.
func (c *Client) sweepUnconsentedIntelCache(ctx context.Context) {
	if managed, err := NodeManaged(ctx, c.store); err == nil && managed {
		return
	}
	if n, err := c.store.SweepUnconsentedOrgIntelCache(ctx, time.Now().UTC()); err != nil {
		c.logger.Warn("org intelligence cache sweep failed", "err", err)
	} else if n > 0 {
		c.logger.Info("org intelligence results pulled without consent were removed from this machine", "count", n)
	}
}

// runIntelConsentCycle is the per-push-cycle consent work: refresh the
// requirement document, run the T-155d sweep of results cached without
// consent, and report the node's consent posture when it changed. Every step
// is fail-open and logged once; none affects push health.
func (c *Client) runIntelConsentCycle(ctx context.Context) {
	if _, err := c.RefreshIntelRequirement(ctx); err != nil && !errors.Is(err, ErrNotEnrolled) && !errors.Is(err, context.Canceled) {
		c.logger.Debug("org intelligence requirement fetch failed", "err", err)
	}
	c.sweepUnconsentedIntelCache(ctx)
	if c.intelConsentSource == nil {
		return
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return
	}
	rep, ok := c.intelConsentSource(ctx)
	if !ok {
		return
	}
	key := intelConsentReportKey(enr.OrgID, rep)
	if key == c.intelConsentReported {
		return
	}
	if _, err := c.ReportIntelConsent(ctx, rep); err != nil {
		if !errors.Is(err, ErrIntelConsentNotSupported) && !errors.Is(err, ErrNotEnrolled) {
			c.logger.Debug("org intelligence consent report failed", "err", err)
		}
		return
	}
	c.intelConsentReported = key
}
