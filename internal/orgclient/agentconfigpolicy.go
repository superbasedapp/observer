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

// agentConfigPolicyRail names this rail in cross-rail key-identity refusals.
const agentConfigPolicyRail = "agent-config-policy"

// SetAgentConfigPolicyGate installs the gate the AI tool policy rail checks
// before every fetch: true only while this node's enrolment is managed with
// a live grant (cmd/observer decides, govern.Effective.ManagedDefaultsApply).
// Nil (the default) keeps the rail OFF: an individual node never asks for
// the org's AI tool settings, which are not its organization's to set.
func (c *Client) SetAgentConfigPolicyGate(gate func(ctx context.Context) bool) {
	if c == nil {
		return
	}
	c.agentConfigGate = gate
}

// SetAgentConfigPolicySink installs the callback run after a NEW policy
// version was verified and cached (the daemon applies it at once). Nil-safe.
func (c *Client) SetAgentConfigPolicySink(sink func()) {
	if c == nil {
		return
	}
	c.agentConfigSink = sink
}

// AgentConfigPolicy returns the last VERIFIED document this node holds for
// its CURRENT enrolment (ok=false when none, or when the cached row was
// signed for a different org or member).
func (c *Client) AgentConfigPolicy(ctx context.Context) (store.OrgAgentConfigPolicyRow, bool, error) {
	row, ok, err := c.store.CurrentOrgAgentConfigPolicy(ctx)
	if err != nil {
		return store.OrgAgentConfigPolicyRow{}, false, fmt.Errorf("orgclient.AgentConfigPolicy: %w", err)
	}
	return row, ok, nil
}

// FetchAgentConfigPolicy pulls the org's AI tool settings for this member
// (GET /api/agent/agent-config-policy) and caches it after verifying, in
// order: exactly one JSON document within the cap; issued for THIS org and
// THIS member; the offered key agrees with the org identity the enrolment
// and the other rails pinned; the Ed25519 signature over the domain-tagged,
// org-, member- and version-bound message; a body schema this build reads.
//
// STATE RULES (D-016): a 404 (an older server, or a member the server does
// not see as managed) and every other non-200, transport error or refused
// document leave the cache UNTOUCHED; the version is monotonic (a document
// at or below the cached version is not re-applied); and only a SIGNED body
// that sets nothing withdraws the org's settings.
//
// Gated: nothing is requested unless the gate says this node is managed
// with a live grant. Returns (true, nil) when a new version was cached.
func (c *Client) FetchAgentConfigPolicy(ctx context.Context) (bool, error) {
	if c.agentConfigGate == nil || !c.agentConfigGate(ctx) {
		return false, nil
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return false, fmt.Errorf("orgclient.FetchAgentConfigPolicy: enrolment: %w", err)
	}
	if enr == nil {
		return false, ErrNotEnrolled
	}
	// Managed by enrolment or by its org's switch to enterprise (P-204).
	if managed, merr := NodeManagedFor(ctx, c.store, enr); merr != nil {
		return false, fmt.Errorf("orgclient.FetchAgentConfigPolicy: %w", merr)
	} else if !managed {
		return false, nil
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return false, fmt.Errorf("orgclient.FetchAgentConfigPolicy: bearer: %w", err)
	}
	url := strings.TrimRight(enr.OrgServerURL, "/") + orgcontract.AgentConfigPolicyPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return false, fmt.Errorf("orgclient.FetchAgentConfigPolicy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if c.classifyRail(agentConfigPolicyRail, resp) == railReplyNotSupported {
		// An older server (a 404, or its SPA page for an unknown GET), or a
		// member the server does not see as managed: keep what was last
		// verified, no error.
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("orgclient.FetchAgentConfigPolicy: server returned %d", resp.StatusCode)
	}
	var doc orgcontract.AgentConfigPolicyDoc
	if err := orgcontract.DecodeCapped(resp.Body, maxOrgDocBytes, &doc); err != nil {
		return false, fmt.Errorf("orgclient.FetchAgentConfigPolicy: decode: %w", err)
	}
	if doc.OrgID != enr.OrgID || doc.Subject != enr.UserID {
		return false, fmt.Errorf("orgclient.FetchAgentConfigPolicy: document is for %q/%q, this node is %q/%q - refusing",
			doc.OrgID, doc.Subject, enr.OrgID, enr.UserID)
	}
	cached, hasCached, err := c.store.GetOrgAgentConfigPolicy(ctx)
	if err != nil {
		return false, err
	}
	if hasCached && (cached.OrgID != enr.OrgID || cached.Subject != enr.UserID) {
		hasCached = false // a row for another enrolment constrains nothing here
	}
	pinned, repinned, stale, err := c.agentConfigPolicyPin(ctx, cached, hasCached, doc)
	if err != nil {
		return false, fmt.Errorf("orgclient.FetchAgentConfigPolicy: %w", err)
	}
	// T-655 (the T-390 shape): verify FIRST, then honour staleness. A
	// document's version is only a fact once its signature (bound to this org
	// and member) holds, so a tampered document or another member's at or
	// below the cached version is refused, not read as "unchanged".
	if err := c.checkOrgKeyIdentity(ctx, agentConfigPolicyRail, doc.PublicKey); err != nil {
		return false, fmt.Errorf("orgclient.FetchAgentConfigPolicy: %w", err)
	}
	if err := orgcontract.VerifyAgentConfigPolicy(doc, enr.OrgID, enr.UserID, pinned); err != nil {
		return false, fmt.Errorf("orgclient.FetchAgentConfigPolicy: %w", err)
	}
	if stale {
		return false, nil
	}
	body, err := orgcontract.DecodeAgentConfigPolicyBody(doc.Body)
	if err != nil {
		// A newer schema than this build reads: keep the last verified body.
		return false, fmt.Errorf("orgclient.FetchAgentConfigPolicy: %w", err)
	}
	if err := c.store.UpsertOrgAgentConfigPolicy(ctx, store.OrgAgentConfigPolicyRow{
		OrgID: doc.OrgID, Subject: doc.Subject, Version: doc.Version, Body: doc.Body, BodyHash: doc.BodyHash,
		Signature: doc.Signature, ServerPubkey: pinned, ReceivedAt: time.Now().UTC(),
	}); err != nil {
		return false, err
	}
	if repinned || !hasCached {
		c.adoptEnrolmentKeyMaterial(ctx, pinned)
	}
	c.logger.Info("org AI tool policy cached", "version", doc.Version, "directives", len(body.Directives), "grants", len(body.Grants))
	return true, nil
}

// agentConfigPolicyPin resolves which key the offered document is verified
// against and whether it is stale. With no usable cached row the offered key
// is taken (and checked against the org identity by the caller). With one,
// the cached key stays pinned unless the offered change is accepted
// (repinned), and a document at or below the cached version is stale, except
// that a re-pin may re-apply the same version under the new key.
func (c *Client) agentConfigPolicyPin(ctx context.Context, cached store.OrgAgentConfigPolicyRow, hasCached bool, doc orgcontract.AgentConfigPolicyDoc) (pinned string, repinned, stale bool, err error) {
	if !hasCached {
		return doc.PublicKey, false, false, nil
	}
	pinned = cached.ServerPubkey
	if cached.ServerPubkey != doc.PublicKey {
		if err := c.acceptOfferedKeyChange(ctx, agentConfigPolicyRail, cached.ServerPubkey, doc.PublicKey); err != nil {
			return "", false, false, err
		}
		pinned, repinned = doc.PublicKey, true
	}
	stale = cached.Version >= doc.Version && !(repinned && doc.Version >= cached.Version)
	return pinned, repinned, stale, nil
}

// refreshAgentConfigPolicy fetches the rail under railsMu and, when a NEW
// verified version was cached, runs the sink (the daemon applies it). The
// push cycle and the freshness dispatch both call it.
func (c *Client) refreshAgentConfigPolicy(ctx context.Context) (bool, error) {
	c.railsMu.Lock()
	changed, err := c.FetchAgentConfigPolicy(ctx)
	c.railsMu.Unlock()
	if changed && err == nil && c.agentConfigSink != nil {
		c.agentConfigSink()
	}
	return changed, err
}
