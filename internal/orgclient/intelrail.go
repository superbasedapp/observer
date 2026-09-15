package orgclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The node half of the org-served Cloud Intelligence RESULT rail
// (docs/plans/org-served-cloud-intelligence-plan-2026-09-10.md §1.3/§2.4/§2.5,
// W3).
//
// It PULLS the org server's own derived per-session enrichment results for
// sessions this node owns and caches them node-locally (org_intel_cache,
// through store.UpsertOrgIntelResult). That is NOT evidence egress — it is the
// same request/response shape as GET /api/agent/pricing, the org's product
// coming BACK to the node. So it rides the EXISTING push/poll loop beside the
// pricing and budget rails (announce.go discipline: no new timer, no new host,
// no new connection), NOT `observer cloud`, which stays the personal plane.
//
// AUTH mirrors the judge relay's SHAPE (judgerelay.go): the enrolment bearer
// plus a per-request Ed25519 proof — loaded together via LoadEnrolment /
// LoadBearer / LoadAgentKey, each mapping a miss to ErrNotEnrolled. But the
// proof MESSAGE is this rail's OWN domain-separated
// orgcontract.IntelRailSigningMessage(ts, method, path, canonical query, org id),
// NOT PushSigningMessage(ts, body): a GET carries no body, and binding the
// method/path/query/org (rather than the body) is what stops a judge-relay proof
// being replayed here. The signed canonical query pins limit=0 — the page size
// is server-owned — so no client `?limit` is ever sent.
//
// The status LADDER is the pricing rail's (pricingpolicy.go): 200 apply /
// 404 not_supported NEVER clears (logged once — a 404 is indistinguishable
// from a pre-feature server and must not wipe a node's cached results) /
// 401-403 auth failed / 409 channel off / 5xx + transport unreachable /
// malformed body. Unlike the pricing DOCUMENT rail there is no signed body to
// verify — results are a request/response product over the authenticated org
// connection, not a distributed signed document (§2.5).

// intelResultsMaxBodyBytes bounds the 200 result page read. Results are short
// prose; this is generous headroom against a misbehaving server.
const intelResultsMaxBodyBytes = 4 << 20 // 4 MiB

// IntelFetchOutcome is the typed classification of one result-pull cycle, in
// the shape PricingFetchOutcome established.
type IntelFetchOutcome struct {
	// State is the closed IntelFetch* enum below.
	State string
	// Applied is the number of result rows upserted this cycle.
	Applied int
	// NextCursor is the server's continuation cursor after this cycle (the
	// node's new `since`); empty when nothing new was returned.
	NextCursor string
}

// Result-pull ladder states. Node-only — nothing ships these on the wire, so
// they live here rather than in orgcontract (which holds only the wire types).
const (
	// IntelFetchDisabled — [intelligence].org_enrichment is off (or no gate
	// was installed). No request is made.
	IntelFetchDisabled = "disabled"
	// IntelFetchOK — a result page was fetched and cached (possibly empty).
	IntelFetchOK = "ok"
	// IntelFetchNotEnrolled — no org enrolment on this node.
	IntelFetchNotEnrolled = "not_enrolled"
	// IntelFetchUnreachable — transport error / timeout / 5xx / other non-200.
	IntelFetchUnreachable = "unreachable"
	// IntelFetchAuthFailed — 401/403: the server answered, our credential was
	// refused.
	IntelFetchAuthFailed = "auth_failed"
	// IntelFetchNotSupported — 404: the org server predates the rail, or the
	// feature is off for this org. NEVER clears the cache (pricing rail N1).
	IntelFetchNotSupported = "not_supported"
	// IntelFetchChannelOff — 409: the feature's channel is off. Like
	// not_supported, it clears nothing.
	IntelFetchChannelOff = "channel_off"
	// IntelFetchMalformed — a 200 body arrived but did not decode.
	IntelFetchMalformed = "malformed"
	// IntelFetchIdentityChanged — the enrolment's org id changed while the
	// request was in flight, so the page belongs to an enrolment that is no
	// longer current. The page is DISCARDED (never cached, cursor not advanced)
	// — a response from an obsolete enrolment is refused (finding 6).
	IntelFetchIdentityChanged = "identity_changed"
)

// SetIntelRail turns the result-pull rail on. enabled is the
// [intelligence].org_enrichment gate; nil leaves the rail OFF (the opt-in
// default), so a build that never wires it makes no request. It gates the
// REQUEST, not merely the apply — a node that has not opted into org
// enrichment has no business asking the org for it.
func (c *Client) SetIntelRail(enabled func() bool) {
	if c == nil {
		return
	}
	c.intelEnabled = enabled
}

// intelRailEnabled resolves the gate. A nil resolver is OFF.
func (c *Client) intelRailEnabled() bool {
	return c != nil && c.intelEnabled != nil && c.intelEnabled()
}

// FetchIntelResults pulls one page of the org's derived enrichment results for
// this node's sessions and caches each row node-locally. Every failure is
// FAIL-OPEN: the outcome names the state, the cache keeps whatever it holds,
// and the error is for logging only. A 404/409 clears NOTHING.
func (c *Client) FetchIntelResults(ctx context.Context) (IntelFetchOutcome, error) {
	if !c.intelRailEnabled() {
		return IntelFetchOutcome{State: IntelFetchDisabled}, nil
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return IntelFetchOutcome{State: IntelFetchNotEnrolled}, fmt.Errorf("orgclient.FetchIntelResults: enrolment: %w", err)
	}
	if enr == nil {
		return IntelFetchOutcome{State: IntelFetchNotEnrolled}, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if errors.Is(err, ErrNoSecret) {
		return IntelFetchOutcome{State: IntelFetchNotEnrolled}, ErrNotEnrolled
	}
	if err != nil {
		return IntelFetchOutcome{State: IntelFetchNotEnrolled}, fmt.Errorf("orgclient.FetchIntelResults: bearer: %w", err)
	}
	signKey, err := c.bearers.LoadAgentKey()
	if errors.Is(err, ErrNoSecret) {
		return IntelFetchOutcome{State: IntelFetchNotEnrolled}, ErrNotEnrolled
	}
	if err != nil {
		return IntelFetchOutcome{State: IntelFetchNotEnrolled}, fmt.Errorf("orgclient.FetchIntelResults: signing key: %w", err)
	}

	// Bind the cursor and cache to THIS enrolment's org id. If the live
	// enrolment's org differs from the one the in-memory cursor belongs to (a
	// re-enrol, possibly to a DIFFERENT org), reset the cursor to page from the
	// start and drop any cached rows stamped with a foreign org — org A's
	// cursor and results must never bleed into org B (finding 6).
	boundOrgID := enr.OrgID
	if boundOrgID != c.intelCursorOrgID {
		c.intelSince = ""
		if derr := c.store.DeleteForeignOrgIntelResults(ctx, boundOrgID); derr != nil {
			c.logger.Warn("org intelligence cache: dropping foreign-org rows failed", "err", derr)
		}
		c.intelCursorOrgID = boundOrgID
	}

	// A GET carries NO body; the proof is domain-separated (finding 1) and binds
	// the method, path, canonical query and org id — NOT the body — so a
	// judge-relay proof can never be replayed here. The node builds the request
	// URL from the SAME canonical query it signs over, so the two can never
	// drift.
	ts := time.Now().Unix()
	canonical := orgcontract.IntelRailCanonicalQuery(c.intelSince, 0)
	sig := ed25519.Sign(signKey, orgcontract.IntelRailSigningMessage(
		ts, http.MethodGet, orgcontract.IntelResultsPath, canonical, boundOrgID))

	reqURL := strings.TrimRight(enr.OrgServerURL, "/") + orgcontract.IntelResultsPath
	if canonical != "" {
		reqURL += "?" + canonical
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return IntelFetchOutcome{State: IntelFetchUnreachable}, fmt.Errorf("orgclient.FetchIntelResults: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set(orgcontract.HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(orgcontract.HeaderAgentSignature, base64.RawURLEncoding.EncodeToString(sig))

	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return IntelFetchOutcome{State: IntelFetchUnreachable}, fmt.Errorf("orgclient.FetchIntelResults: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusOK:
		// fall through to decode
	case resp.StatusCode == http.StatusNotFound:
		// Pre-feature server, or the feature is off for this org. NEVER clears
		// the cache; logged at most once per daemon lifetime.
		if !c.intelNotSupportedLogged {
			c.logger.Info("org intelligence rail not supported by the org server (404) — keeping any cached results")
			c.intelNotSupportedLogged = true
		}
		return IntelFetchOutcome{State: IntelFetchNotSupported}, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return IntelFetchOutcome{State: IntelFetchAuthFailed},
			fmt.Errorf("orgclient.FetchIntelResults: server returned %d", resp.StatusCode)
	case resp.StatusCode == http.StatusConflict:
		return IntelFetchOutcome{State: IntelFetchChannelOff},
			fmt.Errorf("orgclient.FetchIntelResults: intelligence channel off (409)")
	default:
		return IntelFetchOutcome{State: IntelFetchUnreachable},
			fmt.Errorf("orgclient.FetchIntelResults: server returned %d", resp.StatusCode)
	}

	var page orgcontract.IntelResultsResponse
	if derr := json.NewDecoder(io.LimitReader(resp.Body, intelResultsMaxBodyBytes)).Decode(&page); derr != nil {
		return IntelFetchOutcome{State: IntelFetchMalformed}, fmt.Errorf("orgclient.FetchIntelResults: decode: %w", derr)
	}

	// Refuse a response from an obsolete enrolment (finding 6): if the live
	// enrolment changed org while the request was in flight, this page belongs
	// to an enrolment that is no longer current. Discard it without caching or
	// advancing the cursor.
	cur, cerr := c.store.LoadEnrolment(ctx)
	if cerr != nil {
		return IntelFetchOutcome{State: IntelFetchUnreachable}, fmt.Errorf("orgclient.FetchIntelResults: re-check enrolment: %w", cerr)
	}
	if cur == nil || cur.OrgID != boundOrgID {
		c.logger.Warn("org intelligence results discarded: enrolment identity changed in flight")
		return IntelFetchOutcome{State: IntelFetchIdentityChanged}, nil
	}

	applied := 0
	failed := 0
	for _, row := range page.Results {
		if row.SessionID == "" || row.JobID == "" {
			continue // a row we cannot key is not cacheable; skip rather than fail the page
		}
		if uerr := c.store.UpsertOrgIntelResult(ctx, store.OrgIntelResult{
			OrgID:         boundOrgID,
			SessionID:     row.SessionID,
			JobID:         row.JobID,
			Title:         row.Title,
			TaxonomyTags:  row.TaxonomyTags,
			SuggestedTags: row.SuggestedTags,
			Description:   row.Description,
			Confidence:    row.Confidence,
			Limitations:   row.Limitations,
			SchemaVersion: row.SchemaVersion,
		}); uerr != nil {
			// One row that would not persist (a write error, or a hostile field
			// the node-side SafeText gate rejected — finding 8) must not discard
			// the rest of the page, but it MUST hold the cursor back: advancing
			// past an un-persisted row would lose it forever within this daemon's
			// lifetime (finding 5).
			c.logger.Warn("org intelligence result not cached", "session_id", row.SessionID, "job_id", row.JobID, "err", uerr)
			failed++
			continue
		}
		applied++
	}
	// Advance the cursor only when the WHOLE page persisted and there is a
	// non-empty continuation. A single failed write retains the previous cursor
	// so the next cycle re-fetches the page and retries the failed row; the
	// UNIQUE(session_id, job_id) upsert makes re-storing the already-persisted
	// rows idempotent (finding 5).
	advanced := false
	if failed == 0 && page.NextCursor != "" {
		c.intelSince = page.NextCursor
		advanced = true
	}
	if applied > 0 {
		c.logger.Info("org intelligence results cached", "count", applied)
	}
	nextCursor := ""
	if advanced {
		nextCursor = page.NextCursor
	}
	return IntelFetchOutcome{State: IntelFetchOK, Applied: applied, NextCursor: nextCursor}, nil
}
