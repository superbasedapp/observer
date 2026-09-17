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

// intelDeadLetterAfter is N in the bounded dead-letter rule: the number of
// CONSECUTIVE cycles a single row may fail to persist before the rail stops
// holding the cursor for it. Three is deliberately small — a transient write
// error clears on the first retry, while a STRUCTURALLY unpersistable row (the
// node's SafeText gate refusing one of the many narrative items, or a column
// the node's schema does not have yet) is recognised within seconds rather than
// freezing the rail for the daemon's lifetime.
const intelDeadLetterAfter = 3

// intelRowKey identifies one result row across cycles. It is exactly the cache's
// UNIQUE key, so "the same row" means the same thing here and in SQL.
type intelRowKey struct {
	SessionID string
	JobID     string
}

// intelRejectVerdict is the decision for ONE row that would not persist.
type intelRejectVerdict struct {
	// Attempts is the row's new consecutive-failure count.
	Attempts int
	// DeadLetter is true once the row has burned through the threshold: stop
	// retrying it, stop holding the cursor for it, log it once by name.
	DeadLetter bool
	// HoldCursor is true while the row is still worth retrying — the cursor
	// must NOT advance past the page that contains it.
	HoldCursor bool
}

// decideIntelReject is the PURE half of the bounded dead-letter: given how many
// consecutive cycles this row has already failed, it returns the new count and
// whether the row has earned a dead-letter. It reads no clock, no map and no
// config, so its whole behaviour is one table of (prior, threshold) rows.
//
// The rule it encodes: hold the cursor while a row is still retryable, release
// it once the row is hopeless. Never the other way round — releasing early
// would silently drop a row that a single transient write error would have
// stored, and never releasing is the freeze this exists to prevent. A
// non-positive threshold falls back to intelDeadLetterAfter rather than
// dead-lettering on the first failure.
func decideIntelReject(priorAttempts, threshold int) intelRejectVerdict {
	if threshold <= 0 {
		threshold = intelDeadLetterAfter
	}
	if priorAttempts < 0 {
		priorAttempts = 0
	}
	attempts := priorAttempts + 1
	dead := attempts >= threshold
	return intelRejectVerdict{Attempts: attempts, DeadLetter: dead, HoldCursor: !dead}
}

// IntelFetchOutcome is the typed classification of one result-pull cycle, in
// the shape PricingFetchOutcome established.
type IntelFetchOutcome struct {
	// State is the closed IntelFetch* enum below.
	State string
	// Applied is the number of result rows upserted this cycle.
	Applied int
	// DeadLettered is the number of rows this cycle gave up on after
	// intelDeadLetterAfter consecutive rejections. A dead-lettered row is
	// simply NOT cached (fail-open: the node renders no enrichment for that
	// session); it is never partially stored and never silently truncated.
	DeadLettered int
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

// intelRailIdentity is the enrolment + credential set one result-pull cycle
// needs. It is resolved in ONE place (resolveIntelRailIdentity) so the fetch
// path carries the rail's logic rather than six credential branches.
type intelRailIdentity struct {
	OrgID     string
	ServerURL string
	Bearer    string
	SignKey   ed25519.PrivateKey
}

// resolveIntelRailIdentity loads the live enrolment and both credentials.
// Every failure means the same thing to this rail — it has nothing to prove
// itself with — so they all map to IntelFetchNotEnrolled and the returned
// error is for logging only (fail-open, like the rest of the rail).
func (c *Client) resolveIntelRailIdentity(ctx context.Context) (intelRailIdentity, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return intelRailIdentity{}, fmt.Errorf("orgclient.FetchIntelResults: enrolment: %w", err)
	}
	if enr == nil {
		return intelRailIdentity{}, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if errors.Is(err, ErrNoSecret) {
		return intelRailIdentity{}, ErrNotEnrolled
	}
	if err != nil {
		return intelRailIdentity{}, fmt.Errorf("orgclient.FetchIntelResults: bearer: %w", err)
	}
	signKey, err := c.bearers.LoadAgentKey()
	if errors.Is(err, ErrNoSecret) {
		return intelRailIdentity{}, ErrNotEnrolled
	}
	if err != nil {
		return intelRailIdentity{}, fmt.Errorf("orgclient.FetchIntelResults: signing key: %w", err)
	}
	return intelRailIdentity{
		OrgID:     enr.OrgID,
		ServerURL: enr.OrgServerURL,
		Bearer:    bearer,
		SignKey:   signKey,
	}, nil
}

// intelStatusRules maps one result-pull response status onto its ladder
// state. Table-driven (CLAUDE.md #5): a newly-meaningful status is one row
// here, never another arm grown onto the fetch path. A status no row matches
// is Unreachable — the honest default, since the node cannot tell a proxy
// error from a server bug.
var intelStatusRules = []struct {
	Code  int
	State string
}{
	{http.StatusOK, IntelFetchOK},
	{http.StatusNotFound, IntelFetchNotSupported},
	{http.StatusUnauthorized, IntelFetchAuthFailed},
	{http.StatusForbidden, IntelFetchAuthFailed},
	{http.StatusConflict, IntelFetchChannelOff},
}

// classifyIntelStatus resolves one response status to its ladder state.
func classifyIntelStatus(code int) string {
	for _, r := range intelStatusRules {
		if r.Code == code {
			return r.State
		}
	}
	return IntelFetchUnreachable
}

// intelNonOKOutcome turns a non-200 ladder state into its outcome plus the
// log-only error. Every branch here is FAIL-OPEN: the cache keeps whatever it
// holds and the cursor does not move — a 404/409 clears NOTHING.
func (c *Client) intelNonOKOutcome(state string, code int) (IntelFetchOutcome, error) {
	switch state {
	case IntelFetchNotSupported:
		// Pre-feature server, or the feature is off for this org. NEVER clears
		// the cache; logged at most once per daemon lifetime.
		if !c.intelNotSupportedLogged {
			c.logger.Info("org intelligence rail not supported by the org server (404) — keeping any cached results")
			c.intelNotSupportedLogged = true
		}
		return IntelFetchOutcome{State: state}, nil
	case IntelFetchChannelOff:
		return IntelFetchOutcome{State: state},
			errors.New("orgclient.FetchIntelResults: intelligence channel off (409)")
	default:
		return IntelFetchOutcome{State: state},
			fmt.Errorf("orgclient.FetchIntelResults: server returned %d", code)
	}
}

// FetchIntelResults pulls one page of the org's derived enrichment results for
// this node's sessions and caches each row node-locally. Every failure is
// FAIL-OPEN: the outcome names the state, the cache keeps whatever it holds,
// and the error is for logging only. A 404/409 clears NOTHING.
func (c *Client) FetchIntelResults(ctx context.Context) (IntelFetchOutcome, error) {
	if !c.intelRailEnabled() {
		return IntelFetchOutcome{State: IntelFetchDisabled}, nil
	}
	ident, err := c.resolveIntelRailIdentity(ctx)
	if err != nil {
		return IntelFetchOutcome{State: IntelFetchNotEnrolled}, err
	}
	bearer, signKey := ident.Bearer, ident.SignKey

	// Bind the cursor and cache to THIS enrolment's org id. If the live
	// enrolment's org differs from the one the in-memory cursor belongs to (a
	// re-enrol, possibly to a DIFFERENT org), reset the cursor to page from the
	// start and drop any cached rows stamped with a foreign org — org A's
	// cursor and results must never bleed into org B (finding 6).
	boundOrgID := ident.OrgID
	if boundOrgID != c.intelCursorOrgID {
		c.intelSince = ""
		// The dead-letter strikes belong to the cursor they were accrued
		// against: session ids are client-chosen, so a strike from org A must
		// never count against a same-id row from org B.
		c.intelRejects = nil
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

	reqURL := strings.TrimRight(ident.ServerURL, "/") + orgcontract.IntelResultsPath
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

	if state := classifyIntelStatus(resp.StatusCode); state != IntelFetchOK {
		return c.intelNonOKOutcome(state, resp.StatusCode)
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
	// held counts rows that failed but are still RETRYABLE — those are what
	// hold the cursor back. deadLettered counts rows this cycle gave up on;
	// they must NOT hold the cursor, or one unpersistable row freezes the rail.
	held := 0
	deadLettered := 0
	for _, row := range page.Results {
		if row.SessionID == "" || row.JobID == "" {
			continue // a row we cannot key is not cacheable; skip rather than fail the page
		}
		key := intelRowKey{SessionID: row.SessionID, JobID: row.JobID}
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
			// The five narrative lists. They are omitempty on the wire, so a
			// server that predates server migration 156 sends none and these
			// stay nil — cached as NULL, rendered as absence, never as five
			// empty answers.
			WorkDone:         row.WorkDone,
			PlansImplemented: row.PlansImplemented,
			IssuesFound:      row.IssuesFound,
			Failures:         row.Failures,
			NextSteps:        row.NextSteps,
			SchemaVersion:    row.SchemaVersion,
		}); uerr != nil {
			// One row that would not persist (a write error, or a hostile field
			// the node-side SafeText gate rejected — finding 8) must not discard
			// the rest of the page, and while it is still RETRYABLE it holds the
			// cursor back: advancing past an un-persisted row would lose it
			// forever within this daemon's lifetime (finding 5).
			//
			// But holding forever is its own failure. A row the node can NEVER
			// persist — schema drift, or one item of the five narrative lists
			// that the SafeText gate refuses — would re-fetch and re-reject the
			// same page every cycle and freeze the rail, so the node would stop
			// receiving ANY later result. After intelDeadLetterAfter consecutive
			// cycles the row is dead-lettered: logged once by name, counted, and
			// stepped over so the cursor can move on. Fail-open — a
			// dead-lettered row is simply not cached.
			v := decideIntelReject(c.intelRejects[key], intelDeadLetterAfter)
			if v.DeadLetter {
				delete(c.intelRejects, key)
				deadLettered++
				c.logger.Warn("org intelligence result dead-lettered after repeated rejection — skipping it so the rail can advance",
					"session_id", row.SessionID, "job_id", row.JobID, "attempts", v.Attempts, "err", uerr)
				continue
			}
			if c.intelRejects == nil {
				c.intelRejects = make(map[intelRowKey]int, 1)
			}
			c.intelRejects[key] = v.Attempts
			held++
			c.logger.Warn("org intelligence result not cached",
				"session_id", row.SessionID, "job_id", row.JobID, "attempt", v.Attempts, "err", uerr)
			continue
		}
		// A successful persist ends the row's rejection streak, so the count is
		// genuinely CONSECUTIVE and a row that recovers never carries a stale
		// strike into a later cycle.
		delete(c.intelRejects, key)
		applied++
	}
	// Advance the cursor only when every row that is still worth retrying
	// persisted, and there is a non-empty continuation. A retryable failure
	// retains the previous cursor so the next cycle re-fetches the page and
	// retries the row; the UNIQUE(session_id, job_id) upsert makes re-storing
	// the already-persisted rows idempotent (finding 5). A DEAD-LETTERED row
	// deliberately does not hold the cursor — that is the whole point of the
	// bound.
	advanced := false
	if held == 0 && page.NextCursor != "" {
		c.intelSince = page.NextCursor
		advanced = true
	}
	if applied > 0 || deadLettered > 0 {
		c.logger.Info("org intelligence results cached", "count", applied, "dead_lettered", deadLettered)
	}
	nextCursor := ""
	if advanced {
		nextCursor = page.NextCursor
	}
	return IntelFetchOutcome{State: IntelFetchOK, Applied: applied, DeadLettered: deadLettered, NextCursor: nextCursor}, nil
}
