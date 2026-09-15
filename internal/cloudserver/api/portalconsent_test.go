package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// portalconsent_test.go is the F9 suite: the browser consent screen backed by
// REAL server state instead of a localStorage "seen" flag and a module
// variable. What is pinned here is that the state survives (a second request
// with a fresh client sees it), that the server — not the browser — decides
// what a mandatory purpose is stored as, that an unoffered purpose is refused
// rather than stored, and that every change lands in the append-only trail.

type consentBody struct {
	Choices  map[string]bool `json:"choices"`
	Purposes []struct {
		ID        string `json:"id"`
		Mandatory bool   `json:"mandatory"`
	} `json:"purposes"`
	UpdatedAt string `json:"updated_at"`
	Notice    string `json:"notice"`
}

func consentOf(t *testing.T, resp *http.Response, wantStatus int) consentBody {
	t.Helper()
	body := readAll(resp)
	if resp.StatusCode != wantStatus {
		t.Fatalf("status=%d, want %d; body=%s", resp.StatusCode, wantStatus, body)
	}
	var out consentBody
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode consent body %q: %v", body, err)
	}
	return out
}

// postConsent submits a choice set with the client's real CSRF token.
func (c *portalClient) postConsent(choices map[string]bool) *http.Response {
	c.t.Helper()
	body, err := json.Marshal(map[string]any{"choices": choices})
	if err != nil {
		c.t.Fatalf("marshal choices: %v", err)
	}
	return c.mutate("POST", "/portal/api/consent", body, c.csrf)
}

// TestPortalConsentRequiresASessionAndCSRF is the BFF auth wall. The GET needs a
// session; the POST needs a session AND the double-submit token, because it is a
// mutation and a mutation reachable from another origin's page is a mutation
// somebody else can make.
func TestPortalConsentRequiresASessionAndCSRF(t *testing.T) {
	h := newHarness(t)

	// No cookie at all.
	for _, tc := range []struct{ method, path string }{
		{"GET", "/portal/api/consent"},
		{"POST", "/portal/api/consent"},
	} {
		req, _ := http.NewRequest(tc.method, h.srv.URL+tc.path, http.NoBody)
		resp, err := h.srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s without a session = %d, want 401 (body=%s)",
				tc.method, tc.path, resp.StatusCode, readAll(resp))
		}
		resp.Body.Close()
	}

	// Signed in, but no CSRF header on the mutation.
	c := h.portalLogin(t, "consent-csrf")
	body, _ := json.Marshal(map[string]any{"choices": map[string]bool{}})
	for name, token := range map[string]string{"missing": "", "wrong": "not-the-token"} {
		resp := c.mutate("POST", "/portal/api/consent", body, token)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s CSRF token: status=%d, want 403 (body=%s)", name, resp.StatusCode, readAll(resp))
		}
		resp.Body.Close()
	}
	// And nothing was stored by any of those attempts.
	stored, err := h.store.PortalConsentChoices(context.Background(), c.accountID)
	if err != nil {
		t.Fatalf("PortalConsentChoices: %v", err)
	}
	if len(stored) != 0 {
		t.Fatalf("a refused request still stored choices: %+v", stored)
	}
}

// TestPortalConsentAbsentUntilSetupRuns pins the honesty rule the SPA's
// "needs setup" decision now rests on: before the screen runs, choices is JSON
// null — which is a different claim from "everything declined", and is the ONLY
// signal the SPA uses (the localStorage marker is gone).
func TestPortalConsentAbsentUntilSetupRuns(t *testing.T) {
	h := newHarness(t)
	c := h.portalLogin(t, "consent-absent")

	got := consentOf(t, c.get("/portal/api/consent"), http.StatusOK)
	if got.Choices != nil {
		t.Fatalf("a fresh account already has choices: %+v", got.Choices)
	}
	if len(got.Purposes) == 0 {
		t.Fatal("the server offered no purposes; the screen would render empty")
	}
	if got.Notice == "" {
		t.Fatal("the server served no scope notice; the screen would have to invent its own copy")
	}
	// Every offered id is a real consent purpose — the screen's vocabulary is a
	// SUBSET of the canonical one, never a second one.
	mandatory := 0
	for _, p := range got.Purposes {
		if !cloudcontract.Purpose(p.ID).Valid() {
			t.Fatalf("offered purpose %q is not in the cloudcontract vocabulary", p.ID)
		}
		if p.Mandatory {
			mandatory++
			if p.ID != string(cloudcontract.PurposeStructuralInsights) {
				t.Fatalf("unexpected mandatory purpose %q", p.ID)
			}
		}
	}
	if mandatory != 1 {
		t.Fatalf("%d mandatory purposes offered, want exactly 1", mandatory)
	}
}

// TestPortalConsentRoundTripsAcrossReload is the reload-safety property the
// localStorage shell could not provide: a brand-new client (no shared memory,
// its own cookie jar) signing into the SAME account reads back exactly what was
// stored.
func TestPortalConsentRoundTripsAcrossReload(t *testing.T) {
	h := newHarness(t)
	c := h.portalLogin(t, "consent-reload")

	posted := consentOf(t, c.postConsent(map[string]bool{
		string(cloudcontract.PurposeContextEnrichment):  true,
		string(cloudcontract.PurposeCohortBenchmarking): false,
	}), http.StatusOK)
	if posted.Choices[string(cloudcontract.PurposeContextEnrichment)] != true {
		t.Fatalf("the granted optional purpose did not come back granted: %+v", posted.Choices)
	}
	if posted.UpdatedAt == "" {
		t.Fatal("a stored choice set reported no updated_at")
	}

	// A second browser for the same developer.
	reload := h.portalLogin(t, "consent-reload")
	if reload.accountID != c.accountID {
		t.Fatalf("fixture broke: the same subject resolved to two accounts")
	}
	got := consentOf(t, reload.get("/portal/api/consent"), http.StatusOK)
	if got.Choices == nil {
		t.Fatal("a second browser saw no choices — the state did not persist server-side")
	}
	for id, want := range posted.Choices {
		if got.Choices[id] != want {
			t.Fatalf("purpose %q read back as %v, want %v", id, got.Choices[id], want)
		}
	}
}

// TestPortalConsentMandatoryIsAlwaysStoredGranted pins the server-side force. The
// screen shows the mandatory purpose checked and disabled; a hand-rolled POST
// that omits it, or explicitly declines it, must still store it granted —
// otherwise the Privacy page would later present a state the screen could never
// have produced.
func TestPortalConsentMandatoryIsAlwaysStoredGranted(t *testing.T) {
	mandatory := string(cloudcontract.PurposeStructuralInsights)
	for name, choices := range map[string]map[string]bool{
		"omitted":             {string(cloudcontract.PurposeContextEnrichment): true},
		"explicitly declined": {mandatory: false},
		"empty set":           {},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			c := h.portalLogin(t, "consent-mand")
			got := consentOf(t, c.postConsent(choices), http.StatusOK)
			if got.Choices[mandatory] != true {
				t.Fatalf("the mandatory purpose was stored as %v: %+v", got.Choices[mandatory], got.Choices)
			}
			// And an OPTIONAL purpose left out of the body is stored declined —
			// the screen always submits its whole set, so an omission is a
			// decline, never an "unchanged".
			optional := string(cloudcontract.PurposeCohortBenchmarking)
			if _, present := got.Choices[optional]; !present {
				t.Fatalf("an offered optional purpose is missing from the stored set: %+v", got.Choices)
			}
			if got.Choices[optional] {
				t.Fatalf("an omitted optional purpose was stored granted: %+v", got.Choices)
			}
		})
	}
}

// TestPortalConsentRejectsUnknownPurpose pins that the SERVER owns the
// vocabulary. A purpose the screen does not offer is refused outright rather
// than silently dropped: silently dropping it would let a caller believe it had
// been recorded.
func TestPortalConsentRejectsUnknownPurpose(t *testing.T) {
	h := newHarness(t)
	c := h.portalLogin(t, "consent-unknown")

	for name, id := range map[string]string{
		"not a purpose at all": "totally_made_up",
		// A REAL cloudcontract purpose that this screen nonetheless does not
		// offer: valid vocabulary is not the same as offered vocabulary.
		"valid but not offered": string(cloudcontract.PurposeResearch),
	} {
		resp := c.postConsent(map[string]bool{id: true})
		if code := errCodeOf(t, resp, http.StatusBadRequest); code != "unknown_purpose" {
			t.Fatalf("%s: code = %q, want unknown_purpose", name, code)
		}
	}
	stored, err := h.store.PortalConsentChoices(context.Background(), c.accountID)
	if err != nil {
		t.Fatalf("PortalConsentChoices: %v", err)
	}
	if len(stored) != 0 {
		t.Fatalf("a refused submission stored choices: %+v", stored)
	}
}

// TestPortalConsentRevokeAppendsAnEvent is the audit-trail property: consent
// CHANGES must be reconstructable. Granting then revoking a purpose leaves two
// events in order; re-submitting an unchanged set appends nothing, so the trail
// records decisions rather than page loads.
func TestPortalConsentRevokeAppendsAnEvent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	c := h.portalLogin(t, "consent-events")
	optional := string(cloudcontract.PurposeContextEnrichment)

	consentOf(t, c.postConsent(map[string]bool{optional: true}), http.StatusOK)
	// Re-submitting the SAME set changes nothing and must append nothing.
	consentOf(t, c.postConsent(map[string]bool{optional: true}), http.StatusOK)
	// Now revoke it (the Privacy page's per-purpose control).
	after := consentOf(t, c.postConsent(map[string]bool{optional: false}), http.StatusOK)
	if after.Choices[optional] {
		t.Fatalf("the revoked purpose is still granted: %+v", after.Choices)
	}

	events, err := h.store.PortalConsentHistory(ctx, c.accountID, 0)
	if err != nil {
		t.Fatalf("PortalConsentHistory: %v", err)
	}
	var forOptional []store.PortalConsentEvent
	for _, ev := range events {
		if ev.Purpose == optional {
			forOptional = append(forOptional, ev)
		}
	}
	if len(forOptional) != 2 {
		t.Fatalf("%d events for %s, want exactly 2 (grant then revoke; the unchanged re-submit appends nothing): %+v",
			len(forOptional), optional, forOptional)
	}
	// Newest first.
	if forOptional[0].Action != store.PortalConsentRevoked || forOptional[1].Action != store.PortalConsentGranted {
		t.Fatalf("event trail is not grant-then-revoke: %+v", forOptional)
	}

	// The trail is APPEND-ONLY by privilege, not just by convention: the app
	// role holds no UPDATE or DELETE on it. Proven through the app role's own
	// tenant transaction, which is the only way the service ever writes.
	for _, stmt := range []string{
		`DELETE FROM portal_consent_events`,
		`UPDATE portal_consent_events SET action = 'granted'`,
	} {
		// Each probe gets its OWN transaction: the first failure aborts the one
		// it ran in, so reusing it would make the second probe pass for the
		// wrong reason.
		err := h.store.WithAccount(ctx, c.accountID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, stmt)
			return e
		})
		if err == nil {
			t.Errorf("the app role could run %q against the consent trail", stmt)
		}
	}
}

// TestPortalConsentTenantIsolation is the RLS wall: one account's choices are
// invisible to another's session.
func TestPortalConsentTenantIsolation(t *testing.T) {
	h := newHarness(t)
	alice := h.portalLogin(t, "consent-alice")
	bob := h.portalLogin(t, "consent-bob")
	if alice.accountID == bob.accountID {
		t.Fatalf("fixture broke: two subjects share an account")
	}

	consentOf(t, alice.postConsent(map[string]bool{
		string(cloudcontract.PurposeContextEnrichment): true,
	}), http.StatusOK)

	got := consentOf(t, bob.get("/portal/api/consent"), http.StatusOK)
	if got.Choices != nil {
		t.Fatalf("bob sees alice's choices: %+v", got.Choices)
	}
}

// TestPortalConsentChoicesPurgedOnDeletion pins the deletion posture: the live
// CHOICE rows go with the account, and the append-only event trail stays — the
// same split consent_receipts/consent_events already have, and for the same
// reason (the trail is the fact that proves what was agreed and carries no
// activity data).
func TestPortalConsentChoicesPurgedOnDeletion(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	c := h.portalLogin(t, "consent-deleted")
	consentOf(t, c.postConsent(map[string]bool{
		string(cloudcontract.PurposeContextEnrichment): true,
	}), http.StatusOK)

	if _, err := h.store.CreateDeletionRequest(ctx, c.accountID, time.Now()); err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err)
	}

	var choices, events int
	if err := h.store.Pool().QueryRow(ctx,
		`SELECT (SELECT count(*) FROM portal_consent_choices WHERE account_id = $1::uuid),
		        (SELECT count(*) FROM portal_consent_events  WHERE account_id = $1::uuid)`,
		c.accountID).Scan(&choices, &events); err != nil {
		t.Fatalf("count portal consent rows: %v", err)
	}
	if choices != 0 {
		t.Fatalf("%d consent choice rows survived deletion, want 0", choices)
	}
	if events == 0 {
		t.Fatal("the consent audit trail was purged; it is retained like consent_events")
	}
}
