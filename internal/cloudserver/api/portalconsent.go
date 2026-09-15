package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// portalconsent.go is the server state behind the browser consent screen (F9).
//
// SCOPE — the sentence that keeps two consent models from being "unified" by a
// later change: these are PORTAL-plane preferences, gating SERVER-SIDE surfaces
// for a signed-in developer. They are NOT the authority for what a node may
// upload. Node egress consent is NODE-authoritative: the node holds the standing
// grant, declares its consent generation on every upload, and the server
// validates that upload against its per-(account, purpose) REGISTRATION, which
// follows the node's declared generation monotonically (see structural.go and
// store.RegisterStructuralGrant). Nothing on the upload path reads the tables
// below, and nothing here mints or moves accounts.consent_generation. Granting a
// purpose here does not authorize any node to send anything; revoking one here
// does not, by itself, stop a node that still holds its own local grant — what
// it does is withdraw the portal-side permission for the surfaces this service
// builds on that purpose, and the honest copy on the screen says exactly that.
//
// Before this existed, the screen wrote a localStorage "seen" flag and kept the
// chosen set in a module variable: the choices did not survive a reload, did not
// follow the account to a second browser, and there was no way to answer "what
// did this developer actually agree to". R2/F12 and the fifth R7 launch gate
// both require real state before the screen is exposed.

// portalConsentPurpose is one purpose the consent screen offers. The SERVER owns
// this list: the SPA renders labels for these ids, and a submission naming
// anything else is refused, so the two cannot drift into a state where the
// browser believes it granted something the server never stored.
type portalConsentPurpose struct {
	ID string `json:"id"`
	// Mandatory purposes are the condition of the signed-in product itself. They
	// are shown checked and disabled, and forced true SERVER-side, so a
	// hand-rolled POST cannot store a set that the screen could not have
	// produced. Declining is not a checkbox — it is not signing in.
	Mandatory bool `json:"mandatory"`
}

// portalConsentPurposes is the offered set, in screen order. Every id is a
// cloudcontract Purpose (pinned by a test), so this is a SUBSET of the canonical
// vocabulary, never a second one.
var portalConsentPurposes = []portalConsentPurpose{
	{ID: string(cloudcontract.PurposeStructuralInsights), Mandatory: true},
	{ID: string(cloudcontract.PurposeContextEnrichment), Mandatory: false},
	{ID: string(cloudcontract.PurposeCohortBenchmarking), Mandatory: false},
}

// portalConsentNotice is the honest scoping line the screen and the Privacy page
// render verbatim. It is served rather than hard-coded in the SPA so the copy
// and the behaviour are changed in one place.
const portalConsentNotice = "These choices control what this service does with your data on the cloud side, for your signed-in account. " +
	"They are separate from the grant you make on a device: a device only ever uploads what you granted it locally, and you " +
	"withdraw that on the device itself. " +
	providerPostureDisclosure

// providerPostureDisclosure is the shared one-sentence provider-retention
// disclosure (cloudcontract.ProviderPostureDisclosure - the node consent screen,
// `observer cloud enable` and this served notice all render the same text).
const providerPostureDisclosure = cloudcontract.ProviderPostureDisclosure

// portalConsentResponse is the GET payload. Choices is nil (JSON null) when the
// account has never completed the screen — the SPA derives "needs setup" from
// that, which is why the localStorage marker is gone.
type portalConsentResponse struct {
	Choices   map[string]bool        `json:"choices"`
	Purposes  []portalConsentPurpose `json:"purposes"`
	UpdatedAt string                 `json:"updated_at,omitempty"`
	Notice    string                 `json:"notice"`
}

// handlePortalConsentChoices serves the account's current portal consent
// choices, or null when the screen has not been completed.
func (s *Server) handlePortalConsentChoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := portalPrincipalFrom(ctx)

	stored, err := s.store.PortalConsentChoices(ctx, p.AccountID)
	if err != nil {
		s.log.Error("cloudserver/api: portal consent read", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read consent choices")
		return
	}
	out := portalConsentResponse{Purposes: portalConsentPurposes, Notice: portalConsentNotice}
	if len(stored) > 0 {
		out.Choices = make(map[string]bool, len(stored))
		var newest time.Time
		for _, c := range stored {
			out.Choices[c.Purpose] = c.Granted
			if c.UpdatedAt.After(newest) {
				newest = c.UpdatedAt
			}
		}
		out.UpdatedAt = newest.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, out)
}

type portalConsentRequest struct {
	// Choices maps purpose id to granted. A purpose the screen offers but the
	// body omits is stored as NOT granted — the screen always submits its whole
	// set, so an omission is a decline, never an "unchanged".
	Choices map[string]bool `json:"choices"`
}

// handlePortalSetConsentChoices stores the whole choice set (portalAuth ⇒ session
// cookie + double-submit CSRF, since this is a mutation).
//
// Two rules are enforced SERVER-side rather than trusted from the browser:
// a mandatory purpose is always stored granted, and a purpose outside the
// offered set is refused rather than silently dropped. The second is what makes
// the first meaningful — otherwise a caller could store a purpose the screen
// never showed and the Privacy page would later present it as agreed.
func (s *Server) handlePortalSetConsentChoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := portalPrincipalFrom(ctx)

	var req portalConsentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	offered := make(map[string]bool, len(portalConsentPurposes))
	for _, pp := range portalConsentPurposes {
		offered[pp.ID] = pp.Mandatory
	}
	for id := range req.Choices {
		if _, ok := offered[id]; !ok {
			writeErr(w, http.StatusBadRequest, "unknown_purpose",
				"this consent screen does not offer the purpose "+quoteForError(id))
			return
		}
	}
	choices := make(map[string]bool, len(offered))
	for id, mandatory := range offered {
		choices[id] = mandatory || req.Choices[id]
	}

	stored, err := s.store.SetPortalConsentChoices(ctx, p.AccountID, choices, s.now())
	if err != nil {
		s.log.Error("cloudserver/api: portal consent write", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not save consent choices")
		return
	}
	s.audit(ctx, p.AccountID, "portal_consent_choices_set")

	out := portalConsentResponse{
		Choices:  make(map[string]bool, len(stored)),
		Purposes: portalConsentPurposes,
		Notice:   portalConsentNotice,
	}
	var newest time.Time
	for _, c := range stored {
		out.Choices[c.Purpose] = c.Granted
		if c.UpdatedAt.After(newest) {
			newest = c.UpdatedAt
		}
	}
	if !newest.IsZero() {
		out.UpdatedAt = newest.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, out)
}

// quoteForError quotes an untrusted identifier for an error message. It strips
// quotes, backslashes and control bytes and bounds the length, so echoing a
// client-supplied string back cannot break the message's own framing or turn the
// error body into an amplifier.
func quoteForError(s string) string {
	const max = 64
	if len(s) > max {
		s = s[:max] + "..."
	}
	out := make([]rune, 0, len(s)+2)
	out = append(out, '"')
	for _, r := range s {
		if r < 0x20 || r == '"' || r == '\\' {
			continue
		}
		out = append(out, r)
	}
	return string(append(out, '"'))
}
