package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloud_consent.go is the rest of the node dashboard's Cloud Intelligence
// account surface (cloud_account.go holds sign-in/sign-out/sync): the
// per-session PREVIEW and CONSENT actions the session card's buttons drive,
// the Settings "Consent grants" table + standing grant/revoke buttons, and
// "Delete cloud account" (operator directive: every `observer cloud` CLI verb
// needs a dashboard equivalent, and the session card gets buttons instead of
// copy-paste CLI blocks).
//
// Every action here is EITHER a pure store read (GET /api/cloud/consent/grants)
// or a bounded, SYNCHRONOUS run of the exact `observer cloud <verb> <args...>`
// subprocess a human would type — through the SAME CloudCommandRunner seam
// cloud_account.go's login/sync use. This file adds no second way to reach the
// network: it composes cloud_account.go's seams, never a new one, and keeps
// the package's zero-egress posture (see cloud_account.go's header).

const (
	// cloudPreviewTimeout bounds POST /api/cloud/preview: a preview does no
	// network I/O (it only reads the local DB and serializes bytes), so this is
	// generous headroom for a large session, not a network budget.
	cloudPreviewTimeout = 90 * time.Second
	// cloudConsentStepTimeout bounds EACH subprocess POST /api/cloud/consent
	// spawns (a standing-grant catch-up, then the per-session consent itself).
	cloudConsentStepTimeout = 90 * time.Second
	// cloudGrantRevokeTimeout bounds POST /api/cloud/consent/grant and
	// POST /api/cloud/consent/revoke.
	cloudGrantRevokeTimeout = 90 * time.Second
	// cloudDeleteAccountTimeout bounds POST /api/cloud/delete-account — longer
	// than the others because it makes a real server round trip (hosted
	// deletion request), not just a local operation.
	cloudDeleteAccountTimeout = 120 * time.Second
	// cloudPreviewOutputCap bounds the bytes POST /api/cloud/preview returns:
	// 256 KiB, keeping the HEAD (the literal preview bytes come first in
	// `observer cloud preview`'s output, before the digest/summary footer) so a
	// very large session still shows the part that matters most.
	cloudPreviewOutputCap = 256 * 1024
)

// The two consent purposes the session card offers, spelled EXACTLY as
// internal/cloudcontract.Purpose does (structural_activity_insights /
// bounded_context_enrichment). Mirrored here as plain strings — not imported
// — so this package keeps importing nothing from the cloud lane beyond the
// node-local store seam (cloud_account.go's "links NOTHING from the cloud
// lane" discipline).
const (
	cloudPurposeStructural = "structural_activity_insights"
	cloudPurposeBounded    = "bounded_context_enrichment"
)

// cloudPurposeAllowed reports whether p is one of the two purposes a
// session-evidence build may run under. The wider standing-grantable
// vocabulary (e.g. community cohort benchmarking) is a Settings-only concept
// surfaced via CloudGrantableProbe, never accepted here.
func cloudPurposeAllowed(p string) bool {
	return p == cloudPurposeStructural || p == cloudPurposeBounded
}

// cloudPurposeInvalidMessage is the one 400 message for an out-of-vocabulary
// purpose on the preview/consent routes.
func cloudPurposeInvalidMessage(got string) string {
	return fmt.Sprintf("purpose must be %q or %q (got %q)", cloudPurposeStructural, cloudPurposeBounded, got)
}

// cloudCapHead returns the first max bytes of b (the HEAD — `observer cloud
// preview` prints the literal upload bytes before its digest/summary footer,
// so the head is the part worth keeping) and whether it truncated the input.
func cloudCapHead(b []byte, max int) (string, bool) {
	if len(b) <= max {
		return string(b), false
	}
	return string(b[:max]), true
}

// cloudStartupNoticePrefix marks the process-startup lines internal/config
// prints to stderr (emitDeprecationOnce) when ~/.observer/config.toml still
// uses deprecated key aliases. They precede the child's real output because
// the runner captures stdout and stderr combined.
const cloudStartupNoticePrefix = "config: deprecation: "

// cloudStripStartupNotices drops the config-deprecation startup lines from a
// child's combined output so the preview panel shows ONLY what `observer cloud
// preview` printed about the session (the bytes, digests and summary) — the
// notices are about this machine's config file, not about what would upload,
// and the dashboard's Settings page already surfaces config migration. Every
// other line, including a real error, is kept verbatim.
func cloudStripStartupNotices(output string) string {
	if !strings.Contains(output, cloudStartupNoticePrefix) {
		return output
	}
	lines := strings.Split(output, "\n")
	kept := lines[:0]
	for _, l := range lines {
		if strings.HasPrefix(l, cloudStartupNoticePrefix) {
			continue
		}
		kept = append(kept, l)
	}
	return strings.Join(kept, "\n")
}

// cloudDecodeJSON decodes r's body into v, treating a missing/empty body as
// "leave v at its zero value" (a bare POST with no body is a valid, if
// pointless, request) rather than a decode error; a genuinely malformed body
// still errors so the handler can answer 400.
func cloudDecodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}

// runOnce runs one `observer cloud <verb> <args...>` synchronously, bounded by
// timeout, and returns its combined output plus ok/exit_error — the shape
// every synchronous action route in this file shares (preview, consent,
// grant, revoke, delete-account).
func (c *CloudAccountSeams) runOnce(ctx context.Context, verb string, args []string, timeout time.Duration) (output string, ok bool, exitError string) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var buf bytes.Buffer
	err := c.run(ctx, verb, args, &buf)
	output = cloudStripStartupNotices(buf.String())
	return output, err == nil, cloudChildError(output, err)
}

// cloudChildError renders a failed child's error for the JSON exit_error
// field the way a person would read it: cobra prints the RunE error as an
// "Error: <message>" line on stderr, and THAT message is the reason (e.g.
// "bounded_context_enrichment" cannot be granted standing consent: …), while
// exec's err is only "exit status 1". The last "Error: " line wins when one
// exists; otherwise the exec error is returned verbatim; nil err ⇒ "".
func cloudChildError(output string, err error) string {
	if err == nil {
		return ""
	}
	msg := ""
	for _, l := range strings.Split(output, "\n") {
		if strings.HasPrefix(l, cloudChildErrorPrefix) {
			msg = strings.TrimSpace(strings.TrimPrefix(l, cloudChildErrorPrefix))
		}
	}
	if msg != "" {
		return msg
	}
	return err.Error()
}

// cloudChildErrorPrefix is cobra's error-line prefix on stderr.
const cloudChildErrorPrefix = "Error: "

// --- preview -----------------------------------------------------------------

// CloudPreviewRequest is the body of POST /api/cloud/preview. Either
// SessionID+Purpose (the original shape) or ReceiptID alone (the ledger's
// "Show exact bytes" action, which knows a receipt id but not necessarily
// which session/purpose it bound) may be given; ReceiptID is resolved first
// when SessionID is empty.
type CloudPreviewRequest struct {
	SessionID string `json:"session_id"`
	Purpose   string `json:"purpose"`
	ReceiptID string `json:"receipt_id"`
}

// CloudPreviewResponse is the payload for POST /api/cloud/preview: the exact
// bytes (and honest summary) `observer cloud preview` prints — "what you see
// is what uploads" — capped at cloudPreviewOutputCap. SessionID/Purpose echo
// what was actually previewed, which matters when the request named a
// receipt_id instead of resolving them itself.
type CloudPreviewResponse struct {
	UploadDigest string `json:"upload_digest,omitempty"`
	OK           bool   `json:"ok"`
	Output       string `json:"output"`
	ExitError    string `json:"exit_error"`
	Truncated    bool   `json:"truncated"`
	SessionID    string `json:"session_id,omitempty"`
	Purpose      string `json:"purpose,omitempty"`
}

var cloudPreviewDigestPattern = regexp.MustCompile(`(?m)^upload digest:[ \t]+(sha256:[a-f0-9]{64})$`)

// handleCloudPreview serves POST /api/cloud/preview: runs `observer cloud
// preview --session <id> --purpose <p>` synchronously (no network — preview
// only reads the local DB and serializes bytes), so it is allowed even while a
// sign-in or sync is in flight and never refuses on sign-in state.
func (s *Server) handleCloudPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	var req CloudPreviewRequest
	if err := cloudDecodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	req.SessionID = strings.TrimSpace(req.SessionID)
	req.ReceiptID = strings.TrimSpace(req.ReceiptID)
	if req.SessionID == "" && req.ReceiptID != "" {
		sessionID, purpose, rerr := s.resolveCloudPreviewByReceipt(r.Context(), req.ReceiptID)
		if rerr != nil {
			http.Error(w, rerr.Error(), http.StatusBadRequest)
			return
		}
		req.SessionID = sessionID
		req.Purpose = purpose
	}
	if req.SessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}
	if !cloudPurposeAllowed(req.Purpose) {
		http.Error(w, cloudPurposeInvalidMessage(req.Purpose), http.StatusBadRequest)
		return
	}
	args := []string{"--session", req.SessionID, "--purpose", req.Purpose}
	if req.ReceiptID != "" {
		args = append(args, "--receipt-id", req.ReceiptID)
	}
	output, ok2, exitErr := c.runOnce(r.Context(), "preview", args, cloudPreviewTimeout)
	uploadDigest := ""
	if match := cloudPreviewDigestPattern.FindStringSubmatch(output); len(match) == 2 {
		uploadDigest = match[1]
	}
	head, truncated := cloudCapHead([]byte(output), cloudPreviewOutputCap)
	writeJSON(w, CloudPreviewResponse{
		OK: ok2, Output: head, ExitError: exitErr, Truncated: truncated,
		SessionID: req.SessionID, Purpose: req.Purpose, UploadDigest: uploadDigest,
	})
}

// resolveCloudPreviewByReceipt resolves a receipt id to the session id and
// purpose a preview should run under. It refuses (with an honest message) a
// standing receipt — it has no single upload to preview, only the daily
// snapshots the ledger already lists — and a receipt with no queued
// session-evidence upload at all.
func (s *Server) resolveCloudPreviewByReceipt(ctx context.Context, receiptID string) (sessionID, purpose string, err error) {
	const noSingleUpload = "a standing grant has no single upload to preview; its daily snapshots are listed in the ledger"
	st := store.New(s.db())
	rcpt, ok, rerr := st.GetCloudConsentReceipt(ctx, receiptID)
	if rerr != nil {
		return "", "", rerr
	}
	if !ok {
		return "", "", fmt.Errorf("receipt %q not found", receiptID)
	}
	if rcpt.GrantMode == store.CloudGrantStanding {
		return "", "", errors.New(noSingleUpload)
	}
	item, found, ierr := st.FindCloudOutboxByReceipt(ctx, receiptID)
	if ierr != nil {
		return "", "", ierr
	}
	if !found {
		return "", "", fmt.Errorf("receipt %q has no queued upload to preview", receiptID)
	}
	if item.Kind != store.CloudOutboxKindSessionEvidence || item.SessionID == "" {
		return "", "", errors.New(noSingleUpload)
	}
	return item.SessionID, rcpt.Purpose, nil
}

// --- per-session consent -----------------------------------------------------

// CloudConsentRequest is the body of POST /api/cloud/consent.
type CloudConsentRequest struct {
	ExpectedUploadDigest string `json:"expected_upload_digest,omitempty"`
	SessionID            string `json:"session_id"`
	Purpose              string `json:"purpose"`
}

// CloudConsentResponse is the payload for POST /api/cloud/consent.
type CloudConsentResponse struct {
	OK        bool   `json:"ok"`
	Output    string `json:"output"`
	ExitError string `json:"exit_error"`
}

// handleCloudConsent serves POST /api/cloud/consent: records per-session
// consent for a session, first catching up any standing grant the purpose set
// requires (see cloudPurposeSet) and the request authorized. Refused (409,
// before any subprocess) while a sign-in or sync is running — both would race
// this on the credential store / outbox.
func (s *Server) handleCloudConsent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	var req CloudConsentRequest
	if err := cloudDecodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	req.SessionID = strings.TrimSpace(req.SessionID)
	if req.SessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}
	if !cloudPurposeAllowed(req.Purpose) {
		http.Error(w, cloudPurposeInvalidMessage(req.Purpose), http.StatusBadRequest)
		return
	}
	if c.loginRunning() {
		http.Error(w, "a sign-in is running — wait for it to finish (or time out) before recording consent", http.StatusConflict)
		return
	}
	if c.syncRunning() {
		http.Error(w, "a sync is running — wait for it to finish before recording consent", http.StatusConflict)
		return
	}

	// The per-session receipt `observer cloud consent --session` records IS
	// the live grant the gateway checks before the upload (a per-upload
	// receipt for the purpose; internal/cloudgateway resolve() only demands a
	// STANDING receipt for the daily-window structural rail, never for a
	// session upload). No standing grant is minted here: excerpt content
	// (bounded_context_enrichment) is by design never standing-grantable, and
	// minting one for the structural purpose would authorize the background
	// rail the developer did not ask for. Standing grants stay an explicit
	// Settings action (handleCloudConsentGrant).
	args := []string{"--session", req.SessionID, "--purpose", req.Purpose, "--yes"}
	if req.ExpectedUploadDigest != "" {
		args = append(args, "--expected-upload-digest", req.ExpectedUploadDigest)
	}
	output, ok2, exitErr := c.runOnce(r.Context(), "consent", args, cloudConsentStepTimeout)
	writeJSON(w, CloudConsentResponse{OK: ok2, Output: output, ExitError: exitErr})
}

// --- standing-grant management (Settings) ------------------------------------

// CloudConsentReceiptView is one stored consent receipt on GET
// /api/cloud/consent/grants — content-free (purpose, versions, timestamps),
// never session data.
type CloudConsentReceiptView struct {
	ID      string `json:"id"`
	Purpose string `json:"purpose"`
	// Mode is "standing" or "per_upload" — an empty stored GrantMode (pre-098
	// rows) reads as "per_upload", the CLI's own `consent list` convention.
	Mode      string `json:"mode"`
	CreatedAt string `json:"created_at"`
	// ReviewAt is "" when the receipt carries no review/expiry date.
	ReviewAt string `json:"review_at"`
	// InvalidatedAt is nil while the receipt is live.
	InvalidatedAt *string `json:"invalidated_at"`
	// Live is true when the receipt has not been invalidated (the same "live"
	// cloudgateway.Grant resolution starts from; it does not additionally apply
	// review_at expiry, which is the gateway's own clock policy).
	Live bool `json:"live"`
}

// CloudConsentGrantsResponse is the payload for GET /api/cloud/consent/grants.
type CloudConsentGrantsResponse struct {
	Receipts  []CloudConsentReceiptView `json:"receipts"`
	Grantable []CloudGrantable          `json:"grantable"`
}

// handleCloudConsentGrants serves GET /api/cloud/consent/grants: every stored
// receipt (read straight from the store — no subprocess) plus, through the
// injected CloudGrantableProbe, which purposes may be granted standing right
// now and why the others cannot.
func (s *Server) handleCloudConsentGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	rows, err := store.New(s.db()).ListCloudConsentReceipts(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	receipts := make([]CloudConsentReceiptView, 0, len(rows))
	for _, rr := range rows {
		mode := string(rr.GrantMode)
		if mode == "" {
			mode = string(store.CloudGrantPerUpload)
		}
		view := CloudConsentReceiptView{
			ID:        rr.ID,
			Purpose:   rr.Purpose,
			Mode:      mode,
			CreatedAt: cloudRFC3339(rr.CreatedAt),
			Live:      rr.InvalidatedAt == nil,
		}
		if rr.ReviewAt != nil {
			view.ReviewAt = cloudRFC3339(*rr.ReviewAt)
		}
		if rr.InvalidatedAt != nil {
			iv := cloudRFC3339(*rr.InvalidatedAt)
			view.InvalidatedAt = &iv
		}
		receipts = append(receipts, view)
	}
	var grantable []CloudGrantable
	if c.grantable != nil {
		grantable = c.grantable()
	}
	if grantable == nil {
		grantable = []CloudGrantable{}
	}
	writeJSON(w, CloudConsentGrantsResponse{Receipts: receipts, Grantable: grantable})
}

// CloudPurposeRequest is the shared body of POST /api/cloud/consent/grant and
// POST /api/cloud/consent/revoke.
type CloudPurposeRequest struct {
	Purpose string `json:"purpose"`
}

// CloudActionResponse is the payload for every plain run-and-report action
// route (grant, revoke, delete-account) — no extra fields beyond the
// subprocess's own outcome.
type CloudActionResponse struct {
	OK        bool   `json:"ok"`
	Output    string `json:"output"`
	ExitError string `json:"exit_error"`
}

// handleCloudConsentGrant serves POST /api/cloud/consent/grant: runs `observer
// cloud consent grant --purpose <p> --yes`. Refused (409) while a sync runs
// (the outbox race a standing grant's supersede logic must not straddle).
func (s *Server) handleCloudConsentGrant(w http.ResponseWriter, r *http.Request) {
	s.handleCloudPurposeAction(w, r, "grant", func(p string) []string {
		return []string{"grant", "--purpose", p, "--yes"}
	})
}

// handleCloudConsentRevoke serves POST /api/cloud/consent/revoke: runs
// `observer cloud consent revoke --purpose <p>` (no --yes — the CLI's revoke
// has no confirmation flag). Refused (409) while a sync runs.
func (s *Server) handleCloudConsentRevoke(w http.ResponseWriter, r *http.Request) {
	s.handleCloudPurposeAction(w, r, "revoke", func(p string) []string {
		return []string{"revoke", "--purpose", p}
	})
}

// handleCloudPurposeAction is the shared body of grant/revoke: validate,
// refuse while a sync runs, run `observer cloud consent <argv(purpose)>`.
func (s *Server) handleCloudPurposeAction(w http.ResponseWriter, r *http.Request, verbLabel string, argv func(purpose string) []string) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	var req CloudPurposeRequest
	if err := cloudDecodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	req.Purpose = strings.TrimSpace(req.Purpose)
	if req.Purpose == "" {
		http.Error(w, "purpose is required", http.StatusBadRequest)
		return
	}
	if c.syncRunning() {
		http.Error(w, fmt.Sprintf("a sync is running — wait for it to finish before you %s this purpose", verbLabel), http.StatusConflict)
		return
	}
	output, ok2, exitErr := c.runOnce(r.Context(), "consent", argv(req.Purpose), cloudGrantRevokeTimeout)
	writeJSON(w, CloudActionResponse{OK: ok2, Output: output, ExitError: exitErr})
}

// --- delete account -----------------------------------------------------------

// CloudDeleteAccountRequest is the body of POST /api/cloud/delete-account.
type CloudDeleteAccountRequest struct {
	LocalOnly bool `json:"local_only"`
}

// handleCloudDeleteAccount serves POST /api/cloud/delete-account: runs
// `observer cloud delete-account --yes` (plus `--local-only` when requested).
// Refused (409) while a sign-in or sync is running. Invalidates the
// cmd/observer-side sign-in probe cache afterward exactly the way login/logout
// already do — cloudaccount_wire.go's run() drops the cache after every verb,
// this one included.
func (s *Server) handleCloudDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	if c.loginRunning() {
		http.Error(w, "a sign-in is running — wait for it to finish (or time out) before deleting the account", http.StatusConflict)
		return
	}
	if c.syncRunning() {
		http.Error(w, "a sync is running — wait for it to finish before deleting the account", http.StatusConflict)
		return
	}
	var req CloudDeleteAccountRequest
	if err := cloudDecodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	args := []string{"--yes"}
	if req.LocalOnly {
		args = append(args, "--local-only")
	}
	output, ok2, exitErr := c.runOnce(r.Context(), "delete-account", args, cloudDeleteAccountTimeout)
	writeJSON(w, CloudActionResponse{OK: ok2, Output: output, ExitError: exitErr})
}
