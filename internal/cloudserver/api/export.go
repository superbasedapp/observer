package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// export.go is the W6d account-export API surface (divergence-remediation plan
// §3 W6d; closes D11; Doc B §5.2):
//
//	POST /v1/export                          — device PoP; assemble artifact
//	GET  /v1/exports/{id}                     — device PoP; download bytes
//	POST /portal/api/exports                  — portal; step-up-reauth; assemble
//	GET  /portal/api/exports                  — portal; list live artifacts
//	GET  /portal/api/exports/{id}/download    — portal; download bytes
//
// Export is a LIVE-ACCOUNT operation (plan §3 W6d "Export/deletion ordering"):
// the portal deletion flow offers it FIRST ("download your data first"), and
// once deletion runs there is no post-`done` export. Assembly is the sensitive
// disclosure, so the portal ASSEMBLY path requires the same reauth/step-up the
// deletion path does (Doc B §3.2 lists export among the step-up actions); the
// device assembly path is guarded by device proof-of-possession (the same strong
// factor the device deletion path relies on, which has no browser step-up).

// exportResponse is the metadata returned by an assembly (never the bytes). The
// client then GETs the download path with this id.
type exportResponse struct {
	ExportID  string    `json:"export_id"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// handleExportRequest is the DEVICE assembly path (PoP-authenticated).
func (s *Server) handleExportRequest(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	s.assembleExport(w, r, p.AccountID)
}

// handleExportDownload is the DEVICE download path (PoP-authenticated).
func (s *Server) handleExportDownload(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	s.downloadExport(w, r, p.AccountID, r.PathValue("id"))
}

// portalExportRequest carries the reauth for the portal assembly path (mirrors
// portalDeletionRequest): a dev-auth broker credential OR a WorkOS step-up id.
type portalExportRequest struct {
	BrokerToken           string `json:"broker_token"`
	StepUpAuthorizationID string `json:"step_up_authorization_id"`
}

// handlePortalExportRequest is the PORTAL assembly path (session cookie + CSRF)
// with the export reauth/step-up mandated by Doc B §3.2 — the same shape as the
// portal deletion path.
func (s *Server) handlePortalExportRequest(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	var req portalExportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	if !s.portalDevAuth() {
		// WorkOS mode: dark until the browser leg is enabled (R7); with it live,
		// export requires an action=export step-up authorization consumed with the
		// assembly. CSRF is still enforced by the middleware — an ADDITIONAL factor.
		if !s.portalWorkOSEnabled {
			writeErr(w, http.StatusNotImplemented, "provider_not_configured",
				"Reauthentication for export is not available yet (the WorkOS step-up leg is not enabled on this deployment).")
			return
		}
		if req.StepUpAuthorizationID == "" {
			writeErr(w, http.StatusForbidden, "step_up_required",
				"re-authenticate at /portal/auth/workos/start?purpose=step_up&action=export before requesting an export")
			return
		}
		meta, err := s.store.CreateExportArtifactWithStepUp(r.Context(), p.AccountID, p.SessionID, req.StepUpAuthorizationID, s.now())
		if errors.Is(err, store.ErrStepUpInvalid) {
			s.audit(r.Context(), p.AccountID, "portal_export_step_up_invalid")
			writeErr(w, http.StatusForbidden, "step_up_invalid",
				"that re-authentication is expired, already used, or was not issued for this session")
			return
		}
		if err != nil {
			s.log.Error("cloudserver/api: export with step-up", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal", "could not assemble export")
			return
		}
		s.audit(r.Context(), p.AccountID, "export_assembled")
		writeJSON(w, http.StatusCreated, exportResponse{
			ExportID: meta.ID, SizeBytes: meta.SizeBytes, CreatedAt: meta.CreatedAt, ExpiresAt: meta.ExpiresAt,
		})
		return
	}
	// Dev-auth mode: reauth = re-present the broker credential; it must resolve to
	// THIS account (same rule as the portal deletion path).
	id, err := s.verifier.Verify(r.Context(), req.BrokerToken)
	if err != nil {
		s.audit(r.Context(), p.AccountID, "portal_export_reauth_failed")
		writeErr(w, http.StatusUnauthorized, "reauth_required", "re-enter your credential to request an export")
		return
	}
	reauthAccount, err := s.store.AccountForIdentity(r.Context(), id.Provider, id.Subject)
	if err != nil || reauthAccount != p.AccountID {
		s.audit(r.Context(), p.AccountID, "portal_export_reauth_account_mismatch")
		writeErr(w, http.StatusForbidden, "reauth_mismatch", "credential does not match the signed-in account")
		return
	}
	s.assembleExport(w, r, p.AccountID)
}

// handlePortalExportList lists the account's live export artifacts (portal
// session auth; a GET, so CSRF-exempt).
func (s *Server) handlePortalExportList(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	metas, err := s.store.ListExportArtifacts(r.Context(), p.AccountID, s.now())
	if err != nil {
		s.log.Error("cloudserver/api: list exports", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not list exports")
		return
	}
	out := make([]exportResponse, 0, len(metas))
	for _, m := range metas {
		out = append(out, exportResponse{ExportID: m.ID, SizeBytes: m.SizeBytes, CreatedAt: m.CreatedAt, ExpiresAt: m.ExpiresAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"exports": out})
}

// handlePortalExportDownload is the PORTAL download path (session auth; the
// artifact was already gated by the assembly reauth, and the read is RLS-scoped
// to the account).
func (s *Server) handlePortalExportDownload(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	s.downloadExport(w, r, p.AccountID, r.PathValue("id"))
}

// assembleExport builds + encrypts + stores the export and returns its metadata.
func (s *Server) assembleExport(w http.ResponseWriter, r *http.Request, accountID string) {
	meta, err := s.store.CreateExportArtifact(r.Context(), accountID, s.now())
	if err != nil {
		s.log.Error("cloudserver/api: create export", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not assemble export")
		return
	}
	// Content-free audit: names the action, never the exported data.
	s.audit(r.Context(), accountID, "export_assembled")
	writeJSON(w, http.StatusCreated, exportResponse{
		ExportID:  meta.ID,
		SizeBytes: meta.SizeBytes,
		CreatedAt: meta.CreatedAt,
		ExpiresAt: meta.ExpiresAt,
	})
}

// downloadExport decrypts and streams one artifact's JSON as an attachment.
func (s *Server) downloadExport(w http.ResponseWriter, r *http.Request, accountID, exportID string) {
	if exportID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "missing export id")
		return
	}
	body, meta, err := s.store.GetExportArtifact(r.Context(), accountID, exportID, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "export_not_found", "no such export")
		return
	case errors.Is(err, store.ErrExportExpired):
		writeErr(w, http.StatusGone, "export_expired", "this export has expired; assemble a new one")
		return
	case err != nil:
		s.log.Error("cloudserver/api: download export", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read export")
		return
	}
	s.audit(r.Context(), accountID, "export_downloaded")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="superbased-export-%s.json"`, meta.ID))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
