package oidchttp

import (
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"net/url"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
)

// maxTokenBody bounds the token request body.
const maxTokenBody = 16 << 10

// DefaultSignInPath is where an authorize request without a session is
// sent: the portal's WorkOS sign-in start, which takes return_to.
const DefaultSignInPath = "/portal/auth/workos/start"

// ReauthQueryParam is the sign-in start parameter (value "1") that asks for a
// fresh primary authentication: the start sends the identity provider
// max_age=0 and prompt=login instead of letting it reuse its own session.
const ReauthQueryParam = "reauth"

// DefaultSecondFactorPath is the portal's second-factor page (C2): an
// authorize whose session must first use its passkey is sent there with
// return_to set to the request, and the page resumes it.
const DefaultSecondFactorPath = "/portal/second-factor"

// Options configures a Handler.
type Options struct {
	// SignInPath is the same-origin sign-in start; empty means
	// DefaultSignInPath.
	SignInPath string
	// SecondFactorPath is the same-origin second-factor page; empty means
	// DefaultSecondFactorPath.
	SecondFactorPath string
	// Logger receives refusal rule ids (never codes, verifiers or tokens);
	// nil means slog.Default().
	Logger *slog.Logger
}

// Handler serves the issuer's four routes.
type Handler struct {
	issuer           *oidcissuer.Issuer
	signInPath       string
	secondFactorPath string
	log              *slog.Logger
}

// New returns a Handler over issuer.
func New(issuer *oidcissuer.Issuer, o Options) (*Handler, error) {
	if issuer == nil {
		return nil, errors.New("oidchttp.New: nil issuer")
	}
	h := &Handler{issuer: issuer, signInPath: o.SignInPath, secondFactorPath: o.SecondFactorPath, log: o.Logger}
	if h.signInPath == "" {
		h.signInPath = DefaultSignInPath
	}
	if h.secondFactorPath == "" {
		h.secondFactorPath = DefaultSecondFactorPath
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	return h, nil
}

// Issuer returns the issuer identifier this handler serves.
func (h *Handler) Issuer() string { return h.issuer.Identifier() }

// Discovery serves the OpenID Provider Metadata.
func (h *Handler) Discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, h.issuer.Discovery())
}

// JWKS serves the published keys.
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	doc, err := h.issuer.JWKS(r.Context())
	if err != nil {
		h.log.Error("oidchttp: JWKS read failed", "err", err)
		writeOAuthErr(w, &oidcissuer.Error{Code: oidcissuer.ErrCodeTemporarilyUnavailable, Description: "keys are unavailable", Status: http.StatusServiceUnavailable})
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, doc)
}

// Authorize serves GET /oauth2/authorize for the browser's portal session
// (sess.AccountID "" when it holds none).
//
// A sign-in the issuer asks for is sent to the sign-in start with return_to
// set to this request; a FRESH sign-in (prompt=login, max_age exceeded, or an
// unknown authentication time) additionally carries ReauthQueryParam=1, which
// tells the start to make the identity provider authenticate the person again
// rather than reuse its own session, and return_to carries the issuer's
// ReauthParam marker so the resumed request is satisfied by that sign-in.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request, sess oidcissuer.Session) {
	w.Header().Set("Cache-Control", "no-store")
	res := h.issuer.Authorize(r.Context(), oidcissuer.ParseAuthorizeQuery(r.URL.Query()), sess)
	switch res.Outcome {
	case oidcissuer.OutcomeLogin:
		resume := r.URL.RawQuery
		if res.FreshSignIn {
			resume = oidcissuer.ResumeQuery(r.URL.Query(), res.ReauthAt)
		}
		target := h.signInPath + "?return_to=" + url.QueryEscape(oidcissuer.LoginReturnPath(resume))
		if res.FreshSignIn {
			target += "&" + ReauthQueryParam + "=1"
		}
		http.Redirect(w, r, target, http.StatusFound)
	case oidcissuer.OutcomeSecondFactor:
		http.Redirect(w, r, h.secondFactorPath+"?return_to="+url.QueryEscape(oidcissuer.LoginReturnPath(r.URL.RawQuery)), http.StatusFound)
	case oidcissuer.OutcomeRedirect:
		if res.Err != nil {
			h.log.Info("oidchttp: authorize refused", "rule", res.Err.RuleID, "code", res.Err.Code)
		}
		http.Redirect(w, r, res.Location, http.StatusFound)
	default:
		e := res.Err
		if e == nil {
			e = &oidcissuer.Error{Code: oidcissuer.ErrCodeServerError, Description: "sign-in failed", Status: http.StatusInternalServerError, RuleID: "no-outcome"}
		}
		h.log.Info("oidchttp: authorize refused in place", "rule", e.RuleID, "code", e.Code)
		writeOAuthErr(w, e)
	}
}

// Token serves POST /oauth2/token.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if r.Header.Get("Authorization") != "" {
		writeOAuthErr(w, &oidcissuer.Error{Code: oidcissuer.ErrCodeInvalidClient, Description: "this is a public client; send no credentials", Status: http.StatusUnauthorized})
		return
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		writeOAuthErr(w, &oidcissuer.Error{Code: oidcissuer.ErrCodeInvalidRequest, Description: "send the parameters as a form body", Status: http.StatusBadRequest})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenBody)
	if err := r.ParseForm(); err != nil {
		writeOAuthErr(w, &oidcissuer.Error{Code: oidcissuer.ErrCodeInvalidRequest, Description: "unreadable form body", Status: http.StatusBadRequest})
		return
	}
	resp, err := h.issuer.Token(r.Context(), oidcissuer.ParseTokenForm(r.PostForm))
	if err != nil {
		var e *oidcissuer.Error
		if !errors.As(err, &e) {
			e = &oidcissuer.Error{Code: oidcissuer.ErrCodeServerError, Description: "sign-in failed", Status: http.StatusInternalServerError, RuleID: "untyped"}
		}
		h.log.Info("oidchttp: token refused", "rule", e.RuleID, "code", e.Code)
		writeOAuthErr(w, e)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

type oauthErrBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func writeOAuthErr(w http.ResponseWriter, e *oidcissuer.Error) {
	status := e.Status
	if status < 400 || status > 599 {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, oauthErrBody{Error: e.Code, Description: e.Description})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
