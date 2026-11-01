package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

// WorkOS token-endpoint outcomes (T-964). The authenticate endpoint answers
// every failure with a 4xx, but a 4xx is not always the user's fault: a client
// secret from another WorkOS environment answers 400 invalid_client, and the
// first live sign-in on cloud.superbased.app (2026-10-23) told the user their
// authorization code "was rejected" when the server's own key was wrong. The
// classification below separates the three cases a caller acts on differently.

// workOSOutcome is what a token-endpoint answer means for the caller.
type workOSOutcome int

const (
	// workOSOutcomeOK is a 200 the caller decodes.
	workOSOutcomeOK workOSOutcome = iota
	// workOSOutcomeCodeRejected is a client-caused refusal (a bad, expired or
	// already-redeemed code): the user restarts sign-in.
	workOSOutcomeCodeRejected
	// workOSOutcomeMisconfigured is a SERVER misconfiguration (the client id and
	// key do not belong together, or the key is not accepted at all): no user
	// action can fix it, so it is logged as an error and answered 5xx.
	workOSOutcomeMisconfigured
	// workOSOutcomeTransient is a rate limit or a provider fault: try again.
	workOSOutcomeTransient
)

// String names the outcome for logs and the health report.
func (o workOSOutcome) String() string {
	switch o {
	case workOSOutcomeOK:
		return "ok"
	case workOSOutcomeCodeRejected:
		return "code_rejected"
	case workOSOutcomeMisconfigured:
		return "misconfigured"
	default:
		return "transient"
	}
}

// workOSClassifyRule is one row of the ordered classification table: the first
// row whose predicate matches decides the outcome.
type workOSClassifyRule struct {
	name    string
	match   func(status int, code string) bool
	outcome workOSOutcome
}

// workOSMisconfiguredCodes are the OAuth error codes that blame the CLIENT
// credentials (this server's configuration), never the authorization code.
var workOSMisconfiguredCodes = map[string]bool{
	"invalid_client":      true,
	"unauthorized_client": true,
}

// workOSClassifyRules is walked top-down. 429 is WorkOS's slow_down signal and
// must never read as a rejected code (the user would be told to restart sign-in
// when the right action is to wait); a credential error code or a 401 is this
// server's fault; every other 4xx is the code's; anything else is transient.
var workOSClassifyRules = []workOSClassifyRule{
	{"ok", func(st int, _ string) bool { return st == http.StatusOK }, workOSOutcomeOK},
	{"rate_limited", func(st int, _ string) bool { return st == http.StatusTooManyRequests }, workOSOutcomeTransient},
	{"credential_error_code", func(_ int, c string) bool { return workOSMisconfiguredCodes[c] }, workOSOutcomeMisconfigured},
	{"unauthorized_status", func(st int, _ string) bool { return st == http.StatusUnauthorized }, workOSOutcomeMisconfigured},
	{"client_error", func(st int, _ string) bool { return st >= 400 && st < 500 }, workOSOutcomeCodeRejected},
}

// classifyWorkOSStatus maps a token-endpoint status and its OAuth error code to
// an outcome through workOSClassifyRules.
func classifyWorkOSStatus(status int, code string) workOSOutcome {
	for _, r := range workOSClassifyRules {
		if r.match(status, code) {
			return r.outcome
		}
	}
	return workOSOutcomeTransient
}

// workOSErrorFields is the provider's error body. The OAuth shape is
// {"error","error_description"}; other WorkOS endpoints answer
// {"code","message"}, so both are read.
type workOSErrorFields struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	Code             string `json:"code"`
	Message          string `json:"message"`
}

// maxWorkOSReasonLen bounds a provider reason, in runes, before it reaches a
// log line.
const maxWorkOSReasonLen = 200

// workOSRedacted replaces a value the provider echoed back.
const workOSRedacted = "<redacted>"

// workOSEchoPatterns are the shapes in a provider reason that can carry a value
// from the request rather than WorkOS's own wording. WorkOS's invalid_grant
// description repeats the authorization code verbatim ("The code '01DUMMY...'
// has expired or is invalid."), so a quoted token, a long upper-case or digit
// run, a WorkOS-style ULID (26 Crockford base32 characters starting 01), or
// any other id-like token of 24 or more characters is redacted. Walked in order.
var workOSEchoPatterns = []*regexp.Regexp{
	regexp.MustCompile(`'[^']*'`),
	regexp.MustCompile(`"[^"]*"`),
	regexp.MustCompile(`(?i)\b01[0-9A-HJKMNP-TV-Z]{24}\b`),
	regexp.MustCompile(`\b[0-9A-Z]{20,}\b`),
	regexp.MustCompile(`\b[A-Za-z0-9_-]{24,}\b`),
}

// parseWorkOSError extracts the provider's error code and description from a
// non-200 body. Both are sanitized once, here (sanitizeWorkOSReason): control
// characters dropped, any echoed request value redacted, the length bounded,
// so no caller can log the user's authorization code or split a log line with
// what a remote returned.
func parseWorkOSError(body []byte) (code, description string) {
	var f workOSErrorFields
	if json.Unmarshal(body, &f) != nil {
		return "", ""
	}
	code = f.Error
	if code == "" {
		code = f.Code
	}
	description = f.ErrorDescription
	if description == "" {
		description = f.Message
	}
	return sanitizeWorkOSReason(code), sanitizeWorkOSReason(description)
}

// sanitizeWorkOSReason drops control characters, redacts every echoed request
// value (workOSEchoPatterns) and bounds the length to maxWorkOSReasonLen runes.
// Redaction runs on the whole text before the cut, so a value straddling the
// bound can never survive half-redacted.
func sanitizeWorkOSReason(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	for _, re := range workOSEchoPatterns {
		s = re.ReplaceAllString(s, workOSRedacted)
	}
	if r := []rune(s); len(r) > maxWorkOSReasonLen {
		s = string(r[:maxWorkOSReasonLen])
	}
	return s
}

// errWorkOSMisconfigured marks a token exchange WorkOS refused because of this
// server's own client credentials (wrong environment's key, or a key/client id
// pair that does not belong together). It is answered 503, never as the user's
// fault.
var errWorkOSMisconfigured = errors.New("cloudserver/api: workos sign-in is misconfigured")

// workOSTokenError is a classified non-200 token-endpoint answer. It unwraps to
// errWorkOSRejected or errWorkOSMisconfigured so callers keep using errors.Is.
type workOSTokenError struct {
	Outcome     workOSOutcome
	Status      int
	Code        string
	Description string
}

// Error renders the status and the provider's own error code, never a secret.
func (e *workOSTokenError) Error() string {
	return fmt.Sprintf("cloudserver/api: workos token endpoint returned %d (%s, %s)", e.Status, e.Code, e.Outcome)
}

// Unwrap maps the outcome onto the sentinel callers test with errors.Is.
func (e *workOSTokenError) Unwrap() error {
	switch e.Outcome {
	case workOSOutcomeCodeRejected:
		return errWorkOSRejected
	case workOSOutcomeMisconfigured:
		return errWorkOSMisconfigured
	default:
		return nil
	}
}

// postWorkOSToken POSTs one authorization_code grant to the token endpoint with
// this server's client credentials and returns the status and the bounded body.
// It is the one place the client secret is put on the wire.
func (s *Server) postWorkOSToken(ctx context.Context, code, verifier string) (int, []byte, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {s.workOSClientID},
		"client_secret": {s.workOSAPIKey},
		"code":          {code},
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.workOSTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, fmt.Errorf("cloudserver/api.postWorkOSToken: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.workOSHTTP.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("cloudserver/api.postWorkOSToken: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// --- startup self-check ------------------------------------------------------

// WorkOS sign-in self-check states, as GET /healthz reports them under
// "workos_signin". The check is REPORT-ONLY: it never flips the health status
// and never stops the server, so a WorkOS outage at boot cannot take the device
// API down with it. A misconfiguration is an ERROR log line and a health field
// an operator (or a probe script) can read.
const (
	// WorkOSCheckOff: the browser sign-in leg is not active, nothing to check.
	WorkOSCheckOff = "off"
	// WorkOSCheckPending: the leg is active and the check has not finished.
	WorkOSCheckPending = "pending"
	// WorkOSCheckOK: WorkOS accepted the client id and key pair (it refused
	// only the dummy code, with invalid_grant).
	WorkOSCheckOK = "ok"
	// WorkOSCheckMisconfigured: WorkOS refused the client credentials.
	WorkOSCheckMisconfigured = "misconfigured"
	// WorkOSCheckUnverified: the check could not reach a verdict (network
	// error, rate limit, an unexpected answer); sign-in may still work.
	WorkOSCheckUnverified = "unverified"
)

// workOSSelfCheckCode is the obviously fake authorization code the self-check
// redeems. WorkOS answers invalid_grant for it when the client credentials are
// good, and invalid_client when they are not, without signing anybody in.
const workOSSelfCheckCode = "sbci-startup-self-check-not-a-real-code"

// workOSSelfCheckTimeout bounds the one startup request.
const workOSSelfCheckTimeout = 15 * time.Second

// workOSCheckState holds the last self-check verdict (one owner: the Server).
type workOSCheckState struct {
	v atomic.Value // string
}

// load returns the stored verdict, or "" when none was stored yet.
func (c *workOSCheckState) load() string {
	if s, ok := c.v.Load().(string); ok {
		return s
	}
	return ""
}

// WorkOSSignInCheck returns the current self-check verdict (one of the
// WorkOSCheck* constants).
func (s *Server) WorkOSSignInCheck() string {
	if !s.workOSBrowserReady() {
		return WorkOSCheckOff
	}
	if v := s.workOSCheck.load(); v != "" {
		return v
	}
	return WorkOSCheckPending
}

// RunWorkOSSelfCheck verifies, once, that the configured WorkOS client id and
// API key belong together: it redeems an obviously fake code and reads WorkOS's
// refusal. invalid_grant means the pair is accepted (INFO); invalid_client (or
// a 401) means the key is from another environment or does not match the
// client id (a loud ERROR naming WorkOS's own error code and description,
// never the key); anything else is a WARN. It is a no-op when the browser
// sign-in leg is not active, never returns an error, and is meant to run in a
// goroutine at startup. It returns the verdict it stored.
func (s *Server) RunWorkOSSelfCheck(ctx context.Context) string {
	if !s.workOSBrowserReady() {
		return WorkOSCheckOff
	}
	ctx, cancel := context.WithTimeout(ctx, workOSSelfCheckTimeout)
	defer cancel()
	verdict := s.workOSSelfCheckVerdict(ctx)
	s.workOSCheck.v.Store(verdict)
	return verdict
}

// workOSSelfCheckVerdict performs the request and logs the verdict.
func (s *Server) workOSSelfCheckVerdict(ctx context.Context) string {
	status, body, err := s.postWorkOSToken(ctx, workOSSelfCheckCode, "")
	if err != nil {
		s.log.Warn("cloudserver/api: WorkOS sign-in self-check could not reach WorkOS; sign-in is unverified",
			"err", err)
		return WorkOSCheckUnverified
	}
	code, desc := parseWorkOSError(body)
	switch classifyWorkOSStatus(status, code) {
	case workOSOutcomeMisconfigured:
		s.log.Error("cloudserver/api: WorkOS sign-in is MISCONFIGURED: WorkOS refused this server's client id and API key pair, so every browser sign-in will fail. Check that WORKOS_API_KEY is from the same WorkOS environment as WORKOS_CLIENT_ID, then re-create the API container.",
			"workos_status", status, "workos_error", code, "workos_error_description", desc,
			"workos_client_id", s.workOSClientID)
		return WorkOSCheckMisconfigured
	case workOSOutcomeCodeRejected:
		if code == "invalid_grant" {
			s.log.Info("cloudserver/api: WorkOS sign-in self-check passed (client id and API key accepted)",
				"workos_client_id", s.workOSClientID)
			return WorkOSCheckOK
		}
		s.log.Warn("cloudserver/api: WorkOS sign-in self-check got an unexpected refusal; sign-in is unverified",
			"workos_status", status, "workos_error", code, "workos_error_description", desc)
		return WorkOSCheckUnverified
	default:
		s.log.Warn("cloudserver/api: WorkOS sign-in self-check got no verdict; sign-in is unverified",
			"workos_status", status, "workos_error", code)
		return WorkOSCheckUnverified
	}
}
