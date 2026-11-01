package api

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
)

// TestClassifyWorkOSStatus walks workOSClassifyRules one row per case (T-964).
// The live defect: a test-environment key with the production client id
// answered 400 invalid_client and the user was told their code was rejected.
func TestClassifyWorkOSStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
		code   string
		want   workOSOutcome
	}{
		{"200 is ok", 200, "", workOSOutcomeOK},
		{"429 slow_down is transient, never a rejected code", 429, "slow_down", workOSOutcomeTransient},
		{"400 invalid_client is our misconfiguration", 400, "invalid_client", workOSOutcomeMisconfigured},
		{"400 unauthorized_client is our misconfiguration", 400, "unauthorized_client", workOSOutcomeMisconfigured},
		{"401 with no code is our misconfiguration", 401, "", workOSOutcomeMisconfigured},
		{"400 invalid_grant is the code's fault", 400, "invalid_grant", workOSOutcomeCodeRejected},
		{"400 with no body is the code's fault", 400, "", workOSOutcomeCodeRejected},
		{"403 is a client error", 403, "", workOSOutcomeCodeRejected},
		{"500 is transient", 500, "", workOSOutcomeTransient},
		{"502 is transient", 502, "", workOSOutcomeTransient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyWorkOSStatus(tc.status, tc.code); got != tc.want {
				t.Fatalf("classifyWorkOSStatus(%d, %q) = %s, want %s", tc.status, tc.code, got, tc.want)
			}
		})
	}
}

// TestParseWorkOSError reads both WorkOS error shapes and sanitizes them.
func TestParseWorkOSError(t *testing.T) {
	cases := []struct {
		name, body, wantCode, wantDesc string
	}{
		{
			"oauth shape", `{"error":"invalid_client","error_description":"You may be using a client secret from a different environment."}`,
			"invalid_client", "You may be using a client secret from a different environment.",
		},
		{"code/message shape", `{"code":"invalid_credentials","message":"bad key"}`, "invalid_credentials", "bad key"},
		{"not json", `<html>oops</html>`, "", ""},
		{"control characters dropped", "{\"error\":\"invalid_grant\",\"error_description\":\"line1\\nline2\"}", "invalid_grant", "line1line2"},
		{"bounded in runes", `{"error":"x","error_description":"` + strings.Repeat("ab ", 400) + `"}`, "x", strings.Repeat("ab ", 400)[:maxWorkOSReasonLen]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, desc := parseWorkOSError([]byte(tc.body))
			if code != tc.wantCode || desc != tc.wantDesc {
				t.Fatalf("parseWorkOSError = (%q, %q), want (%q, %q)", code, desc, tc.wantCode, tc.wantDesc)
			}
		})
	}
}

// TestSanitizeWorkOSReasonRedactsEchoedValues pins that a provider reason can
// never carry a value from the request into a log line: WorkOS's invalid_grant
// description repeats the authorization code verbatim (live example below).
func TestSanitizeWorkOSReasonRedactsEchoedValues(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{
			"live invalid_grant echo",
			"The code '01DUMMYCODE000000000000000' has expired or is invalid.",
			"The code <redacted> has expired or is invalid.",
		},
		{"double-quoted value", `Invalid code "abc123" supplied.`, "Invalid code <redacted> supplied."},
		{"bare WorkOS ULID", "Code 01HZX9K2M3N4P5Q6R7S8T9V0W1 is invalid.", "Code <redacted> is invalid."},
		{"bare lower-case ULID", "Code 01hzx9k2m3n4p5q6r7s8t9v0w1 is invalid.", "Code <redacted> is invalid."},
		{"long upper-case or digit run", "Session ABCDEF0123456789ABCDEF expired.", "Session <redacted> expired."},
		{"long id-like token", "Token sess_0f3c9a7b2e1d4c6a8b0f expired.", "Token <redacted> expired."},
		{"several echoes", `Code 'x1' and "y2" and 01HZX9K2M3N4P5Q6R7S8T9V0W1.`, "Code <redacted> and <redacted> and <redacted>."},
		{"plain provider wording kept", "You may be using a client secret from a different environment.", "You may be using a client secret from a different environment."},
		{"short numbers kept", "Status 401 from API v2.", "Status 401 from API v2."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeWorkOSReason(tc.in); got != tc.want {
				t.Fatalf("sanitizeWorkOSReason(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	if n := len([]rune(sanitizeWorkOSReason(strings.Repeat("é ", 300)))); n != maxWorkOSReasonLen {
		t.Fatalf("multi-byte reason bounded to %d runes, want %d", n, maxWorkOSReasonLen)
	}
	// Through the parser too: the code value never reaches the description.
	_, desc := parseWorkOSError([]byte(`{"error":"invalid_grant","error_description":"The code '01DUMMYCODE000000000000000' has expired or is invalid."}`))
	if desc != "The code <redacted> has expired or is invalid." {
		t.Fatalf("parsed description = %q", desc)
	}
}

// selfCheckVerifier is a non-dev verifier so the server runs in WorkOS mode.
type selfCheckVerifier struct{}

func (selfCheckVerifier) Provider() string { return "workos" }
func (selfCheckVerifier) Verify(context.Context, string) (identity.Identity, error) {
	return identity.Identity{}, identity.ErrInvalidToken
}

// newSelfCheckServer builds a Server whose token endpoint is handler and whose
// logs land in buf. No database: the self-check never touches the store.
func newSelfCheckServer(t *testing.T, enabled bool, handler http.HandlerFunc, buf *bytes.Buffer) *Server {
	t.Helper()
	tokenURL := "http://127.0.0.1:1/unreachable"
	if handler != nil {
		fake := httptest.NewServer(handler)
		t.Cleanup(fake.Close)
		tokenURL = fake.URL + "/token"
	}
	return New(Options{
		Verifier:            selfCheckVerifier{},
		Logger:              slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		RateLimit:           &RateLimitConfig{},
		PortalWorkOSEnabled: enabled,
		WorkOSClientID:      "client_prod",
		WorkOSAPIKey:        "sk_test_wrong_environment_secret",
		WorkOSTokenURL:      tokenURL,
	})
}

// TestRunWorkOSSelfCheck pins the startup self-check verdicts (T-964): it
// redeems an obviously fake code, reads WorkOS's refusal, logs the verdict
// without the key or the code, and reports it on /healthz without failing it.
func TestRunWorkOSSelfCheck(t *testing.T) {
	answer := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil || r.PostForm.Get("client_id") != "client_prod" ||
				r.PostForm.Get("client_secret") == "" || r.PostForm.Get("code") != workOSSelfCheckCode ||
				r.PostForm.Get("grant_type") != "authorization_code" {
				w.WriteHeader(http.StatusTeapot)
				return
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}
	}
	cases := []struct {
		name      string
		enabled   bool
		handler   http.HandlerFunc
		want      string
		wantLevel string
		wantInLog string
	}{
		{
			"pair accepted", true, answer(400, `{"error":"invalid_grant","error_description":"The code is invalid."}`),
			WorkOSCheckOK, "level=INFO", "self-check passed",
		},
		{
			"key from another environment", true,
			answer(400, `{"error":"invalid_client","error_description":"You may be using a client secret from a different environment."}`),
			WorkOSCheckMisconfigured, "level=ERROR", "different environment",
		},
		{"401", true, answer(401, `{"message":"Unauthorized"}`), WorkOSCheckMisconfigured, "level=ERROR", "MISCONFIGURED"},
		{"rate limited", true, answer(429, `{"error":"slow_down"}`), WorkOSCheckUnverified, "level=WARN", "no verdict"},
		{"provider fault", true, answer(503, ``), WorkOSCheckUnverified, "level=WARN", "no verdict"},
		{"unexpected refusal", true, answer(400, `{"error":"invalid_request"}`), WorkOSCheckUnverified, "level=WARN", "unexpected refusal"},
		{"network error", true, nil, WorkOSCheckUnverified, "level=WARN", "could not reach WorkOS"},
		{"leg not active", false, answer(400, `{"error":"invalid_grant"}`), WorkOSCheckOff, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			s := newSelfCheckServer(t, tc.enabled, tc.handler, &buf)
			if tc.enabled {
				if got := s.WorkOSSignInCheck(); got != WorkOSCheckPending {
					t.Fatalf("before the check: %q, want %q", got, WorkOSCheckPending)
				}
			}
			if got := s.RunWorkOSSelfCheck(context.Background()); got != tc.want {
				t.Fatalf("RunWorkOSSelfCheck = %q, want %q\nlog: %s", got, tc.want, buf.String())
			}
			if got := s.WorkOSSignInCheck(); got != tc.want {
				t.Fatalf("WorkOSSignInCheck = %q, want %q", got, tc.want)
			}
			logs := buf.String()
			if tc.wantLevel != "" && !strings.Contains(logs, tc.wantLevel) {
				t.Errorf("log lacks %s:\n%s", tc.wantLevel, logs)
			}
			if tc.wantInLog != "" && !strings.Contains(logs, tc.wantInLog) {
				t.Errorf("log lacks %q:\n%s", tc.wantInLog, logs)
			}
			if !tc.enabled && logs != "" {
				t.Errorf("an inactive leg must log nothing and make no request:\n%s", logs)
			}
			if strings.Contains(logs, "sk_test_wrong_environment_secret") {
				t.Fatalf("the API key leaked into the log:\n%s", logs)
			}
		})
	}
}

// TestWorkOSTokenErrorUnwrap pins the sentinel mapping the callback branches on.
func TestWorkOSTokenErrorUnwrap(t *testing.T) {
	cases := []struct {
		outcome       workOSOutcome
		rejected      bool
		misconfigured bool
	}{
		{workOSOutcomeCodeRejected, true, false},
		{workOSOutcomeMisconfigured, false, true},
		{workOSOutcomeTransient, false, false},
	}
	for _, tc := range cases {
		err := error(&workOSTokenError{Outcome: tc.outcome, Status: 400})
		if errors.Is(err, errWorkOSRejected) != tc.rejected || errors.Is(err, errWorkOSMisconfigured) != tc.misconfigured {
			t.Errorf("%s: Is(rejected)=%v Is(misconfigured)=%v", tc.outcome,
				errors.Is(err, errWorkOSRejected), errors.Is(err, errWorkOSMisconfigured))
		}
	}
}
