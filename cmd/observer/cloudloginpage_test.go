package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWriteCloudLoginPage pins the styled CLI-login loopback pages: correct
// status per variant, themed HTML (not the old one-line plain text), and the
// core copy for each outcome.
func TestWriteCloudLoginPage(t *testing.T) {
	cases := []struct {
		name       string
		variant    cloudLoginPageVariant
		wantStatus int
		wantBits   []string
	}{
		// The success page must claim only what is true at the moment it renders:
		// the authorization came back, the token exchanges have NOT run yet.
		{"success", cloudLoginPageSuccess, 200, []string{
			"Almost signed in", "authorization received", "This window can be closed",
			"Return to the terminal",
		}},
		{"state mismatch", cloudLoginPageStateMismatch, 400, []string{
			"Sign-in could not be completed", "state mismatch", "observer cloud login",
		}},
		{"auth error", cloudLoginPageAuthError, 400, []string{
			"Authorization was not granted", "shown in your terminal",
		}},
		{"no code", cloudLoginPageNoCode, 400, []string{
			"no authorization code",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeCloudLoginPage(rec, tc.variant)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Fatalf("Content-Type = %q, want text/html", ct)
			}
			body := rec.Body.String()
			if !strings.Contains(body, "<!doctype html>") {
				t.Fatalf("body is not the themed HTML page:\n%s", body)
			}
			// Theme anchors: brand base color, accent, footer wordmark.
			for _, bit := range append(tc.wantBits, "#0D0D12", "SuperBased Observer") {
				if !strings.Contains(body, bit) {
					t.Errorf("body missing %q", bit)
				}
			}
			// The template must be fully static: no fmt verb residue.
			if strings.Contains(body, "%!") || strings.Contains(body, "%s") {
				t.Errorf("unsubstituted/extra fmt verbs leaked into the page:\n%s", body)
			}
			// No page may claim the sign-in is COMPLETE: the loopback responder
			// runs before the token + device exchanges, so it cannot know.
			if strings.Contains(body, "You're signed in") {
				t.Errorf("page claims a completed sign-in it cannot know about:\n%s", body)
			}
		})
	}
}

// TestCloudLoginPageNeverReflectsRequestData pins the no-reflection property:
// the loopback pages are constant HTML, so nothing an attacker puts in the
// callback query (error, error_description, state, code) can appear in the
// response body. The detailed reason goes to the terminal, not the browser.
func TestCloudLoginPageNeverReflectsRequestData(t *testing.T) {
	marker := `<script>alert('xss-marker-4711')</script>`
	for v := cloudLoginPageSuccess; v <= cloudLoginPageNoCode; v++ {
		rec := httptest.NewRecorder()
		// The writer takes no request input at all — this test documents and
		// pins that shape: rebuilding it to accept request-derived strings
		// should force a conscious look at this property.
		writeCloudLoginPage(rec, v)
		if strings.Contains(rec.Body.String(), marker) || strings.Contains(rec.Body.String(), "xss-marker") {
			t.Fatalf("variant %d reflected request data", v)
		}
	}
}
