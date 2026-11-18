package api_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// browserCallback is h.callback as a browser navigation sends it: Accept
// names text/html.
func (h *workosHarness) browserCallback(t *testing.T, hc *http.Client, code, state string) *http.Response {
	t.Helper()
	u := h.srv.URL + "/portal/auth/workos/callback?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	return resp
}

// TestWorkOSCallbackRecoverableRefusalReturnsToSignIn is L-142: a person
// whose sign-in transaction is gone (the WorkOS page was open longer than the
// transaction, another tab's state, a cookieless browser) finished a real
// sign-up and then saw a raw JSON error. A browser navigation refused for a
// recoverable reason now lands on the console sign-in page with the code, and
// is still refused: no session cookie, the honest transaction unspent. A
// non-browser caller keeps the structured 400.
func TestWorkOSCallbackRecoverableRefusalReturnsToSignIn(t *testing.T) {
	h := newWorkOSHarness(t, true)
	want := "/portal/?signin_error="

	t.Run("no transaction cookie", func(t *testing.T) {
		starter := newBrowser(t)
		state, resp := h.startFlow(t, starter, "")
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("start status=%d", resp.StatusCode)
		}
		cb := h.browserCallback(t, newBrowser(t), "code-recover-missing", state)
		if cb.StatusCode != http.StatusSeeOther || cb.Header.Get("Location") != want+"transaction_missing" {
			t.Fatalf("status=%d location=%q, want 303 to %stransaction_missing", cb.StatusCode, cb.Header.Get("Location"), want)
		}
		if cookieNamed(cb, devCookieName) != nil {
			t.Fatal("a refused callback minted a session cookie")
		}
		if ok := h.callback(t, starter, "code-recover-missing", state); ok.StatusCode != http.StatusSeeOther {
			t.Fatalf("honest completion status=%d body=%s", ok.StatusCode, readAll(ok))
		}
	})

	t.Run("forged state", func(t *testing.T) {
		hc := newBrowser(t)
		if _, resp := h.startFlow(t, hc, ""); resp.StatusCode != http.StatusFound {
			t.Fatalf("start status=%d", resp.StatusCode)
		}
		cb := h.browserCallback(t, hc, newCode("recover-forge"), "an-attacker-chosen-state")
		if cb.StatusCode != http.StatusSeeOther || cb.Header.Get("Location") != want+"state_mismatch" {
			t.Fatalf("status=%d location=%q, want 303 to %sstate_mismatch", cb.StatusCode, cb.Header.Get("Location"), want)
		}
		if cookieNamed(cb, devCookieName) != nil {
			t.Fatal("a forged state minted a session cookie")
		}
	})

	t.Run("replay after consume", func(t *testing.T) {
		hc := newBrowser(t)
		state, _ := h.startFlow(t, hc, "")
		if first := h.callback(t, hc, "code-recover-replay", state); first.StatusCode != http.StatusSeeOther {
			t.Fatalf("first completion status=%d body=%s", first.StatusCode, readAll(first))
		}
		// The first completion spent the cookie, so a stale tab's replay of
		// the same state arrives without one.
		cb := h.browserCallback(t, newBrowser(t), "code-recover-replay", state)
		if cb.StatusCode != http.StatusSeeOther || cb.Header.Get("Location") != want+"transaction_missing" {
			t.Fatalf("status=%d location=%q, want 303 to %stransaction_missing", cb.StatusCode, cb.Header.Get("Location"), want)
		}
	})

	t.Run("a non-browser caller keeps the structured error", func(t *testing.T) {
		starter := newBrowser(t)
		state, _ := h.startFlow(t, starter, "")
		cb := h.callback(t, newBrowser(t), "code-recover-api", state)
		if cb.StatusCode != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400", cb.StatusCode)
		}
		assertCode(t, cb, "transaction_missing")
	})
}

// TestWorkOSTxnCookieLivesAsLongAsItsTransaction pins the cookie's Max-Age to
// the transaction row's lifetime (30 minutes since L-142): a cookie that
// outlived its row, or a row that outlived its cookie, fails the same person.
func TestWorkOSTxnCookieLivesAsLongAsItsTransaction(t *testing.T) {
	h := newWorkOSHarness(t, true)
	_, resp := h.startFlow(t, newBrowser(t), "")
	c := cookieNamed(resp, devTxnCookieName)
	if c == nil {
		t.Fatal("start set no transaction cookie")
	}
	if want := int(store.DefaultAuthTransactionTTL.Seconds()); c.MaxAge != want {
		t.Fatalf("transaction cookie Max-Age=%d, want %d (store.DefaultAuthTransactionTTL)", c.MaxAge, want)
	}
}
