package paddleapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/seatbilling"
)

const (
	testKey   = "pdl_sdbx_apikey_test_not_a_real_key"
	subID     = "sub_01jc0000000000000000000000"
	seatPrice = "pri_01jcseat000000000000000000"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// exchange is one expected request and the fixture answered.
type exchange struct {
	method  string
	body    string // expected request body ("" for none)
	status  int
	fixture string
}

// replay serves the exchanges in order and fails the test on any request
// that is not the next one expected (method, path, headers, body).
func replay(t *testing.T, ex ...exchange) (*Client, *int) {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n >= len(ex) {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusTeapot)
			return
		}
		e := ex[n]
		n++
		if r.Method != e.method || r.URL.Path != "/subscriptions/"+subID {
			t.Errorf("request %s %s, want %s /subscriptions/%s", r.Method, r.URL.Path, e.method, subID)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testKey {
			t.Errorf("Authorization = %q", got)
		}
		if r.Header.Get("Paddle-Version") != APIVersion || r.Header.Get("Accept") != "application/json" {
			t.Errorf("headers = %v", r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		if strings.TrimSpace(string(body)) != strings.TrimSpace(e.body) {
			t.Errorf("body = %s\nwant   %s", body, e.body)
		}
		if e.body != "" && r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(e.status)
		_, _ = w.Write(fixture(t, e.fixture))
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testKey, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return c, &n
}

// TestSyncAgainstTheFixtures drives seatbilling.Sync through the real
// client: one GET, one PATCH carrying every item with only the seat
// quantity changed, and the answer checked.
func TestSyncAgainstTheFixtures(t *testing.T) {
	t.Parallel()
	c, n := replay(t,
		exchange{method: http.MethodGet, status: 200, fixture: "get_subscription.json"},
		exchange{method: http.MethodPatch, body: string(fixture(t, "update_request.json")), status: 200, fixture: "update_subscription.json"},
	)
	d, err := seatbilling.Sync(context.Background(), c, seatbilling.SyncInput{
		SubscriptionID: subID, SeatPriceID: seatPrice, Seats: 7, Complete: true, SeatsMin: 3,
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if d.Action != seatbilling.ActionUpdate || d.Quantity != 7 || d.Current != 4 || *n != 2 {
		t.Fatalf("Sync = %+v after %d requests", d, *n)
	}
}

// TestGetMapsTheEntity: status, interval and items come through.
func TestGetMapsTheEntity(t *testing.T) {
	t.Parallel()
	c, _ := replay(t, exchange{method: http.MethodGet, status: 200, fixture: "get_subscription.json"})
	s, err := c.GetSubscription(context.Background(), subID)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != subID || s.Status != "active" || s.Interval != "month" || len(s.Items) != 2 || s.Items[0].PriceID != seatPrice || s.Items[0].Quantity != 4 {
		t.Fatalf("GetSubscription = %+v", s)
	}
}

// TestErrorsDecodeTheEnvelope: a 404 and a 429 become APIErrors with
// Paddle's fields; neither leaks the key.
func TestErrorsDecodeTheEnvelope(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		status    int
		fixture   string
		code      string
		retryable bool
	}{
		{404, "error_not_found.json", "not_found", false},
		{429, "error_rate_limited.json", "too_many_requests", true},
	} {
		c, _ := replay(t, exchange{method: http.MethodGet, status: tc.status, fixture: tc.fixture})
		_, err := c.GetSubscription(context.Background(), subID)
		var ae *APIError
		if !errors.As(err, &ae) || ae.HTTPStatus != tc.status || ae.Code != tc.code || ae.Retryable() != tc.retryable || ae.RequestID == "" {
			t.Fatalf("%d: err = %#v", tc.status, err)
		}
		if strings.Contains(err.Error(), testKey) {
			t.Fatal("an error carries the API key")
		}
	}
}

// TestNewBaseURLAndKeyTable: one row per base URL rule and per key
// environment, plus the refusals.
func TestNewBaseURLAndKeyTable(t *testing.T) {
	t.Parallel()
	const liveKey = "pdl_live_apikey_test_not_a_real_key"
	for _, tc := range []struct {
		name string
		base string
		key  string
		want error // nil: accepted
	}{
		{"sandbox with a sandbox key", SandboxBaseURL, testKey, nil},
		{"live with a live key", LiveBaseURL, liveKey, nil},
		{"loopback with any key", "http://127.0.0.1:8080", "anything", nil},
		{"localhost", "http://localhost:9", testKey, nil},
		{"live with a sandbox key", LiveBaseURL, testKey, ErrKeyEnvironment},
		{"sandbox with a live key", SandboxBaseURL, liveKey, ErrKeyEnvironment},
		{"live with an unprefixed key", LiveBaseURL, "0123456789abcdef", ErrKeyEnvironment},
		{"look-alike host", "https://sandbox-api.paddle.com.evil.example", testKey, ErrBaseURL},
		{"live look-alike host", "https://api.paddle.com.evil.example", liveKey, ErrBaseURL},
		{"plain http sandbox", "http://sandbox-api.paddle.com", testKey, ErrBaseURL},
		{"live with a path", "https://api.paddle.com/v1", liveKey, ErrBaseURL},
		{"loopback with a path", "http://127.0.0.1:8080/prefix", testKey, ErrBaseURL},
		{"not a url", "::not a url", testKey, ErrBaseURL},
		{"no key", SandboxBaseURL, "", ErrNoKey},
	} {
		_, err := New(tc.base, tc.key, http.DefaultClient)
		switch {
		case tc.want == nil && err != nil:
			t.Errorf("%s: New = %v, want ok", tc.name, err)
		case tc.want != nil && !errors.Is(err, tc.want):
			t.Errorf("%s: New = %v, want %v", tc.name, err, tc.want)
		}
		if err != nil && tc.key != "" && strings.Contains(err.Error(), tc.key) {
			t.Errorf("%s: the error carries the key", tc.name)
		}
	}
	if _, err := New(SandboxBaseURL, testKey, nil); err == nil {
		t.Error("no HTTP client accepted")
	}
}

// TestKeyEnvironmentAndBaseURLFor: the prefix table and the environment
// table.
func TestKeyEnvironmentAndBaseURLFor(t *testing.T) {
	t.Parallel()
	for key, want := range map[string]string{
		"pdl_live_apikey_x": EnvLive, "pdl_sdbx_apikey_x": EnvSandbox, "": "", "live_x": "", "test_x": "", "pdl_x": "",
	} {
		if got := KeyEnvironment(key); got != want {
			t.Errorf("KeyEnvironment(%q) = %q, want %q", key, got, want)
		}
	}
	for env, want := range map[string]string{EnvLive: LiveBaseURL, EnvSandbox: SandboxBaseURL} {
		if got, err := BaseURLFor(env); err != nil || got != want {
			t.Errorf("BaseURLFor(%q) = %q, %v", env, got, err)
		}
	}
	if _, err := BaseURLFor("production"); !errors.Is(err, ErrEnvironment) {
		t.Errorf("BaseURLFor(production) = %v", err)
	}
}

// TestGetReadsTheBillingPeriod: the current period comes through for the
// seat sync pass.
func TestGetReadsTheBillingPeriod(t *testing.T) {
	t.Parallel()
	c, _ := replay(t, exchange{method: http.MethodGet, status: 200, fixture: "get_subscription.json"})
	s, err := c.GetSubscription(context.Background(), subID)
	if err != nil {
		t.Fatal(err)
	}
	if s.PeriodStart != "2026-11-01T00:00:00Z" || s.PeriodEnd != "2026-12-01T00:00:00Z" {
		t.Fatalf("period = %q..%q", s.PeriodStart, s.PeriodEnd)
	}
}

const customerID = "ctm_01jc0000000000000000000000"

// portalServer answers one portal session request with body, checking the
// request.
func portalServer(t *testing.T, status int, body string) (*Client, *int) {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if r.Method != http.MethodPost || r.URL.Path != "/customers/"+customerID+"/portal-sessions" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+testKey || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("headers = %v", r.Header)
		}
		got, _ := io.ReadAll(r.Body)
		if strings.TrimSpace(string(got)) != `{"subscription_ids":["`+subID+`"]}` {
			t.Errorf("body = %s", got)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testKey, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return c, &n
}

// TestCreatePortalSession: the documented response shape, and a link that
// is not an https paddle.com link is dropped or refused.
func TestCreatePortalSession(t *testing.T) {
	t.Parallel()
	c, n := portalServer(t, 201, string(fixture(t, "portal_session.json")))
	ps, err := c.CreatePortalSession(context.Background(), customerID, []string{subID})
	if err != nil {
		t.Fatal(err)
	}
	if *n != 1 || !strings.HasPrefix(ps.Overview, "https://sandbox-customer-portal.paddle.com/") || len(ps.Subscriptions) != 1 ||
		ps.Subscriptions[0].ID != subID || ps.Subscriptions[0].Cancel == "" || ps.Subscriptions[0].UpdatePaymentMethod == "" {
		t.Fatalf("session = %+v", ps)
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{"another customer", `{"data":{"customer_id":"ctm_01jc1111111111111111111111","urls":{"general":{"overview":"https://customer-portal.paddle.com/x"}}}}`},
		{"overview off paddle.com", `{"data":{"customer_id":"` + customerID + `","urls":{"general":{"overview":"https://customer-portal.paddle.com.evil.example/x"}}}}`},
		{"overview over http", `{"data":{"customer_id":"` + customerID + `","urls":{"general":{"overview":"http://customer-portal.paddle.com/x"}}}}`},
		{"no entity", `{"meta":{}}`},
	} {
		c, _ := portalServer(t, 201, tc.body)
		if _, err := c.CreatePortalSession(context.Background(), customerID, []string{subID}); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}

	c, _ = portalServer(t, 201, `{"data":{"customer_id":"`+customerID+`","urls":{"general":{"overview":"https://customer-portal.paddle.com/x"},"subscriptions":[{"id":"`+subID+`","cancel_subscription":"javascript:alert(1)","update_subscription_payment_method":"https://customer-portal.paddle.com/y"}]}}}`)
	ps, err = c.CreatePortalSession(context.Background(), customerID, []string{subID})
	if err != nil || ps.Subscriptions[0].Cancel != "" || ps.Subscriptions[0].UpdatePaymentMethod == "" {
		t.Fatalf("a bad deep link is not dropped: %+v %v", ps, err)
	}
}

// TestPortalSessionIDsAreCheckedBeforeAnyRequest: a malformed customer or
// subscription id sends nothing; an error answer is an APIError.
func TestPortalSessionIDsAreCheckedBeforeAnyRequest(t *testing.T) {
	t.Parallel()
	c, n := portalServer(t, 403, `{"error":{"type":"request_error","code":"forbidden","detail":"permission"},"meta":{"request_id":"r1"}}`)
	for _, tc := range []struct {
		customer string
		subs     []string
		want     error
	}{
		{"ctm_short", []string{subID}, ErrCustomerID},
		{"ctm_01jc000000000000000000000/../x", []string{subID}, ErrCustomerID},
		{customerID, []string{"sub_bad"}, ErrSubscriptionID},
	} {
		if _, err := c.CreatePortalSession(context.Background(), tc.customer, tc.subs); !errors.Is(err, tc.want) {
			t.Errorf("CreatePortalSession(%q, %v) = %v", tc.customer, tc.subs, err)
		}
	}
	if *n != 0 {
		t.Fatalf("%d requests sent", *n)
	}
	_, err := c.CreatePortalSession(context.Background(), customerID, []string{subID})
	var ae *APIError
	if !errors.As(err, &ae) || ae.HTTPStatus != 403 || ae.Code != "forbidden" {
		t.Fatalf("403 = %#v", err)
	}
}

// TestSubscriptionIDIsCheckedBeforeAnyRequest: a malformed id (a path
// injection, among others) sends nothing.
func TestSubscriptionIDIsCheckedBeforeAnyRequest(t *testing.T) {
	t.Parallel()
	c, n := replay(t)
	for _, id := range []string{"", "sub_short", "sub_01JC0000000000000000000000", "sub_01jc000000000000000000000/../x", "ctm_01jc0000000000000000000000"} {
		if _, err := c.GetSubscription(context.Background(), id); !errors.Is(err, ErrSubscriptionID) {
			t.Errorf("GetSubscription(%q) = %v", id, err)
		}
	}
	if *n != 0 {
		t.Fatalf("%d requests sent", *n)
	}
	if !ValidSubscriptionID(subID) {
		t.Fatal("the fixture id is not valid")
	}
}

// TestAnswerForAnotherSubscriptionIsRefused: a 200 that names another
// subscription, or carries no entity, is an error.
func TestAnswerForAnotherSubscriptionIsRefused(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "0") {
			_, _ = w.Write([]byte(`{"data":{"id":"sub_01jc1111111111111111111111"},"meta":{}}`))
			return
		}
		_, _ = w.Write([]byte(`{"meta":{}}`))
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, testKey, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetSubscription(context.Background(), subID); err == nil || !strings.Contains(err.Error(), "answered sub_01jc1111") {
		t.Fatalf("another subscription = %v", err)
	}
	if _, err := c.GetSubscription(context.Background(), "sub_01jc0000000000000000000001"); err == nil || !strings.Contains(err.Error(), "no subscription") {
		t.Fatalf("no entity = %v", err)
	}
}

// TestCancelSubscription (FR-1): one row per answer. The request is POST
// /subscriptions/{id}/cancel with effective_from "immediately"; a 200 maps
// the canceled entity, a refused cancel and a rate limit are APIErrors, and
// a malformed id sends nothing.
func TestCancelSubscription(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		id        string
		status    int
		fixture   string
		requests  int
		wantState string
		wantCode  string
		retryable bool
		wantIDErr bool
	}{
		{name: "canceled now", id: subID, status: 200, fixture: "cancel_subscription.json", requests: 1, wantState: StatusCanceled},
		{name: "refused: already canceled", id: subID, status: 400, fixture: "error_cancel_refused.json", requests: 1, wantCode: "subscription_update_when_canceled"},
		{name: "rate limited", id: subID, status: 429, fixture: "error_rate_limited.json", requests: 1, wantCode: "too_many_requests", retryable: true},
		{name: "malformed id sends nothing", id: "sub_01jc000000000000000000000/../x", wantIDErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n++
				if r.Method != http.MethodPost || r.URL.Path != "/subscriptions/"+subID+"/cancel" {
					t.Errorf("request %s %s", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer "+testKey {
					t.Errorf("Authorization = %q", got)
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
				}
				body, _ := io.ReadAll(r.Body)
				if string(body) != `{"effective_from":"immediately"}` {
					t.Errorf("body = %s", body)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write(fixture(t, tc.fixture))
			}))
			t.Cleanup(srv.Close)
			c, err := New(srv.URL, testKey, srv.Client())
			if err != nil {
				t.Fatal(err)
			}
			s, err := c.CancelSubscription(context.Background(), tc.id)
			switch {
			case tc.wantIDErr:
				if !errors.Is(err, ErrSubscriptionID) {
					t.Fatalf("err = %v, want ErrSubscriptionID", err)
				}
			case tc.wantCode != "":
				var ae *APIError
				if !errors.As(err, &ae) || ae.Code != tc.wantCode || ae.Retryable() != tc.retryable {
					t.Fatalf("err = %#v", err)
				}
				if strings.Contains(err.Error(), testKey) {
					t.Fatal("an error carries the API key")
				}
			default:
				if err != nil || s.ID != subID || s.Status != tc.wantState {
					t.Fatalf("CancelSubscription = %+v, %v", s, err)
				}
			}
			if n != tc.requests {
				t.Fatalf("%d requests sent, want %d", n, tc.requests)
			}
		})
	}
}
