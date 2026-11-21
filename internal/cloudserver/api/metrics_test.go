package api_test

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudmetrics"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// metrics_test.go: the Paddle webhook end to end against a real store, with
// a metrics registry: the blackbox probe's unsigned POSTs are counted every
// time but write one audit row per source per 10 minutes (AUDITRL-1), the
// next row carries the suppressed count, and verified deliveries and refused
// bindings are counted by their closed labels.

type stepClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stepClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *stepClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newMetricsHarness(t *testing.T, clock *stepClock) (*harness, *cloudmetrics.Registry) {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
	s.SetDeletionJournal(mustJournal(t))
	apiStore.SetDeletionJournal(mustJournal(t))
	priceMap := map[string]store.PaddlePlan{"pri_test_plus": {Name: "plus_beta", Version: 1}}
	s.SetPaddlePriceMap(priceMap)
	apiStore.SetPaddlePriceMap(priceMap)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	reg := cloudmetrics.New(cloudmetrics.ProcessAPI)
	handler := api.New(api.Options{
		Store:               apiStore,
		Queue:               jobs.NewPGQueue(apiStore),
		Verifier:            identity.NewDevAuth(),
		ExternalBaseURL:     "http://" + lis.Addr().String(),
		RateLimit:           &api.RateLimitConfig{},
		Attestor:            admAttestor{verified: true},
		Credentials:         jobs.StaticCredentials{Key: "test-key"},
		PaddleWebhookSecret: paddleSecret,
		Now:                 clock.now,
		Metrics:             reg,
	}).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &harness{srv: srv, store: s}, reg
}

func unsignedPaddle(t *testing.T, base string) int {
	t.Helper()
	resp, err := http.Post(base+"/portal/webhooks/paddle", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

type auditRow struct {
	n      int
	detail string
}

func invalidSignatureRows(t *testing.T, h *harness) auditRow {
	t.Helper()
	var r auditRow
	err := h.store.Pool().QueryRow(t.Context(),
		`SELECT count(*), coalesce(string_agg(detail::text, '|' ORDER BY detail::text DESC), '')
		   FROM security_audit_events WHERE event_type = 'paddle_webhook_signature_invalid'`).Scan(&r.n, &r.detail)
	if err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return r
}

func TestPaddleWebhookMetricsAndInvalidSignatureRowLimit(t *testing.T) {
	clock := &stepClock{t: time.Now()}
	h, reg := newMetricsHarness(t, clock)
	base := h.srv.URL

	// Five probes, two minutes apart: every one answers 401, every one is
	// counted, ONE row is written.
	for i := range 5 {
		if code := unsignedPaddle(t, base); code != http.StatusUnauthorized {
			t.Fatalf("probe %d: status %d, want 401", i, code)
		}
		clock.add(2 * time.Minute)
	}
	if got := invalidSignatureRows(t, h); got.n != 1 || got.detail != "{}" {
		t.Fatalf("rows after 5 probes in one window: %+v, want 1 row with {}", got)
	}
	ev := "paddle_webhook_signature_invalid"
	if got := reg.Value(cloudmetrics.MetricAuditEvents, "event", ev); got != 5 {
		t.Errorf("audit events counted %v, want 5", got)
	}
	if got := reg.Value(cloudmetrics.MetricAuditRowsSuppressed, "event", ev); got != 4 {
		t.Errorf("suppressed rows counted %v, want 4", got)
	}
	if got := reg.Value(cloudmetrics.MetricWebhookDeliveries, "result", "refused", "reason", "signature_invalid"); got != 5 {
		t.Errorf("refused deliveries counted %v, want 5", got)
	}

	// The window (10 minutes from the first row) has passed: the next probe
	// writes a row carrying the four suppressed ones.
	if code := unsignedPaddle(t, base); code != http.StatusUnauthorized {
		t.Fatalf("status %d", code)
	}
	got := invalidSignatureRows(t, h)
	if got.n != 2 || got.detail != `{}|{"window_seconds": 600, "suppressed_rows": 4}` {
		t.Fatalf("rows after the window: %+v", got)
	}

	// A verified delivery that refuses its binding (no checkout nonce, a price
	// we sell): accepted/binding_refused and the binding counter with
	// price_known=true. Signed deliveries never touch the row limit.
	body := paddleActivationBody(uuid.NewString(), "")
	resp := signedPaddle(t, base, body, clock.now(), paddleSecret)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signed delivery status %d", resp.StatusCode)
	}
	if got := reg.Value(cloudmetrics.MetricWebhookDeliveries, "result", "accepted", "reason", "binding_refused"); got != 1 {
		t.Errorf("accepted/binding_refused counted %v, want 1", got)
	}
	if got := reg.Value(cloudmetrics.MetricBindingRefused, "reason", "missing_nonce", "price_known", "true"); got != 1 {
		t.Errorf("binding refused counted %v, want 1", got)
	}
	if got := reg.Value(cloudmetrics.MetricAuditEvents, "event", "paddle_*"); got != 1 {
		t.Errorf("paddle delivery family counted %v, want 1", got)
	}
	if got := reg.Value(cloudmetrics.MetricAuditEvents, "event", cloudmetrics.AuditUnlisted); got != 0 {
		t.Errorf("unlisted audit events %v, want 0", got)
	}
}
