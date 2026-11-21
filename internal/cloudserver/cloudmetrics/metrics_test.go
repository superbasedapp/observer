package cloudmetrics

import (
	"bytes"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestAuditEventTableSortedAndUnique(t *testing.T) {
	if !slices.IsSorted(auditEvents) {
		t.Fatal("auditEvents must stay sorted (AuditEventLabel binary-searches it)")
	}
	if len(slices.Compact(slices.Clone(auditEvents))) != len(auditEvents) {
		t.Fatal("auditEvents has a duplicate")
	}
	// A family must never swallow a listed name's label by accident: a listed
	// name always answers itself.
	for _, e := range auditEvents {
		if got := AuditEventLabel(e); got != e {
			t.Errorf("AuditEventLabel(%q) = %q", e, got)
		}
	}
}

func TestAuditEventLabel(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"paddle_webhook_signature_invalid", "paddle_webhook_signature_invalid"},
		{"paddle_subscription.created_applied", "paddle_*"},
		{"portal_mfa_refused_org_requires_passkey", "portal_mfa_refused_*"},
		{"org_deletion_step_up_invalid", "org_deletion_step_up_invalid"},
		{"org_deletion_step_up_consume", "org_deletion_step_up_*"},
		{"result_correction_applied_user", "result_correction_applied_*"},
		{"paddle_", AuditUnlisted},
		{"", AuditUnlisted},
		{"anything a caller made up", AuditUnlisted},
		{"auth_missing_bearer\n", AuditUnlisted},
	} {
		if got := AuditEventLabel(tc.in); got != tc.want {
			t.Errorf("AuditEventLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestClosedLabels(t *testing.T) {
	for _, tc := range []struct{ res, reason, wantRes, wantReason string }{
		{WebhookAccepted, "applied", WebhookAccepted, "applied"},
		{WebhookAccepted, "made_up", WebhookAccepted, Other},
		{WebhookRefused, "signature_invalid", WebhookRefused, "signature_invalid"},
		{WebhookFailed, "signature_invalid", WebhookFailed, Other},
		{"bogus", "applied", WebhookRefused, Other},
	} {
		res, why := WebhookLabels(tc.res, tc.reason)
		if res != tc.wantRes || why != tc.wantReason {
			t.Errorf("WebhookLabels(%q,%q) = %q,%q", tc.res, tc.reason, res, why)
		}
	}
	if BindingRefusalLabel("no_live_intent") != "no_live_intent" || BindingRefusalLabel("x") != Other {
		t.Error("BindingRefusalLabel")
	}
	if k, r := DeletionBlockLabels("org", "billing_seam_unwired"); k != "org" || r != "billing_seam_unwired" {
		t.Errorf("DeletionBlockLabels = %q,%q", k, r)
	}
	if k, r := DeletionBlockLabels("tenant", "free text"); k != Other || r != Other {
		t.Errorf("DeletionBlockLabels unknown = %q,%q", k, r)
	}
}

func render(t *testing.T, r *Registry) string {
	t.Helper()
	var b bytes.Buffer
	if err := r.Render(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestRenderAPI(t *testing.T) {
	r := New(ProcessAPI)
	out := render(t, r)
	// Seeded from zero: the first event is visible to increase().
	for _, want := range []string{
		"# TYPE sbci_audit_events_total counter\n",
		`sbci_audit_events_total{event="paddle_webhook_signature_invalid"} 0` + "\n",
		`sbci_audit_rows_suppressed_total{event="paddle_webhook_signature_invalid"} 0` + "\n",
		`sbci_paddle_webhook_deliveries_total{result="refused",reason="signature_invalid"} 0` + "\n",
		`sbci_paddle_binding_refused_total{reason="no_live_intent",price_known="true"} 0` + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render lacks %q", want)
		}
	}
	if strings.Contains(out, "sbci_deletion") {
		t.Error("the API process must not render the worker's families")
	}
	r.AuditEvent("paddle_webhook_signature_invalid")
	r.AuditEvent("paddle_webhook_signature_invalid")
	r.AuditRowSuppressed("paddle_webhook_signature_invalid")
	r.AuditEvent(`free "text"`)
	r.WebhookDelivery(WebhookRefused, "signature_invalid")
	r.BindingRefused("no_live_intent", true)
	r.BindingRefused("something new", false)
	out = render(t, r)
	for _, want := range []string{
		`sbci_audit_events_total{event="paddle_webhook_signature_invalid"} 2`,
		`sbci_audit_rows_suppressed_total{event="paddle_webhook_signature_invalid"} 1`,
		`sbci_audit_events_total{event="unlisted"} 1`,
		`sbci_paddle_webhook_deliveries_total{result="refused",reason="signature_invalid"} 1`,
		`sbci_paddle_binding_refused_total{reason="no_live_intent",price_known="true"} 1`,
		`sbci_paddle_binding_refused_total{reason="other",price_known="false"} 1`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("render lacks %q", want)
		}
	}
	if strings.Contains(out, "free") {
		t.Error("a caller's string reached a label")
	}
}

func TestRenderWorker(t *testing.T) {
	r := New(ProcessWorker)
	out := render(t, r)
	for _, want := range []string{
		`sbci_deletion_blocked_total{kind="org",reason="billing_seam_unwired"} 0`,
		`sbci_deletion_blocked_open{kind="org"} 0`,
		`sbci_deletion_blocked_open{kind="account"} 0`,
		`sbci_deletion_blocked_open_read_ok -1`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("render lacks %q", want)
		}
	}
	if strings.Contains(out, "sbci_audit") || strings.Contains(out, "sbci_paddle") {
		t.Error("the worker must not render the API's families")
	}
	r.DeletionBlocked("org", "billing_cancel_refused")
	r.DeletionBlocked("weird", "billing:cancel:http_400")
	r.SetDeletionsBlockedOpen(2, 1)
	out = render(t, r)
	for _, want := range []string{
		`sbci_deletion_blocked_total{kind="org",reason="billing_cancel_refused"} 1`,
		`sbci_deletion_blocked_total{kind="other",reason="other"} 1`,
		`sbci_deletion_blocked_open{kind="org"} 2`,
		`sbci_deletion_blocked_open{kind="account"} 1`,
		`sbci_deletion_blocked_open_read_ok 1`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("render lacks %q", want)
		}
	}
	r.DeletionsBlockedOpenReadFailed()
	if r.Value(MetricDeletionOpenReadOK) != 0 || r.Value(MetricDeletionBlockedOpen, "kind", "org") != 2 {
		t.Error("a failed read keeps the counts and reports 0")
	}
}

func TestNilRegistryIsInert(t *testing.T) {
	var r *Registry
	r.AuditEvent("x")
	r.AuditRowSuppressed("x")
	r.WebhookDelivery(WebhookAccepted, "applied")
	r.BindingRefused("x", true)
	r.DeletionBlocked("org", "x")
	r.SetDeletionsBlockedOpen(1, 1)
	r.DeletionsBlockedOpenReadFailed()
	if r.Value(MetricAuditEvents) != 0 {
		t.Fatal("nil Value")
	}
	if err := r.Render(&bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentIncrements(t *testing.T) {
	r := New(ProcessAPI)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				r.AuditEvent("auth_missing_bearer")
				_ = r.Render(&bytes.Buffer{})
			}
		}()
	}
	wg.Wait()
	if got := r.Value(MetricAuditEvents, "event", "auth_missing_bearer"); got != 8000 {
		t.Fatalf("got %v, want 8000", got)
	}
}

func TestEscapeLabelValue(t *testing.T) {
	if got := escapeLabelValue("a\\b\"c\nd"); got != `a\\b\"c\nd` {
		t.Fatalf("got %q", got)
	}
}
