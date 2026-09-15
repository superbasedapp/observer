package orgclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestReportIntegrity_RoundTrip: the client POSTs the fingerprint + coarse
// labels to /api/agent/managed-integrity under the enrolment bearer and decodes
// the ack. The fingerprint is present (this host has /etc/machine-id) so the
// call reaches the server rather than skipping.
func TestReportIntegrity_RoundTrip(t *testing.T) {
	var (
		gotAuth string
		gotBody orgcontract.ManagedIntegrityReport
		hits    int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/agent/managed-integrity" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(orgcontract.ManagedIntegrityResponse{Acknowledged: true})
	}))
	defer srv.Close()

	c, _, _ := enrolledClient(t, srv.URL)
	res, err := c.ReportIntegrity(context.Background(), orgcontract.ManagedIntegrityReport{
		SiblingObservers:    2,
		SiblingDetail:       []string{"wsl-mnt/windows", "wsl-mnt/windows"},
		RouteDrift:          1,
		DriftedTools:        []string{"claude-code"},
		CaptureCheckVersion: orgcontract.ManagedCaptureCheckVersion,
		CaptureRisks:        []string{orgcontract.CaptureRiskHookConfigChanged},
		UnknownChecks:       []string{orgcontract.CaptureUnknownCodexTrust},
	})
	if err != nil {
		t.Fatalf("ReportIntegrity: %v", err)
	}
	if hits == 0 {
		t.Fatal("server was never hit (empty machine identity?)")
	}
	if !res.Acknowledged {
		t.Errorf("ack = %v, want true", res.Acknowledged)
	}
	if gotAuth != "Bear"+"er "+"bearer-xyz" {
		t.Errorf("Authorization = %q, want the enrolment credential", gotAuth)
	}
	if gotBody.MachineIdentity == "" {
		t.Error("machine_identity must be present on the wire")
	}
	if gotBody.SiblingObservers != 2 || gotBody.RouteDrift != 1 {
		t.Errorf("counts = (%d,%d), want (2,1); label dedup must not erase multiplicity", gotBody.SiblingObservers, gotBody.RouteDrift)
	}
	if len(gotBody.SiblingDetail) != 1 {
		t.Errorf("sibling labels = %v, want one deduplicated coarse label", gotBody.SiblingDetail)
	}
	if len(gotBody.DriftedTools) != 1 || gotBody.DriftedTools[0] != "claude-code" {
		t.Errorf("drifted tools = %v, want [claude-code]", gotBody.DriftedTools)
	}
	if gotBody.CaptureCheckVersion != orgcontract.ManagedCaptureCheckVersion ||
		len(gotBody.CaptureRisks) != 1 || len(gotBody.UnknownChecks) != 1 {
		t.Errorf("capture checks = version %d risks=%v unknown=%v", gotBody.CaptureCheckVersion, gotBody.CaptureRisks, gotBody.UnknownChecks)
	}
}

// TestReportIntegrity_OlderServer404: a 404 from an older server is a no-op, not
// an error (best-effort probe).
func TestReportIntegrity_OlderServer404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c, _, _ := enrolledClient(t, srv.URL)
	if _, err := c.ReportIntegrity(context.Background(), orgcontract.ManagedIntegrityReport{}); err != nil {
		t.Fatalf("404 must be a no-op, got %v", err)
	}
}

// TestReportIntegrity_Unbound409: a 409 (the ownership guard refusing an
// unbound or mismatched machine) surfaces as the named
// ErrManagedIntegrityUnbound sentinel — recognizable via errors.Is, not a
// generic error string — mirroring BindMachine's own ErrManagedBindRefused
// precedent for the same server-side condition class.
func TestReportIntegrity_Unbound409(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	c, _, _ := enrolledClient(t, srv.URL)
	_, err := c.ReportIntegrity(context.Background(), orgcontract.ManagedIntegrityReport{})
	if !errors.Is(err, ErrManagedIntegrityUnbound) {
		t.Fatalf("ReportIntegrity on 409 = %v, want errors.Is ErrManagedIntegrityUnbound", err)
	}
}
