package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// clouddispatch_test.go pins the dispatch-lease seam (migration 100, Sol
// re-review N2): a lease is refused under a receipt that is not live at the
// EXACT terms named, revoke/supersede cancel leases, and the quiescence wait
// blocks while a lease is active and returns on release or expiry.

// seedDispatchStandingReceipt records a live standing receipt at generation 1
// for purpose and returns its id.
func seedDispatchStandingReceipt(t *testing.T, s *Store, purpose string) string {
	t.Helper()
	review := time.Now().UTC().Add(24 * time.Hour)
	id, err := s.InsertCloudConsentReceipt(context.Background(), CloudConsentReceipt{
		AccountPseudonym:      "acct-lease",
		Purpose:               purpose,
		FieldClassesJSON:      `["structural_metrics"]`,
		EnvelopeSchemaVersion: "x.v1",
		ScrubberVersion:       "scrub-v1",
		Endpoint:              "https://cloud.example/v1/community/contribution",
		UploadDigest:          "sha256:dict",
		DataDictionaryDigest:  "sha256:dict",
		GrantMode:             CloudGrantStanding,
		DeclaredTimezone:      "UTC",
		SourceWindowRule:      "in_progress_utc_month_after_grant",
		ReviewAt:              &review,
		ConsentGeneration:     1,
	})
	if err != nil {
		t.Fatalf("seed standing receipt: %v", err)
	}
	return id
}

func leaseReq(receiptID string) CloudDispatchLeaseRequest {
	return CloudDispatchLeaseRequest{
		ReceiptID:         receiptID,
		Purpose:           "community_cohort_benchmarking",
		ConsentGeneration: 1,
		TTL:               time.Minute,
	}
}

func TestAcquireCloudDispatchLeaseRequiresExactLiveTerms(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	id := seedDispatchStandingReceipt(t, s, "community_cohort_benchmarking")

	lease, err := s.AcquireCloudDispatchLease(ctx, leaseReq(id))
	if err != nil {
		t.Fatalf("live receipt at exact terms: %v", err)
	}
	if lease.ID == "" || lease.ReceiptID != id || !lease.ExpiresAt.After(time.Now()) {
		t.Fatalf("lease = %+v", lease)
	}
	if n, _ := s.CountActiveCloudDispatchLeases(ctx, []string{id}); n != 1 {
		t.Fatalf("active leases = %d, want 1", n)
	}

	tests := []struct {
		name   string
		mutate func(r *CloudDispatchLeaseRequest)
	}{
		{"wrong generation", func(r *CloudDispatchLeaseRequest) { r.ConsentGeneration = 2 }},
		{"wrong purpose", func(r *CloudDispatchLeaseRequest) { r.Purpose = "structural_activity_insights" }},
		{"unknown receipt", func(r *CloudDispatchLeaseRequest) { r.ReceiptID = "rcpt_nope" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := leaseReq(id)
			tc.mutate(&req)
			_, err := s.AcquireCloudDispatchLease(ctx, req)
			if !errors.Is(err, ErrCloudDispatchRefused) {
				t.Fatalf("want ErrCloudDispatchRefused, got %v", err)
			}
		})
	}

	// A revoked receipt refuses the lease.
	if err := s.InvalidateCloudConsentReceipt(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcquireCloudDispatchLease(ctx, leaseReq(id)); !errors.Is(err, ErrCloudDispatchRefused) {
		t.Fatalf("revoked receipt: want ErrCloudDispatchRefused, got %v", err)
	}
	// The lease taken before the revoke is still ACTIVE until released — a
	// revoke must wait for it, not pretend it is gone.
	if n, _ := s.CountActiveCloudDispatchLeases(ctx, []string{id}); n != 1 {
		t.Fatalf("active leases after revoke = %d, want 1 (still held)", n)
	}
	if err := s.ReleaseCloudDispatchLease(ctx, lease.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountActiveCloudDispatchLeases(ctx, []string{id}); n != 0 {
		t.Fatalf("active leases after release = %d, want 0", n)
	}
}

func TestAcquireCloudDispatchLeaseRefusesPerUploadAndExpiredReceipts(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	perUpload := seedReceipt(t, s, "sha256:one")
	_, err := s.AcquireCloudDispatchLease(ctx, CloudDispatchLeaseRequest{
		ReceiptID: perUpload, Purpose: "bounded_context_enrichment", ConsentGeneration: 1, TTL: time.Minute,
	})
	if !errors.Is(err, ErrCloudDispatchRefused) {
		t.Fatalf("per-upload receipt: want ErrCloudDispatchRefused, got %v", err)
	}

	past := time.Now().UTC().Add(-time.Hour)
	expired, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
		AccountPseudonym: "acct", Purpose: "community_cohort_benchmarking", UploadDigest: "sha256:d",
		Endpoint: "https://cloud.example/x", GrantMode: CloudGrantStanding, ReviewAt: &past, ConsentGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcquireCloudDispatchLease(ctx, leaseReq(expired)); !errors.Is(err, ErrCloudDispatchRefused) {
		t.Fatalf("expired receipt: want ErrCloudDispatchRefused, got %v", err)
	}
}

// TestAwaitCloudDispatchQuiescenceBlocksWhileALeaseIsHeld is the N2 wait: a
// revoke must not return while an attempt holds a lease under the receipt,
// and must return as soon as that lease is released.
func TestAwaitCloudDispatchQuiescenceBlocksWhileALeaseIsHeld(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	id := seedDispatchStandingReceipt(t, s, "community_cohort_benchmarking")
	lease, err := s.AcquireCloudDispatchLease(ctx, leaseReq(id))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.CancelCloudDispatchLeasesForReceipt(ctx, id); err != nil || n != 1 {
		t.Fatalf("cancel: n=%d err=%v", n, err)
	}

	done := make(chan int, 1)
	go func() {
		waited, err := s.AwaitCloudDispatchQuiescence(ctx, []string{id})
		if err != nil {
			t.Errorf("await: %v", err)
		}
		done <- waited
	}()
	select {
	case <-done:
		t.Fatal("AwaitCloudDispatchQuiescence returned while the lease was still held")
	case <-time.After(150 * time.Millisecond):
	}
	if err := s.ReleaseCloudDispatchLease(ctx, lease.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case waited := <-done:
		if waited != 1 {
			t.Fatalf("waited for %d lease(s), want 1", waited)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AwaitCloudDispatchQuiescence did not return after the lease was released")
	}
}

// TestAwaitCloudDispatchQuiescenceIsBoundedByLeaseExpiry pins the bound: a
// holder that never releases (a hung or killed sender) cannot block revoke past
// the lease's own expiry.
func TestAwaitCloudDispatchQuiescenceIsBoundedByLeaseExpiry(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	id := seedDispatchStandingReceipt(t, s, "community_cohort_benchmarking")
	req := leaseReq(id)
	req.TTL = 80 * time.Millisecond
	if _, err := s.AcquireCloudDispatchLease(ctx, req); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	waited, err := s.AwaitCloudDispatchQuiescence(ctx, []string{id})
	if err != nil {
		t.Fatal(err)
	}
	if waited != 1 {
		t.Fatalf("waited = %d, want 1", waited)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("quiescence took %s — not bounded by the lease TTL", el)
	}
	if _, err := s.AwaitCloudDispatchQuiescence(ctx, nil); err != nil {
		t.Fatalf("no receipts: %v", err)
	}
}

// TestReplaceStandingConsentGrantCancelsSupersededLeases pins that a supersede
// marks the old receipt's leases cancelled inside its own transaction.
func TestReplaceStandingConsentGrantCancelsSupersededCloudDispatchLeases(t *testing.T) {
	s, database := cloudTestStore(t)
	ctx := context.Background()
	old := seedDispatchStandingReceipt(t, s, "community_cohort_benchmarking")
	lease, err := s.AcquireCloudDispatchLease(ctx, leaseReq(old))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceStandingConsentGrant(ctx, CloudConsentReceipt{
		AccountPseudonym: "acct-lease", Purpose: "community_cohort_benchmarking",
		UploadDigest: "sha256:dict2", DataDictionaryDigest: "sha256:dict2",
		Endpoint: "https://cloud.example/v1/community/contribution", GrantMode: CloudGrantStanding,
	}); err != nil {
		t.Fatal(err)
	}
	var cancelled string
	if err := database.QueryRowContext(ctx,
		`SELECT COALESCE(cancelled_at, '') FROM cloud_dispatch_leases WHERE id = ?`, lease.ID).Scan(&cancelled); err != nil {
		t.Fatal(err)
	}
	if cancelled == "" {
		t.Fatal("the superseded receipt's lease was not cancelled")
	}
	// Still active (held) until released — the CLI waits for it.
	if n, _ := s.CountActiveCloudDispatchLeases(ctx, []string{old}); n != 1 {
		t.Fatalf("active = %d, want 1", n)
	}
	// And no NEW lease can be taken under the superseded receipt.
	if _, err := s.AcquireCloudDispatchLease(ctx, leaseReq(old)); !errors.Is(err, ErrCloudDispatchRefused) {
		t.Fatalf("want ErrCloudDispatchRefused under a superseded receipt, got %v", err)
	}
}
