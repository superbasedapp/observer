package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCloudBackgroundReceiptsFollowPolicyGeneration(t *testing.T) {
	for _, change := range []CloudEnrichPolicy{
		{Level: CloudEnrichOff},
		{Level: CloudEnrichTitles, Background: true},
		{Level: CloudEnrichExcerpts, Background: false},
	} {
		t.Run(string(change.Level), func(t *testing.T) {
			s, _ := cloudTestStore(t)
			ctx := context.Background()
			if err := s.SetCloudEnrichPolicy(ctx, CloudEnrichPolicy{Level: CloudEnrichExcerpts, Background: true}); err != nil {
				t.Fatal(err)
			}
			policy, _, _ := s.GetCloudEnrichPolicy(ctx)
			receipt := CloudConsentReceipt{
				AccountPseudonym: "a", Purpose: cloudPurposeContextEnrichment,
				UploadDigest: "digest", BackgroundGeneration: policy.Generation,
			}
			id, err := s.InsertCloudConsentReceipt(ctx, receipt)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.SetCloudEnrichPolicy(ctx, change); err != nil {
				t.Fatal(err)
			}
			old, ok, err := s.GetCloudConsentReceipt(ctx, id)
			if err != nil || !ok || old.InvalidatedAt == nil {
				t.Fatalf("old generation remained live: %+v, %v", old, err)
			}
			if _, err := s.InsertCloudConsentReceipt(ctx, receipt); !errors.Is(err, ErrCloudBackgroundPolicyChanged) {
				t.Fatalf("late background subprocess minted receipt: %v", err)
			}
			// Attended consent remains available even with background off.
			receipt.BackgroundGeneration = 0
			if _, err := s.InsertCloudConsentReceipt(ctx, receipt); err != nil {
				t.Fatalf("manual consent refused: %v", err)
			}
		})
	}
}

func TestCloudPolicyEditWaitsForBackgroundDispatch(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	if err := s.SetCloudEnrichPolicy(ctx, CloudEnrichPolicy{Level: CloudEnrichTitles, Background: true}); err != nil {
		t.Fatal(err)
	}
	p, _, _ := s.GetCloudEnrichPolicy(ctx)
	id, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
		AccountPseudonym: "a",
		Purpose:          cloudPurposeStructuralInsights, UploadDigest: "digest", BackgroundGeneration: p.Generation,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := CloudDispatchLeaseRequest{ReceiptID: id, Purpose: cloudPurposeStructuralInsights, GrantMode: CloudGrantPerUpload, TTL: 5 * time.Second}
	lease, err := s.AcquireCloudDispatchLease(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.SetCloudEnrichPolicy(ctx, CloudEnrichPolicy{Level: CloudEnrichOff}) }()
	deadline := time.After(3 * time.Second)
	for {
		r, _, err := s.GetCloudConsentReceipt(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if r.InvalidatedAt != nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("policy edit did not invalidate the receipt")
		case <-time.After(10 * time.Millisecond):
		}
	}
	select {
	case err := <-done:
		t.Fatalf("off returned before the dispatch lease drained: %v", err)
	default:
	}
	if _, err := s.AcquireCloudDispatchLease(ctx, req); !errors.Is(err, ErrCloudDispatchRefused) {
		t.Fatalf("retired background receipt acquired another dispatch: %v", err)
	}
	if err := s.ReleaseCloudDispatchLease(ctx, lease.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("off did not finish after dispatch released")
	}
}
