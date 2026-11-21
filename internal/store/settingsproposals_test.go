package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSettingsProposalsLifecycle(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)

	first, err := s.FileSettingsProposal(ctx, NewSettingsProposal{Key: "observability.sdk.destination", Value: "online", Category: "destination_online", RequestedBy: "mcp:test"}, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.FileSettingsProposal(ctx, NewSettingsProposal{Key: "observability.sdk.destination", Value: "both"}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.GetSettingsProposal(ctx, first)
	if err != nil || old.Status != SettingsProposalSuperseded {
		t.Fatalf("a newer request for the same key supersedes the older one: %+v %v", old, err)
	}
	pending, err := s.ListSettingsProposals(ctx, true, 0)
	if err != nil || len(pending) != 1 || pending[0].ID != second || pending[0].Value != "both" {
		t.Fatalf("pending = %+v, %v", pending, err)
	}
	if err := s.DecideSettingsProposal(ctx, second, SettingsProposalApproved, "dashboard", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.DecideSettingsProposal(ctx, second, SettingsProposalRejected, "cli:x", now); !errors.Is(err, ErrSettingsProposalDecided) {
		t.Fatalf("a decided proposal cannot be decided again: %v", err)
	}
	if err := s.DecideSettingsProposal(ctx, 9999, SettingsProposalRejected, "cli:x", now); !errors.Is(err, ErrSettingsProposalNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	if err := s.DecideSettingsProposal(ctx, second, "pending", "x", now); err == nil {
		t.Fatal("only approved or rejected are decisions")
	}
	got, _ := s.GetSettingsProposal(ctx, second)
	if got.Status != SettingsProposalApproved || got.DecidedBy != "dashboard" || got.DecidedAt.IsZero() {
		t.Fatalf("decided row = %+v", got)
	}
	all, _ := s.ListSettingsProposals(ctx, false, 10)
	if len(all) != 2 {
		t.Fatalf("all = %d rows", len(all))
	}
}
