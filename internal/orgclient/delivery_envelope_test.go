// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package orgclient

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedDeliveryForPush records one AI-touched commit that landed through a
// merged PR, so SelectUnpushedSince composes delivery rows (D-689).
func seedDeliveryForPush(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	seedActivity(t, s, 1)
	pid, err := s.UpsertProject(ctx, "/tmp/proj", "git@example.com:acme/app.git")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	const sha = "0123456789abcdef0123456789abcdef01234567"
	if _, err := s.UpsertCommits(ctx, pid, []commitlog.Commit{{
		SHA: sha, AuthoredAt: now.Add(-2 * time.Hour), CommittedAt: now.Add(-2 * time.Hour), Subject: "feat: delivery",
		Files: []commitlog.CommitFile{{RelPath: "a.go", PathHash: "h-a", Added: 3}},
	}}, now); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}
	rows, err := s.LoadProjectCommits(ctx, pid, now.Add(-24*time.Hour), now.Add(time.Hour), 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("LoadProjectCommits = %+v, %v", rows, err)
	}
	linkID, err := s.CreateProviderLink(ctx, delivery.ProviderLink{Provider: delivery.ProviderGitHub, Host: "github.com", AuthMode: "token", KeyName: "link.x.token"})
	if err != nil {
		t.Fatal(err)
	}
	prID, err := s.UpsertPullRequest(ctx, delivery.PullRequest{
		LinkID: linkID, Provider: delivery.ProviderGitHub, Host: "github.com", RepoSlug: "acme/app", Number: 12,
		Title: "feat: delivery", URL: "https://github.com/acme/app/pull/12", State: delivery.PRMerged,
		MergeMethod: delivery.MergeSquash, CreatedAt: now.Add(-90 * time.Minute), MergedAt: now.Add(-time.Hour), FetchedAt: now,
	}, []delivery.PRCommit{{SHA: sha}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertCommitLandings(ctx, []delivery.Landing{{
		CommitID: rows[0].ID, Status: delivery.StatusLanded, Kind: delivery.KindSquash, PRID: prID, PRNumber: 12,
		RuleID: "P1", RuleVersion: delivery.RuleVersion, Source: delivery.SourceProvider, EvaluatedAt: now, SessionIDs: []string{"s1"},
	}}); err != nil {
		t.Fatal(err)
	}
}

// TestPushOnce_DeliveryFamiliesReachTheWire is the end-to-end twin of the
// reflective TestPushEnvelopeMapsEveryBatchFamily for the delivery wire, the
// same way the CommitOwnership family is mapped: the PushBatch slices
// SelectUnpushedSince composes must arrive in the marshalled envelope. Day
// counts ride every posture; PR identity rows only the raw one.
func TestPushOnce_DeliveryFamiliesReachTheWire(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fullContent bool
		wantPRs     bool
	}{
		{"metadata posture ships day counts only", false, false},
		{"full content ships PR rows too", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAgentStore(t)
			bs := &memBearerStore{}
			srv, env := capturePushServer(t)
			bindPub(srv, enrolFixture(t, s, bs, srv.URL))
			seedDeliveryForPush(t, s)

			cfg := config.OrgClientConfig{
				Enabled: true, PushIntervalSeconds: config.DefaultPushIntervalSeconds,
				MaxPushBytes: config.DefaultMaxPushBytes, KeychainID: config.DefaultKeychainID,
				Share: config.OrgClientShareConfig{FullContent: tc.fullContent},
			}
			c := New(cfg, s, bs, "test-version", http.DefaultClient, quietLogger())
			if _, err := c.PushOnce(context.Background()); err != nil {
				t.Fatalf("PushOnce: %v", err)
			}
			if len(env.DeliveryDays) == 0 {
				t.Fatalf("envelope carries no delivery day rows: %+v", *env)
			}
			var landed int64
			for _, d := range env.DeliveryDays {
				landed += d.AICommitsLanded
			}
			if landed != 1 {
				t.Fatalf("landed across day rows = %d, want 1 (%+v)", landed, env.DeliveryDays)
			}
			if got := len(env.PullRequests) > 0; got != tc.wantPRs {
				t.Fatalf("PR rows present = %v, want %v (%+v)", got, tc.wantPRs, env.PullRequests)
			}
			if tc.wantPRs {
				want := orgcontract.PullRequestRow{Number: 12, PRState: "merged"}
				if p := env.PullRequests[0]; p.Number != want.Number || p.PRState != want.PRState {
					t.Fatalf("PR row = %+v", p)
				}
			}
		})
	}
}
