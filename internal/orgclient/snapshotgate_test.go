// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package orgclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// This file pins the PUSH-LOOP half of Track R2 (docs/plans/
// observer-steady-state-cpu-remediation-plan-2026-08-26.md): the snapshot
// cadence knob the loop owns, and the commit-on-success contract that decides
// when the store may treat a snapshot family as delivered.

func TestSnapshotInterval_ResolvesFromPushInterval(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		push     int
		snapshot int
		want     time.Duration
	}{
		{
			name: "unset defaults to a multiple of the effective push interval",
			push: 0, snapshot: 0,
			want: time.Duration(config.DefaultSnapshotIntervalMultiple) *
				time.Duration(config.DefaultPushIntervalSeconds) * time.Second,
		},
		{
			// The default is a RATIO, not an absolute: retuning the push
			// cadence must retune the snapshot cadence with it.
			name: "unset tracks a retuned push interval",
			push: 30, snapshot: 0,
			want: time.Duration(config.DefaultSnapshotIntervalMultiple) * 30 * time.Second,
		},
		{
			name: "explicit value wins",
			push: 120, snapshot: 900,
			want: 900 * time.Second,
		},
		{
			name: "negative disables the throttle",
			push: 120, snapshot: -1,
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Client{cfg: config.OrgClientConfig{
				PushIntervalSeconds:     tc.push,
				SnapshotIntervalSeconds: tc.snapshot,
			}}
			if got := c.snapshotInterval(); got != tc.want {
				t.Errorf("snapshotInterval() = %v, want %v", got, tc.want)
			}
		})
	}
}

// pushGateFixture stands up an enrolled client whose only snapshot wire is the
// routing summary, recording every envelope the server receives. The routing
// summary is chosen because it is a single, cheaply-dirtied aggregate over one
// table (router_decisions).
type pushGateFixture struct {
	store *store.Store
	envs  []orgcontract.PushEnvelope
	srv   *httptest.Server
}

func newPushGateFixture(t *testing.T, snapshotIntervalSeconds int) (*pushGateFixture, *Client) {
	t.Helper()
	s := newAgentStore(t)
	bs := &memBearerStore{}
	f := &pushGateFixture{store: s}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ := io.ReadAll(r.Body)
		env := decodeEnvelope(t, wire)
		f.envs = append(f.envs, env)
		writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{NextCursor: env.CursorTo})
	}))
	t.Cleanup(f.srv.Close)

	pub := enrolFixture(t, s, bs, f.srv.URL)
	bindPub(f.srv, pub)

	cfg := config.OrgClientConfig{
		Enabled: true, PushIntervalSeconds: config.DefaultPushIntervalSeconds,
		SnapshotIntervalSeconds: snapshotIntervalSeconds,
		MaxPushBytes:            config.DefaultMaxPushBytes, KeychainID: config.DefaultKeychainID,
		Share: config.OrgClientShareConfig{RoutingSummary: true},
	}
	return f, New(cfg, s, bs, "test-version", http.DefaultClient, quietLogger())
}

// seedRoutingDecision dirties the routing summary's only source table.
func seedRoutingDecision(t *testing.T, s *store.Store, selected string) {
	t.Helper()
	if err := s.InsertRouterDecisions(context.Background(), []store.RouterDecisionRow{{
		SessionID: "s1", Timestamp: time.Now().UTC(), Mode: "advise", Channel: "B",
		OriginalModel: "claude-opus-4-8", SelectedModel: selected, TurnKind: "read_only",
		PolicyHash: "h1", ReasonCodes: []string{"cheap_turn"}, EstSavingsUSD: 0.4, Applied: true,
	}}); err != nil {
		t.Fatalf("InsertRouterDecisions: %v", err)
	}
}

// TestPushOnce_CommitsSnapshotsOnlyOnAcceptance is the commit-on-success
// contract: an ACCEPTED push settles the snapshot families, so an unchanged
// follow-up push recomposes none of them; the cadence throttle is disabled here
// so the assertion isolates the change-detection gate.
func TestPushOnce_CommitsSnapshotsOnlyOnAcceptance(t *testing.T) {
	f, c := newPushGateFixture(t, -1) // -1 = no cadence throttle
	ctx := context.Background()
	seedActivity(t, f.store, 2)
	seedRoutingDecision(t, f.store, "claude-haiku-4-5")

	if _, err := c.PushOnce(ctx); err != nil {
		t.Fatalf("PushOnce (first): %v", err)
	}
	if len(f.envs) != 1 || len(f.envs[0].RoutingSummaries) == 0 {
		t.Fatalf("first push did not carry the routing summary: %d envelopes", len(f.envs))
	}

	// Nothing changed: the batch is empty, so no second request is made at all.
	res, err := c.PushOnce(ctx)
	if err != nil {
		t.Fatalf("PushOnce (second): %v", err)
	}
	if !res.Empty {
		t.Errorf("an unchanged push after an ACCEPTED batch must be empty, got %+v", res)
	}
	if len(f.envs) != 1 {
		t.Errorf("an unchanged push made %d server calls, want 0 more", len(f.envs)-1)
	}

	// Dirty the source: the family recomposes and ships again.
	seedRoutingDecision(t, f.store, "claude-haiku-4-5-next")
	if _, err := c.PushOnce(ctx); err != nil {
		t.Fatalf("PushOnce (third): %v", err)
	}
	if len(f.envs) != 2 {
		t.Fatalf("a dirtied snapshot family did not push: %d envelopes", len(f.envs))
	}
	if len(f.envs[1].RoutingSummaries) == 0 {
		t.Error("the re-pushed envelope carried no routing summary")
	}
}

// TestPushOnce_RejectedBatchLeavesSnapshotsDirty is the other half of the
// contract: a batch the server REJECTED must not settle anything, or the rows
// it never received would be skipped forever.
func TestPushOnce_RejectedBatchLeavesSnapshotsDirty(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}
	var envs []orgcontract.PushEnvelope
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ := io.ReadAll(r.Body)
		env := decodeEnvelope(t, wire)
		envs = append(envs, env)
		if fail {
			writeTestJSON(w, http.StatusInternalServerError, orgcontract.PushResponse{})
			return
		}
		writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{NextCursor: env.CursorTo})
	}))
	defer srv.Close()

	pub := enrolFixture(t, s, bs, srv.URL)
	bindPub(srv, pub)
	seedActivity(t, s, 2)
	seedRoutingDecision(t, s, "claude-haiku-4-5")

	cfg := config.OrgClientConfig{
		Enabled: true, PushIntervalSeconds: config.DefaultPushIntervalSeconds,
		SnapshotIntervalSeconds: -1,
		MaxPushBytes:            config.DefaultMaxPushBytes, KeychainID: config.DefaultKeychainID,
		Share: config.OrgClientShareConfig{RoutingSummary: true},
	}
	c := New(cfg, s, bs, "test-version", http.DefaultClient, quietLogger())

	if _, err := c.PushOnce(context.Background()); err == nil {
		t.Fatal("expected the 500 to surface as a retryable error")
	}
	fail = false
	if _, err := c.PushOnce(context.Background()); err != nil {
		t.Fatalf("PushOnce (retry): %v", err)
	}
	if len(envs) != 2 {
		t.Fatalf("expected a retry push, got %d envelopes", len(envs))
	}
	if len(envs[1].RoutingSummaries) == 0 {
		t.Error("the retry after a REJECTED push shipped no routing summary — a batch the server " +
			"never accepted must never be treated as delivered")
	}
}

// TestPushOnce_SnapshotCadenceHoldsBackDirtyFamilies pins Lever 2 through the
// real loop: with the default cadence installed, a snapshot family that
// genuinely changed still waits out the interval, while the CURSOR wires keep
// shipping on every tick.
func TestPushOnce_SnapshotCadenceHoldsBackDirtyFamilies(t *testing.T) {
	f, c := newPushGateFixture(t, 0) // 0 = default 4x push interval (8 min)
	ctx := context.Background()
	seedActivity(t, f.store, 2)
	seedRoutingDecision(t, f.store, "claude-haiku-4-5")

	if _, err := c.PushOnce(ctx); err != nil {
		t.Fatalf("PushOnce (first): %v", err)
	}
	if len(f.envs[0].RoutingSummaries) == 0 {
		t.Fatal("the first push must not be throttled — a never-delivered family always composes")
	}

	// Dirty BOTH a cursor wire and the snapshot family.
	seedRoutingDecision(t, f.store, "claude-haiku-4-5-next")
	seedActivity(t, f.store, 3)

	if _, err := c.PushOnce(ctx); err != nil {
		t.Fatalf("PushOnce (second): %v", err)
	}
	if len(f.envs) != 2 {
		t.Fatalf("the second push did not reach the server: %d envelopes", len(f.envs))
	}
	if n := len(f.envs[1].Actions); n == 0 {
		t.Error("cursor wires must keep the fast tick — snapshot_interval_seconds governs only " +
			"the snapshot families")
	}
	if n := len(f.envs[1].RoutingSummaries); n != 0 {
		t.Errorf("routing summary composed %d rows inside the snapshot cadence window, want 0", n)
	}
}
