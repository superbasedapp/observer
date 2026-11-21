package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// browsersession_authtime_test.go: the portal session's authentication time
// (cloud 0083; the platform OIDC issuer's auth_time). Only a sign-in that was
// a fresh authentication records one; an ordinary sign-in, which AuthKit may
// have answered from its own session, records none; nothing that reuses the
// session moves it. Postgres-backed (cloudtestpg; SKIPPED loudly without
// SBCI_TEST_PG_DSN).

func TestBrowserSessionAuthTime(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	cases := []struct {
		name string
		opts []store.PortalLoginOption
		want time.Time
	}{
		{"ordinary sign-in: not known", nil, time.Time{}},
		{"fresh authentication: the sign-in time", []store.PortalLoginOption{store.WithFreshAuthentication()}, now},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub := fmt.Sprintf("authtime-%d", subjCounter.Add(1))
			sess, err := s.PortalLogin(ctx, "dev", sub, 24*time.Hour, now, tc.opts...)
			if err != nil {
				t.Fatalf("PortalLogin: %v", err)
			}
			bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now)
			if err != nil || !bp.Valid {
				t.Fatalf("introspect: valid=%v err=%v", bp.Valid, err)
			}
			got, err := s.BrowserSessionAuthTime(ctx, bp.AccountID, bp.SessionID)
			if err != nil || !got.Equal(tc.want) {
				t.Fatalf("BrowserSessionAuthTime = %v, %v; want %v", got, err, tc.want)
			}

			// Reusing the session does not move it: a later introspection
			// that rolls the idle boundary, and a CSRF rotation.
			later := now.Add(20 * time.Minute)
			if bp2, err := s.IntrospectBrowserSession(ctx, sess.RawSession, later); err != nil || !bp2.Valid {
				t.Fatalf("later introspect: valid=%v err=%v", bp2.Valid, err)
			}
			if _, err := s.RotateBrowserCSRF(ctx, bp.AccountID, sess.RawSession, later); err != nil {
				t.Fatalf("RotateBrowserCSRF: %v", err)
			}
			if got, err := s.BrowserSessionAuthTime(ctx, bp.AccountID, bp.SessionID); err != nil || !got.Equal(tc.want) {
				t.Fatalf("after reuse = %v, %v; want %v unchanged", got, err, tc.want)
			}

			// Revoked: not found, whatever it recorded.
			if err := s.RevokeBrowserSession(ctx, bp.AccountID, sess.RawSession, later); err != nil {
				t.Fatalf("RevokeBrowserSession: %v", err)
			}
			if _, err := s.BrowserSessionAuthTime(ctx, bp.AccountID, bp.SessionID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("revoked session err = %v, want ErrNotFound", err)
			}
		})
	}

	// An unknown session id, and another account's session, are not found.
	sess, err := s.PortalLogin(ctx, "dev", fmt.Sprintf("authtime-other-%d", subjCounter.Add(1)), 24*time.Hour, now,
		store.WithFreshAuthentication())
	if err != nil {
		t.Fatalf("PortalLogin: %v", err)
	}
	bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now)
	if err != nil || !bp.Valid {
		t.Fatalf("introspect: valid=%v err=%v", bp.Valid, err)
	}
	if _, err := s.BrowserSessionAuthTime(ctx, bp.AccountID, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown session err = %v, want ErrNotFound", err)
	}
	other, err := s.PortalLogin(ctx, "dev", fmt.Sprintf("authtime-stranger-%d", subjCounter.Add(1)), 24*time.Hour, now)
	if err != nil {
		t.Fatalf("PortalLogin: %v", err)
	}
	if _, err := s.BrowserSessionAuthTime(ctx, other.AccountID, bp.SessionID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another account's session err = %v, want ErrNotFound (row-level security)", err)
	}
}

// TestAuthTransactionForceReauthRoundTrip: whether the AuthKit start forced a
// fresh authentication is recorded server-side and comes back at the callback.
func TestAuthTransactionForceReauthRoundTrip(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	for _, force := range []bool{false, true} {
		stateHash := hashOf(fmt.Sprintf("state-force-%v", force))
		in := loginTxn(stateHash, now)
		in.ForceReauth = force
		if _, err := s.CreateAuthTransaction(ctx, in); err != nil {
			t.Fatalf("CreateAuthTransaction(force=%v): %v", force, err)
		}
		txn, err := s.ConsumeAuthTransaction(ctx, stateHash, now)
		if err != nil {
			t.Fatalf("ConsumeAuthTransaction(force=%v): %v", force, err)
		}
		if txn.ForceReauth != force {
			t.Errorf("ForceReauth = %v, want %v", txn.ForceReauth, force)
		}
	}
}
