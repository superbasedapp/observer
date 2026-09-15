package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// Wave C, gap 2.4 residuals (a) "session idle + rolling refresh" and (b)
// "sign out everywhere" (docs/handovers/next-session-kickoff-2026-09-12-
// paddle-signin-production.md §2.4). Operator ruling 2026-09-11: 24h absolute
// expiry, 2h idle with rolling refresh on authenticated activity.

// --- (a) idle timeout + rolling refresh -------------------------------------

// TestS10_IdleExpiryRefuses pins the idle half of the model on its own: a
// session well inside its 24h absolute window is refused once its SHORTER
// idle window has lapsed.
func TestS10_IdleExpiryRefuses(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	sub := fmt.Sprintf("idle-expires-%d", subjCounter.Add(1))

	sess, err := s.PortalLogin(ctx, "dev", sub, 24*time.Hour, now, store.WithIdleTTL(10*time.Minute))
	if err != nil {
		t.Fatalf("PortalLogin: %v", err)
	}

	// Just inside the idle window: still valid.
	if bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now.Add(5*time.Minute), store.WithIdleTTL(10*time.Minute)); err != nil || !bp.Valid {
		t.Fatalf("introspect within idle window: valid=%v err=%v, want valid", bp.Valid, err)
	}
	// Past the idle window, but nowhere near the 24h absolute one: refused.
	bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now.Add(15*time.Minute), store.WithIdleTTL(10*time.Minute))
	if err != nil {
		t.Fatalf("IntrospectBrowserSession: %v", err)
	}
	if bp.Valid {
		t.Fatal("session past its idle window was reported valid")
	}
}

// TestS10_ActivityExtendsIdle pins the rolling-refresh half: a successful
// introspection rolls idle_expires_at forward, so a session that would
// otherwise have gone idle stays alive because it was USED in between.
func TestS10_ActivityExtendsIdle(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	sub := fmt.Sprintf("idle-extends-%d", subjCounter.Add(1))

	sess, err := s.PortalLogin(ctx, "dev", sub, 24*time.Hour, now, store.WithIdleTTL(10*time.Minute))
	if err != nil {
		t.Fatalf("PortalLogin: %v", err)
	}

	// Use it at +8m (inside the 10m idle window ⇒ valid, and the introspection
	// itself rolls the boundary forward another 10m from +8m ⇒ ~+18m).
	if bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now.Add(8*time.Minute), store.WithIdleTTL(10*time.Minute)); err != nil || !bp.Valid {
		t.Fatalf("introspect at +8m: valid=%v err=%v, want valid", bp.Valid, err)
	}
	// +16m is PAST the ORIGINAL +10m idle boundary, but the roll at +8m pushed
	// it out to ~+18m — so this must still be valid. Without the roll this
	// would be refused, which is exactly the defect this test pins.
	bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now.Add(16*time.Minute), store.WithIdleTTL(10*time.Minute))
	if err != nil {
		t.Fatalf("IntrospectBrowserSession at +16m: %v", err)
	}
	if !bp.Valid {
		t.Fatal("activity between +0 and +16m should have rolled the idle boundary forward, but the session was refused")
	}
}

// TestS10_IdleNeverExceedsAbsolute pins the "absolute boundary always wins"
// rule: an idle TTL configured LONGER than the remaining absolute lifetime
// must never let the idle roll push a session past its own expires_at.
func TestS10_IdleNeverExceedsAbsolute(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	sub := fmt.Sprintf("idle-capped-%d", subjCounter.Add(1))

	// A short absolute TTL (20 minutes) with a much longer idle TTL (2h): the
	// idle boundary minted at PortalLogin must be capped at expires_at, not at
	// now+2h.
	sess, err := s.PortalLogin(ctx, "dev", sub, 20*time.Minute, now, store.WithIdleTTL(2*time.Hour))
	if err != nil {
		t.Fatalf("PortalLogin: %v", err)
	}
	if !sess.ExpiresAt.Before(now.Add(21 * time.Minute)) {
		t.Fatalf("ExpiresAt=%v, want ~now+20m", sess.ExpiresAt)
	}

	// At +10m (inside BOTH the absolute and idle windows as configured, and the
	// idle roll here would also try to push out to +10m+2h) the session must
	// still be refused once past the 20m absolute boundary — never granted the
	// full 2h idle window.
	bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now.Add(10*time.Minute), store.WithIdleTTL(2*time.Hour))
	if err != nil {
		t.Fatalf("introspect at +10m: %v", err)
	}
	if !bp.Valid {
		t.Fatal("session at +10m (inside its 20m absolute window) was refused")
	}
	// Past the 20-minute absolute boundary: refused, regardless of the 2h idle
	// TTL and regardless of the roll at +10m (which the store must have capped
	// at expires_at, not extended to +10m+2h).
	bp, err = s.IntrospectBrowserSession(ctx, sess.RawSession, now.Add(25*time.Minute), store.WithIdleTTL(2*time.Hour))
	if err != nil {
		t.Fatalf("introspect at +25m: %v", err)
	}
	if bp.Valid {
		t.Fatal("session past its 20m ABSOLUTE boundary was still valid — the idle roll must never extend past expires_at")
	}
}

// TestS10_AbsoluteStillWinsEvenWithConstantActivity is the inverse of
// TestS10_ActivityExtendsIdle: continuous activity (which keeps rolling the
// idle boundary forward indefinitely) must NEVER keep a session alive past its
// fixed absolute expires_at.
func TestS10_AbsoluteStillWinsEvenWithConstantActivity(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	sub := fmt.Sprintf("idle-absolute-wins-%d", subjCounter.Add(1))

	sess, err := s.PortalLogin(ctx, "dev", sub, 30*time.Minute, now, store.WithIdleTTL(10*time.Minute))
	if err != nil {
		t.Fatalf("PortalLogin: %v", err)
	}

	// "Use" the session every 6 minutes (well inside its 10m idle window each
	// time) for 24 minutes — constant activity that would keep an idle-only
	// model alive forever.
	for _, offset := range []time.Duration{6 * time.Minute, 12 * time.Minute, 18 * time.Minute, 24 * time.Minute} {
		bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now.Add(offset), store.WithIdleTTL(10*time.Minute))
		if err != nil {
			t.Fatalf("introspect at +%v: %v", offset, err)
		}
		if !bp.Valid {
			t.Fatalf("introspect at +%v (inside the absolute window, active every 6m): got invalid", offset)
		}
	}
	// Past the 30m absolute boundary: refused, even though the session was
	// "used" as recently as +24m (6 minutes prior, well inside any idle
	// window).
	bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now.Add(31*time.Minute), store.WithIdleTTL(10*time.Minute))
	if err != nil {
		t.Fatalf("introspect at +31m: %v", err)
	}
	if bp.Valid {
		t.Fatal("constant activity kept a session alive past its fixed absolute expires_at")
	}
}

// TestS10_IntrospectNullIdleBoundaryDoesNotRefuse pins the migration-safety
// property in the 0035 header comment: a row with idle_expires_at still NULL
// (simulated here by never rolling — a fresh row from PortalLogin always sets
// it, so this drives the store's introspection path directly through the raw
// pool the way deletion_w6d_test.go resets status) must be judged on the
// absolute boundary alone, not refused for want of an idle value.
func TestS10_IntrospectNullIdleBoundaryDoesNotRefuse(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	sub := fmt.Sprintf("idle-null-%d", subjCounter.Add(1))

	sess, err := s.PortalLogin(ctx, "dev", sub, time.Hour, now, store.WithIdleTTL(time.Minute))
	if err != nil {
		t.Fatalf("PortalLogin: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE browser_sessions SET idle_expires_at = NULL, last_seen_at = NULL WHERE account_id = $1::uuid`,
		sess.AccountID); err != nil {
		t.Fatalf("force NULL idle columns: %v", err)
	}

	// Well past the 1-minute idle TTL this session WOULD have had, but the row
	// now carries no idle boundary at all: it must still be valid on the
	// absolute (1h) boundary alone.
	bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now.Add(5*time.Minute), store.WithIdleTTL(time.Minute))
	if err != nil {
		t.Fatalf("introspect with NULL idle columns: %v", err)
	}
	if !bp.Valid {
		t.Fatal("a NULL idle boundary refused an otherwise-valid session — it must be treated as \"not yet observed\", not refused")
	}
}

// --- (b) sign out everywhere -------------------------------------------------

// TestS10_ListBrowserSessionsShowsLiveSessions pins the read half: two
// sign-ins for the same identity (two browsers/devices) both show up, newest
// first, and a revoked one drops out of the list.
func TestS10_ListBrowserSessionsShowsLiveSessions(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	sub := fmt.Sprintf("list-sessions-%d", subjCounter.Add(1))

	first, err := s.PortalLogin(ctx, "dev", sub, 0, now)
	if err != nil {
		t.Fatalf("PortalLogin (first): %v", err)
	}
	second, err := s.PortalLogin(ctx, "dev", sub, 0, now.Add(time.Second))
	if err != nil {
		t.Fatalf("PortalLogin (second): %v", err)
	}
	if first.AccountID != second.AccountID {
		t.Fatalf("same subject resolved to two accounts: %s vs %s", first.AccountID, second.AccountID)
	}

	list, err := s.ListBrowserSessions(ctx, first.AccountID)
	if err != nil {
		t.Fatalf("ListBrowserSessions: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d sessions, want 2", len(list))
	}
	// Newest first.
	if list[0].CreatedAt.Before(list[1].CreatedAt) {
		t.Fatal("sessions not ordered newest-first")
	}

	if err := s.RevokeBrowserSession(ctx, first.AccountID, first.RawSession, now.Add(2*time.Second)); err != nil {
		t.Fatalf("RevokeBrowserSession: %v", err)
	}
	list, err = s.ListBrowserSessions(ctx, first.AccountID)
	if err != nil {
		t.Fatalf("ListBrowserSessions after revoke: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d sessions after revoking one, want 1", len(list))
	}
	if list[0].ID == "" {
		t.Fatal("remaining session row carries no id")
	}
}

// TestS10_RevokeAllBrowserSessionsKeepCurrent pins the "everywhere but here"
// shape: revoking all-except one raw session leaves exactly that one valid and
// kills every other one, cleanly separated from a plain revoke-all (no
// exception) which kills all of them including the caller's own.
func TestS10_RevokeAllBrowserSessionsKeepCurrent(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	sub := fmt.Sprintf("revoke-all-keep-%d", subjCounter.Add(1))

	a, err := s.PortalLogin(ctx, "dev", sub, 0, now)
	if err != nil {
		t.Fatalf("PortalLogin (a): %v", err)
	}
	b, err := s.PortalLogin(ctx, "dev", sub, 0, now.Add(time.Second))
	if err != nil {
		t.Fatalf("PortalLogin (b): %v", err)
	}
	c, err := s.PortalLogin(ctx, "dev", sub, 0, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("PortalLogin (c): %v", err)
	}

	n, err := s.RevokeAllBrowserSessions(ctx, a.AccountID, b.RawSession, now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("RevokeAllBrowserSessions: %v", err)
	}
	if n != 2 {
		t.Fatalf("revoked=%d, want 2 (a and c, keeping b)", n)
	}

	if valid := introspectValid(t, s, a.RawSession, now.Add(3*time.Second)); valid {
		t.Fatal("session a still valid after revoke-all-keep-b")
	}
	if valid := introspectValid(t, s, c.RawSession, now.Add(3*time.Second)); valid {
		t.Fatal("session c still valid after revoke-all-keep-b")
	}
	if valid := introspectValid(t, s, b.RawSession, now.Add(3*time.Second)); !valid {
		t.Fatal("session b (the kept one) was revoked")
	}

	list, err := s.ListBrowserSessions(ctx, a.AccountID)
	if err != nil {
		t.Fatalf("ListBrowserSessions: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d live sessions after revoke-all-keep-b, want 1", len(list))
	}
}

// TestS10_RevokeAllBrowserSessionsNoException pins the plain "sign out
// everywhere including this tab" shape: an empty exceptRawSession kills every
// live session on the account.
func TestS10_RevokeAllBrowserSessionsNoException(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	sub := fmt.Sprintf("revoke-all-none-%d", subjCounter.Add(1))

	a, err := s.PortalLogin(ctx, "dev", sub, 0, now)
	if err != nil {
		t.Fatalf("PortalLogin (a): %v", err)
	}
	b, err := s.PortalLogin(ctx, "dev", sub, 0, now.Add(time.Second))
	if err != nil {
		t.Fatalf("PortalLogin (b): %v", err)
	}

	n, err := s.RevokeAllBrowserSessions(ctx, a.AccountID, "", now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("RevokeAllBrowserSessions: %v", err)
	}
	if n != 2 {
		t.Fatalf("revoked=%d, want 2", n)
	}
	for _, raw := range []string{a.RawSession, b.RawSession} {
		if introspectValid(t, s, raw, now.Add(2*time.Second)) {
			t.Fatal("a session survived a no-exception revoke-all")
		}
	}
}

// TestS10_CrossAccountCannotListOrRevokeBrowserSessions pins tenant isolation
// on the new sessions surface, the same shape TestS10_CrossAccountRepositoryIsolation
// already pins for tokens/devices: account B's scope may never touch account
// A's sessions.
func TestS10_CrossAccountCannotListOrRevokeBrowserSessions(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	victim, err := s.PortalLogin(ctx, "dev", fmt.Sprintf("cross-victim-%d", subjCounter.Add(1)), 0, now)
	if err != nil {
		t.Fatalf("PortalLogin (victim): %v", err)
	}
	attacker, err := s.PortalLogin(ctx, "dev", fmt.Sprintf("cross-attacker-%d", subjCounter.Add(1)), 0, now)
	if err != nil {
		t.Fatalf("PortalLogin (attacker): %v", err)
	}

	// Listing under the ATTACKER's scope must show exactly the attacker's own
	// session — never the victim's (RLS scopes the SELECT to the tenant
	// context, so a leaked row would show up as a second entry here).
	list, err := s.ListBrowserSessions(ctx, attacker.AccountID)
	if err != nil {
		t.Fatalf("ListBrowserSessions (attacker): %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("attacker's session list has %d rows, want exactly 1 (its own; a leaked victim row would make this 2)", len(list))
	}

	// Revoke-all under the attacker's scope must be a no-op against the
	// victim's session (RLS confines the UPDATE to the attacker's own tenant
	// context; there is nothing to revoke there).
	n, err := s.RevokeAllBrowserSessions(ctx, attacker.AccountID, "", now.Add(time.Second))
	if err != nil {
		t.Fatalf("RevokeAllBrowserSessions (attacker): %v", err)
	}
	if n != 1 {
		t.Fatalf("attacker revoke-all affected %d rows, want 1 (only the attacker's own)", n)
	}
	if !introspectValid(t, s, victim.RawSession, now.Add(time.Second)) {
		t.Fatal("cross-account RevokeAllBrowserSessions killed the victim's session")
	}
}

// introspectValid is a small local wrapper mirroring portalSessionValid in
// s10_lifecycle_d18_test.go (kept separate to avoid a cross-file rename in a
// file outside this wave's footprint).
func introspectValid(t *testing.T, s *store.Store, raw string, now time.Time) bool {
	t.Helper()
	bp, err := s.IntrospectBrowserSession(context.Background(), raw, now)
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		t.Fatalf("IntrospectBrowserSession: %v", err)
	}
	return bp.Valid
}
