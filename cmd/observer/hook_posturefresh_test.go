package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
)

const (
	freshGuardObserve = "[guard]\nenabled = true\nmode = \"observe\"\n"
	freshGuardEnforce = "[guard]\nenabled = true\nmode = \"enforce\"\n"
)

// TestStalePostureDoesNotKeepBlocking reproduces T-050: the daemon signed an
// ENFORCED posture, then stopped; enforcement was turned off in the config
// afterwards. Before the fix the valid signature alone kept every gate hook
// failure closed until a daemon republished. A posture older than the config
// file, or past its freshness window, is now ignored and the answer comes
// from the config (+ signed bundle); a fresh posture is still authoritative.
func TestStalePostureDoesNotKeepBlocking(t *testing.T) {
	// The hook reads the org bundle under the home; the process temp home's
	// .observer is a file (FU-20), which reads as an unverifiable org layer.
	pinToolHomes(t)
	setup := func(t *testing.T, cfg string, postureAt, configAt time.Time) string {
		t.Helper()
		cp := filepath.Join(t.TempDir(), "config.toml")
		writeFileT(t, cp, cfg)
		p := enforcedPosture
		p.WrittenAt = postureAt
		writePosture(t, cp, p)
		if err := os.Chtimes(cp, configAt, configAt); err != nil {
			t.Fatal(err)
		}
		return cp
	}
	now := time.Now()
	for _, tc := range []struct {
		name               string
		cfg                string
		postureAt, cfgAt   time.Time
		wantToolGateClosed bool
	}{
		// The T-050 scenario: enforcement turned off after the daemon wrote
		// (and stopped writing) its posture.
		{"enforcement turned off after the posture: open", freshGuardObserve, now.Add(-30 * time.Second), now.Add(-5 * time.Second), false},
		// The daemon is gone and nothing changed: the posture expires, the
		// derivation still says enforced, so failures still block.
		{"expired posture, config still enforces: closed", freshGuardEnforce, now.Add(-10 * time.Minute), now.Add(-time.Hour), true},
		{"expired posture, config observes: open", freshGuardObserve, now.Add(-10 * time.Minute), now.Add(-time.Hour), false},
		// A fresh posture newer than the config stays authoritative (e.g. an
		// org bundle enforces what the local config does not).
		{"fresh posture newer than the config: closed", freshGuardObserve, now.Add(-30 * time.Second), now.Add(-time.Hour), true},
		{"posture from the future: ignored", freshGuardObserve, now.Add(10 * time.Minute), now.Add(-time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := setup(t, tc.cfg, tc.postureAt, tc.cfgAt)
			if ld := guardposture.Load(guardposture.PosturePath(cp), guardposture.KeyPath(cp)); ld.State != guardposture.StateValid {
				t.Fatalf("setup: posture state %s (%s), want a validly signed one", ld.State, ld.Detail)
			}
			if got := resolveHookFailurePlan("claude-code", "pre-tool", cp).FailClosed; got != tc.wantToolGateClosed {
				t.Errorf("tool gate FailClosed = %v, want %v", got, tc.wantToolGateClosed)
			}
		})
	}
}

// TestStaleUserPolicyFailClosedPostureDoesNotBlock pins the Integration 6
// merge of feat/org-guard-fallbacks onto T-050: hookPostureFailsClosed now
// returns the fallbacks answer (hookPostureAnswer), and a stale, future-dated
// or older-than-config posture carrying user_policy_fail_closed must still be
// ignored, so hookUserPolicyGate (which returns at once when the plan's
// UserPolicyFailClosed is false) does not block every gated call on it. The
// config here enforces the gate but has no org fail_closed choice, so only a
// fresh posture may close the gate on an invalid user policy (D-208).
func TestStaleUserPolicyFailClosedPostureDoesNotBlock(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name             string
		postureAt, cfgAt time.Time
		wantUserPolicy   bool
	}{
		{"posture older than the config: ignored", now.Add(-30 * time.Second), now.Add(-5 * time.Second), false},
		{"expired posture: ignored", now.Add(-10 * time.Minute), now.Add(-time.Hour), false},
		{"posture from the future: ignored", now.Add(10 * time.Minute), now.Add(-time.Hour), false},
		{"fresh posture newer than the config: applies", now.Add(-30 * time.Second), now.Add(-time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := filepath.Join(t.TempDir(), "config.toml")
			writeFileT(t, cp, freshGuardEnforce)
			p := enforcedPosture
			p.UserPolicyFailClosed = true
			p.WrittenAt = tc.postureAt
			writePosture(t, cp, p)
			if err := os.Chtimes(cp, tc.cfgAt, tc.cfgAt); err != nil {
				t.Fatal(err)
			}
			if ld := guardposture.Load(guardposture.PosturePath(cp), guardposture.KeyPath(cp)); ld.State != guardposture.StateValid {
				t.Fatalf("setup: posture state %s (%s), want a validly signed one", ld.State, ld.Detail)
			}
			plan := resolveHookFailurePlan("claude-code", "pre-tool", cp)
			if !plan.FailClosed {
				t.Fatalf("tool gate FailClosed = false; the config enforces it")
			}
			if plan.UserPolicyFailClosed != tc.wantUserPolicy {
				t.Errorf("UserPolicyFailClosed = %v, want %v", plan.UserPolicyFailClosed, tc.wantUserPolicy)
			}
		})
	}
}

// TestGuardPostureWriterHeartbeat: an unchanged posture is re-signed once it
// is RefreshInterval old (so readers can tell a running daemon), without
// reporting a change; inside the interval it is left alone.
func TestGuardPostureWriterHeartbeat(t *testing.T) {
	cp := filepath.Join(t.TempDir(), "config.toml")
	w := &guardPostureWriter{}
	t0 := time.Unix(1_000_000, 0).UTC()
	p := guardposture.Posture{Enforced: true, Source: "local", GateCaps: []string{"tool_gate"}, WrittenAt: t0}
	if changed, err := w.publish(cp, p); err != nil || !changed {
		t.Fatalf("first publish = %v, %v", changed, err)
	}
	readAt := func() time.Time {
		got, err := guardposture.Read(guardposture.PosturePath(cp))
		if err != nil || got == nil {
			t.Fatalf("read: %v", err)
		}
		return got.WrittenAt
	}
	p.WrittenAt = t0.Add(guardposture.RefreshInterval / 2)
	if changed, _ := w.publish(cp, p); changed || !readAt().Equal(t0) {
		t.Errorf("inside the interval: changed=%v written_at=%v, want untouched", changed, readAt())
	}
	p.WrittenAt = t0.Add(guardposture.RefreshInterval)
	if changed, err := w.publish(cp, p); err != nil || changed {
		t.Errorf("heartbeat reported changed=%v err=%v, want a silent re-sign", changed, err)
	}
	if !readAt().Equal(p.WrittenAt) {
		t.Errorf("heartbeat did not re-sign: written_at=%v want %v", readAt(), p.WrittenAt)
	}
	if ld := guardposture.Load(guardposture.PosturePath(cp), guardposture.KeyPath(cp)); ld.State != guardposture.StateValid {
		t.Errorf("heartbeat posture state %s", ld.State)
	}
	// requestRefresh forces the next publish to re-sign at once.
	w.requestRefresh()
	p.WrittenAt = p.WrittenAt.Add(time.Second)
	if _, err := w.publish(cp, p); err != nil || !readAt().Equal(p.WrittenAt) {
		t.Errorf("requested refresh did not re-sign: %v %v", readAt(), err)
	}
}

// TestPostureConfigWatch: the daemon keeps publishing (re-signed) when the
// config file changes without touching [guard], and stops when [guard]
// changed, until restart.
func TestPostureConfigWatch(t *testing.T) {
	cp := filepath.Join(t.TempDir(), "config.toml")
	writeFileT(t, cp, freshGuardEnforce)
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cp})
	if err != nil {
		t.Fatal(err)
	}
	watch := &postureConfigWatch{path: cp, configPath: cp, guard: cfg.Guard, mod: fileModTime(cp)}
	logger := newLogger("error")
	if got := watch.check(logger); got != postureConfigCurrent {
		t.Fatalf("unchanged file = %v", got)
	}
	bump := func() {
		t.Helper()
		at := time.Now().Add(time.Minute)
		if err := os.Chtimes(cp, at, at); err != nil {
			t.Fatal(err)
		}
	}
	writeFileT(t, cp, freshGuardEnforce+"\n[observer]\nlog_level = \"debug\"\n")
	bump()
	if got := watch.check(logger); got != postureConfigTouched {
		t.Fatalf("non-guard edit = %v, want touched", got)
	}
	if got := watch.check(logger); got != postureConfigCurrent {
		t.Fatalf("after a touched edit = %v, want current", got)
	}
	writeFileT(t, cp, freshGuardObserve)
	at := time.Now().Add(time.Hour)
	if err := os.Chtimes(cp, at, at); err != nil {
		t.Fatal(err)
	}
	if got := watch.check(logger); got != postureConfigGuardChanged {
		t.Fatalf("guard edit = %v, want guard-changed", got)
	}
}
