//go:build !sbo_omit_org_update

package main

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// TestUpdateRuntimeRemembersTheSandboxDeferral: an apply deferred for live
// sandboxed runs is remembered (the question reads it; the posture reason
// stays deferred_live_sandbox), a dry run changes nothing, any settled
// outcome forgets it, and the runtime installs the question's hooks.
func TestUpdateRuntimeRemembersTheSandboxDeferral(t *testing.T) {
	saved := updateLiveDeferredHook.Load()
	t.Cleanup(func() { updateLiveDeferredHook.Store(saved) })
	cfg := config.Default()
	cfg.Update.Enabled = true
	u := newUpdateRuntime(cfg, "", store.New(nil), nil, fakeSandboxManager{live: 1}, nil)
	if h := updateLiveDeferredHook.Load(); h == nil || h.pending() {
		t.Fatalf("hooks = %v, want installed and not pending", h)
	}
	req := updateApplyRequest{Version: "1.2.3"}
	deferred := applyOutcome{State: update.StateAvailable, Reason: update.ReasonDeferredLiveSandbox, Deferred: true}
	u.noteLiveDeferral(updateApplyRequest{DryRun: true}, deferred)
	if u.liveDeferredPending() {
		t.Fatal("a dry run was remembered")
	}
	u.noteLiveDeferral(req, deferred)
	if !updateLiveDeferredHook.Load().pending() || u.liveDeferred.Load().Version != "1.2.3" {
		t.Fatal("the sandbox deferral was not remembered")
	}
	u.noteLiveDeferral(req, applyOutcome{State: update.StateAvailable, Reason: update.ReasonWindow, Deferred: true})
	if u.liveDeferredPending() {
		t.Fatal("a deferral for another reason kept the sandbox question")
	}
	u.noteLiveDeferral(req, deferred)
	u.noteLiveDeferral(req, applyOutcome{})
	if !u.liveDeferredPending() {
		t.Fatal("an outcome with no state (nothing ran) forgot the deferral")
	}
	u.liveDeferred.Store(nil)
	if err := u.applyLiveDeferred(context.Background()); err == nil {
		t.Fatal("applyLiveDeferred with nothing deferred succeeded")
	}
}
