//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secask"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

// TestDepsAskSkewKeepsOfflineAnswer pins lane SEC-DEPS3 item 11: a daemon
// that did not understand the ask (an older one, left running across an
// upgrade) leaves the hook with the same answer as no ask at all, never an
// ask failure (online_unknown, S-748 under enforce); any other error still
// reads as a failed ask.
func TestDepsAskSkewKeepsOfflineAnswer(t *testing.T) {
	specs := []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "left-pad@1.3.0")}
	public := func(secfeed.InstallSpec) bool { return true }
	gate := func(ask secfeed.Asker) policy.InstallVerdict {
		checks := secfeed.Gate(context.Background(), secfeed.GateInput{Specs: specs, Public: public, Ask: ask, MinAge: depsDefaultMinAge, Now: time.Now()})
		if len(checks) != 1 {
			t.Fatalf("checks %+v", checks)
		}
		return checks[0].Verdict
	}
	offline := gate(nil)
	skew := gate(func(_ context.Context, s []secfeed.InstallSpec) ([]secfeed.OnlineAnswer, error) {
		return depsAskOrOffline(nil, secask.ErrNotUnderstood)(s)
	})
	if skew != offline || skew == policy.InstallOnlineUnknown {
		t.Fatalf("a stale daemon: verdict %q, want the offline %q", skew, offline)
	}
	failed := gate(func(_ context.Context, s []secfeed.InstallSpec) ([]secfeed.OnlineAnswer, error) {
		return depsAskOrOffline(nil, errors.New("daemon down"))(s)
	})
	if failed != policy.InstallOnlineUnknown {
		t.Fatalf("a failed ask stays online_unknown, got %q", failed)
	}
}
