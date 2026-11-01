package main

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
)

// TestHookContextSameFactsAsBefore: the parent id and ancestry the
// pid-bridge seeds and the lifecycle handler now read through the hook
// context seam are what they passed before it (os.Getppid and
// defaultAncestors), with and without an attached context, and an
// attached context wins.
func TestHookContextSameFactsAsBefore(t *testing.T) {
	ppid := os.Getppid()
	want := defaultAncestors(ppid)
	attached := hookctx.Host(context.Background(), hookctx.Request{Tool: "claude-code"}, hostHookSource(), hostHookProviders(""))
	for name, c := range map[string]*hookctx.Context{
		"unattached": hookContext(context.Background()),
		"attached":   hookContext(hookctx.WithContext(context.Background(), attached)),
	} {
		if got := c.ParentPID(); got != ppid {
			t.Errorf("%s: ParentPID = %d, want %d", name, got, ppid)
		}
		if got := c.Ancestors(ppid); !slices.Equal(got, want) {
			t.Errorf("%s: Ancestors = %v, want %v", name, got, want)
		}
	}
	if hookContext(hookctx.WithContext(context.Background(), attached)) != attached {
		t.Error("hookContext did not return the attached context")
	}
	deps := productionLifecycleDeps(hookctx.WithContext(context.Background(), attached))
	if deps.parentPID != ppid || !slices.Equal(deps.ancestors(ppid), want) {
		t.Errorf("productionLifecycleDeps = pid %d, ancestors %v", deps.parentPID, deps.ancestors(ppid))
	}
	// The security providers are wired exactly when the security module
	// is compiled in (hook_security.go and its omit twin).
	wired := !slices.Contains(components.Omitted(), "security")
	if p := hostHookProviders(""); (p.Sidecar != nil) != wired || (p.Dirty != nil) != wired || (p.QuickScan != nil) != wired {
		t.Errorf("security host providers wired = %v, %v, %v; want %v", p.Sidecar != nil, p.Dirty != nil, p.QuickScan != nil, wired)
	}
}
