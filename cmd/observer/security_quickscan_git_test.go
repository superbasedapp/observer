//go:build !sbo_omit_security

package main

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/gitview"
)

// TestSecurityQuickScanEngineNeverLazyFetches pins RB1 sweep finding
// SECP-39: the quick scan's git runner is the envelope that never fetches a
// missing object in a partial clone (a fetch runs the repository's own
// transport configuration), not the plain read-only runner.
func TestSecurityQuickScanEngineNeverLazyFetches(t *testing.T) {
	e := newSecurityQuickScanEngine(nil)
	if e.Git == nil {
		t.Fatal("the quick scan engine has no git runner")
	}
	if got, want := reflect.ValueOf(e.Git).Pointer(), reflect.ValueOf(gitview.RunReadOnlyNoLazyFetch).Pointer(); got != want {
		t.Fatal("the quick scan engine's git runner is not gitview.RunReadOnlyNoLazyFetch")
	}
}
