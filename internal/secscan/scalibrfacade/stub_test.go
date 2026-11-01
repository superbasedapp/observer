//go:build sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"context"
	"errors"
	"testing"
)

// TestStubAnswersNotCompiled: the omitted build's API refuses every call,
// so the driver reports "not scanned", never clean.
func TestStubAnswersNotCompiled(t *testing.T) {
	if Compiled {
		t.Fatal("the stub build must say SCALIBR is not compiled")
	}
	if _, err := Extract(context.Background(), t.TempDir(), ExtractOptions{}); !errors.Is(err, ErrNotCompiled) {
		t.Fatalf("Extract: %v", err)
	}
	if _, err := Match(context.Background(), NewInventory(nil), MatchRequest{Ecosystem: "npm"}, MatchOptions{}); !errors.Is(err, ErrNotCompiled) {
		t.Fatalf("Match: %v", err)
	}
}
