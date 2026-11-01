//go:build sbo_omit_security_scan_scalibr

package scalibrchild

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// TestRunWithoutSCALIBR answers Compiled false and scans nothing.
func TestRunWithoutSCALIBR(t *testing.T) {
	resp := Run(context.Background(), depscan.ChildRequest{Version: depscan.ProtocolVersion, Root: t.TempDir()}, nil)
	if resp.Compiled || len(resp.Ecosystems) != 0 || resp.Error != "" {
		t.Fatalf("resp %+v", resp)
	}
}
