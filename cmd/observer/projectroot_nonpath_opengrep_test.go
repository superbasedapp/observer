//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/xcodehost"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// TestCodeScanRefusesANonPathRoot (audit row 8, FU-193): the daemon's code
// scan refuses a project root that is not a folder on this host before it
// takes the lease or runs a driver, never resolving it against the working
// directory.
func TestCodeScanRefusesANonPathRoot(t *testing.T) {
	err := runCodeScanOnce(context.Background(), &codeEnv{}, secscan.Target{ProjectRoot: xcodehost.ProjectUnknown})
	if err == nil || !strings.Contains(err.Error(), "not a folder on this host") {
		t.Errorf("runCodeScanOnce = %v", err)
	}
}
