//go:build !sbo_omit_security

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestPrintSecurityStatusShortHash: a project hash shorter than the
// 12-character prefix prints whole instead of panicking (audit P-002
// finding 10).
func TestPrintSecurityStatusShortHash(t *testing.T) {
	var b bytes.Buffer
	printSecurityStatus(&b, securityStatusReport{Module: "active", RulePack: "x", Projects: []securityProjectState{
		{ProjectRootHash: "abc", State: "unknown", Reason: "posture_missing"},
		{ProjectRootHash: strings.Repeat("f", 64), State: "blocking", Reason: "blocking_findings", Blocking: 2},
	}})
	out := b.String()
	if !strings.Contains(out, "  abc  unknown") || !strings.Contains(out, "  ffffffffffff  blocking (blocking_findings), 2 blocking") {
		t.Fatalf("status text:\n%s", out)
	}
}

// TestSecurityDirtyDetail: doctor's dirty-marker line for a missing
// directory, a healthy one and one with an unreadable marker.
func TestSecurityDirtyDetail(t *testing.T) {
	l := secposture.Layout{Dir: filepath.Join(t.TempDir(), secposture.DirName)}
	now := time.Now()
	if line, warn := securityDirtyDetail(l, now); warn || !strings.Contains(line, "none yet") {
		t.Fatalf("missing: %q %v", line, warn)
	}
	if err := secposture.RaiseDirty(l, secposture.ProjectRootHash("/p")); err != nil {
		t.Fatal(err)
	}
	if line, warn := securityDirtyDetail(l, now); warn || line != "dirty markers: 1 (1 raised in the last 24 h)" {
		t.Fatalf("healthy: %q %v", line, warn)
	}
	if err := os.Mkdir(l.DirtyPath(secposture.ProjectRootHash("/q")), 0o700); err != nil {
		t.Fatal(err)
	}
	if line, warn := securityDirtyDetail(l, now); !warn || !strings.Contains(line, "1 not a readable counter") {
		t.Fatalf("unreadable: %q %v", line, warn)
	}
}
