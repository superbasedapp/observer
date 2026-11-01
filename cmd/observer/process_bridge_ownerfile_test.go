//go:build !sbo_omit_processobs

package main

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestProcessBridgeTokenFileIsOwnerOnly (R-160): the process bridge token
// is written owner-only, never with the profile directory's inherited ACL
// on Windows.
func TestProcessBridgeTokenFileIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	var pc config.ProcessConfig
	if tok, err := resolveProcessBridgeListenToken(pc, dir); err != nil || tok == "" {
		t.Fatalf("resolveProcessBridgeListenToken: %q, %v", tok, err)
	}
	mustOwnerOnlyFile(t, filepath.Join(dir, processBridgeTokenFileName))
}
