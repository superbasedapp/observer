//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestHostedKeeperKeyFile (SBX-UPD audit finding 2): the keeper key is kept
// at home owner-only beside the per-box secrets, never in the box record, and
// reads back; a damaged or missing file reads as an error.
func TestHostedKeeperKeyFile(t *testing.T) {
	obs := t.TempDir()
	key := bytes.Repeat([]byte{3}, 32)
	if err := hostedSaveKeeperKey(obs, "run-k", key); err != nil {
		t.Fatal(err)
	}
	p := hostedKeeperKeyPath(obs, "run-k")
	if filepath.Dir(p) != hostedSecretsDir(obs) {
		t.Fatalf("the key is kept at %s", p)
	}
	if fi, err := os.Stat(p); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("key file %v %v", fi, err)
	}
	got, err := hostedReadKeeperKey(obs, "run-k")
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("read back %x %v", got, err)
	}
	if err := os.WriteFile(p, []byte("zz"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := hostedReadKeeperKey(obs, "run-k"); err == nil {
		t.Fatal("a damaged key file read back")
	}
	if _, err := hostedReadKeeperKey(obs, "run-none"); err == nil {
		t.Fatal("a missing key file read back")
	}
}
