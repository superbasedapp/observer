//go:build linux

package mcprelay

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// fakeProc builds a synthetic procfs tree for pid: exe -> target, stat with
// the given start time.
func fakeProc(t *testing.T, root string, pid int, exeTarget, start string) string {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(dir, "exe"))
	if err := os.Symlink(exeTarget, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	stat := strconv.Itoa(pid) + " (claude (code)) S 1 1 1 0 -1 4194560 100 0 0 0 5 5 0 0 20 0 1 0 " + start + " 1000 100 18446744073709551615"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestProcAttestor(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "claude")
	body := []byte("#!/bin/sh\necho claude\n")
	_ = os.WriteFile(bin, body, 0o755)
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	reg := StaticClientRegistry{{Agent: "agent:claude-code", Product: "claude-code", Exe: bin, SHA256: sha}}

	cases := []struct {
		name    string
		setup   func() ProcAttestor
		reg     ClientRegistry
		want    string
		agent   string
		reasonS string
	}{
		{"verified parent", func() ProcAttestor {
			fakeProc(t, root, 100, bin, "777")
			return ProcAttestor{Root: root, PPID: 100}
		}, reg, "process_attested", "agent:claude-code", "verified"},
		{"spoof: unregistered image at the registered path", func() ProcAttestor {
			other := filepath.Join(root, "claude-spoof")
			_ = os.WriteFile(other, []byte("not the client"), 0o755)
			// exe resolves to a different image whose hash is not listed.
			fakeProc(t, root, 101, other, "1")
			return ProcAttestor{Root: root, PPID: 101}
		}, reg, "configured", "", "not a registered client"},
		{"symlink launcher: kernel path differs from the registered one", func() ProcAttestor {
			link := filepath.Join(root, "claude-link")
			_ = os.Symlink(bin, link)
			// The registry lists bin; a parent whose kernel exe path is the
			// symlink itself (same bytes, other path) is NOT the listed row.
			fakeProc(t, root, 102, link, "2")
			return ProcAttestor{Root: root, PPID: 102}
		}, reg, "configured", "", "not a registered client"},
		{"binary replaced/deleted on disk", func() ProcAttestor {
			fakeProc(t, root, 103, bin+" (deleted)", "3")
			return ProcAttestor{Root: root, PPID: 103}
		}, reg, "configured", "", "deleted"},
		{"no registry", func() ProcAttestor {
			fakeProc(t, root, 104, bin, "4")
			return ProcAttestor{Root: root, PPID: 104}
		}, nil, "configured", "", "no registered-client list"},
		{"parent is init", func() ProcAttestor { return ProcAttestor{Root: root, PPID: 1} }, reg, "configured", "", "init"},
		{"no proc entry", func() ProcAttestor { return ProcAttestor{Root: root, PPID: 4242} }, reg, "configured", "", "start time"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := tc.setup()
			got := a.Attest(tc.reg)
			if got.Attestation != tc.want || got.Agent != tc.agent {
				t.Fatalf("got %+v", got)
			}
			if tc.reasonS != "" && !contains(got.Reason, tc.reasonS) {
				t.Fatalf("reason %q lacks %q", got.Reason, tc.reasonS)
			}
		})
	}
}

// TestProcAttestorPIDReuse: the start time read AFTER hashing differs from
// the one read BEFORE (the pid was recycled mid-check) -> configured.
func TestProcAttestorPIDReuse(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "claude")
	body := []byte("client")
	_ = os.WriteFile(bin, body, 0o755)
	sum := sha256.Sum256(body)
	reg := StaticClientRegistry{{Agent: "agent:claude-code", Product: "claude-code", Exe: bin, SHA256: hex.EncodeToString(sum[:])}}
	dir := fakeProc(t, root, 200, bin, "10")
	a := ProcAttestor{Root: root, PPID: 200, afterHash: func() {
		_ = os.WriteFile(filepath.Join(dir, "stat"), []byte("200 (x) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99 0 0 0"), 0o644)
	}}
	got := a.Attest(reg)
	if got.Attestation != "configured" || !contains(got.Reason, "pid reuse") {
		t.Fatalf("got %+v", got)
	}
}

func TestProcStartTimeParsesCommWithSpaces(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "stat"), []byte("7 (a b) c) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 4242 0 0 0"), 0o644)
	got, err := procStartTime(dir)
	if err != nil || got != "4242" {
		t.Fatalf("%q %v", got, err)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})())
}
