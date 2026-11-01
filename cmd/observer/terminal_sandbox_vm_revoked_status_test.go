//go:build !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestSandboxStatusShowsARevokedSetAsRevoked (R-015, P-149): after a signed
// manifest revokes the installed guest image set, `observer sandbox status`
// shows the microVM row as revoked (not available) and names the revoking
// manifest, and the content status line no longer reads as a usable set.
func TestSandboxStatusShowsARevokedSetAsRevoked(t *testing.T) {
	pub, priv := vmTestKey(t)
	keys := []ed25519.PublicKey{pub}
	tr := contentchan.Trust{VendorKeys: keys}
	store := vmContentStore(t.TempDir())
	if _, err := sandboxContentImport(store, keys, writeVMTestSet(t, priv, 1, "1.0.0", "1.40.0").dir); err != nil {
		t.Fatal(err)
	}
	if line := sandboxContentStatusLine(store, tr, content.SandboxRootfs); strings.Contains(line, "REVOKED") {
		t.Fatalf("a good set reads as revoked: %s", line)
	}
	revoke := content.Revocation{SHA256: strings.Repeat("9", 64), Reason: "withdrawn in a test"}
	if _, err := sandboxContentImport(store, keys, writeVMTestSet(t, priv, 2, "1.0.0", "1.40.0", revoke).dir); err != nil {
		t.Fatal(err)
	}
	f := loadVMImageSet(store, tr, "", "1.40.0").facts()
	if f.Verdict.OK() {
		t.Fatalf("a revoked set verified: %+v", f)
	}
	b := dashapi.SandboxBackendAvail{ID: "cloud-hypervisor", Class: "hw_vm", Location: "local", Maturity: "preview", Verdict: f.Verdict.Code, Rule: "S1", Reason: f.Verdict.Reason}
	var out bytes.Buffer
	if err := renderSandboxStatus(&out, sandboxStatusReport{Enabled: true, Egress: "none", Host: "linux", Backends: []dashapi.SandboxBackendAvail{b}}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"revoked", "sandbox.rootfs manifest version 2", "withdrawn in a test"} {
		if !strings.Contains(text, want) {
			t.Errorf("sandbox status lacks %q:\n%s", want, text)
		}
	}
	for _, ln := range strings.Split(text, "\n") {
		if strings.HasPrefix(ln, "cloud-hypervisor ") && strings.Contains(ln, "available") {
			t.Errorf("the revoked row reads as available: %q", ln)
		}
	}
	line := sandboxContentStatusLine(store, tr, content.SandboxRootfs)
	if !strings.Contains(line, "REVOKED, not available") || !strings.Contains(line, "manifest version 2") {
		t.Errorf("content status line does not name the revocation: %s", line)
	}
}
