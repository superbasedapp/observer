//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
)

// TestSecurityTrustVerbsRefuseWhileInactive: every trust verb refuses
// unless security.trust is active (fail invisible); the id is unknown to
// the catalog until security Phase A adds its rows, so today they refuse.
func TestSecurityTrustVerbsRefuseWhileInactive(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if componentSnapshotFor(cfgPath).ModuleActive(repoTrustComponent) {
		t.Skip("security.trust is active in this build's catalog; the refusal path is covered by the component tests")
	}
	if len(componentstate.UnknownNodeIDs(repoTrustComponent)) == 0 {
		t.Log("security.trust is a catalog row but inactive by default here")
	}
	for _, args := range [][]string{{"check"}, {"accept", "--all"}, {"list"}, {"revoke", "sha256:00"}} {
		cmd := newSecurityTrustCmd()
		cmd.SetArgs(append(args, "--config", cfgPath))
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.ExecuteContext(context.Background())
		if err == nil || !strings.Contains(err.Error(), "not active") {
			t.Errorf("%v: err = %v, want the inactive refusal", args, err)
		}
	}
}

// TestPrintTrustResult: the person-facing output names the verdict, each
// reason, and the accept command for a digest not yet accepted.
func TestPrintTrustResult(t *testing.T) {
	res := sectrust.Result{Verdict: sectrust.VerdictUntrusted, Reasons: []sectrust.Reason{
		{Code: "mcp_server_command", Level: sectrust.LevelUntrusted, File: ".mcp.json", Key: "mcpServers.x", Excerpt: "node x.js", Digest: "sha256:ab", Indicators: []string{"names a URL"}},
		{Code: "hook_command", Level: sectrust.LevelFlagged, File: ".claude/settings.json", Digest: "sha256:cd", Accepted: true},
	}}
	var b bytes.Buffer
	printTrustResult(&b, repoTrustTarget{root: "/r", launchRel: "pkg"}, res)
	out := b.String()
	for _, want := range []string{"repository /r: untrusted", "down to pkg", "mcp_server_command", "observer security trust accept sha256:ab", "accepted (sha256:cd)", "it names a URL"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}
