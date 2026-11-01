//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestSandboxStatusShowsTheLiveRunPolicy: status prints the policy in force
// when the sandbox is on, and says nothing about it when it is off.
func TestSandboxStatusShowsTheLiveRunPolicy(t *testing.T) {
	for _, tc := range []struct {
		enabled bool
		policy  string
		want    string
	}{
		{true, liveRunPolicyDefer, "Updates while sandboxed runs are live: defer"},
		{true, liveRunPolicyAskImmediately, "Updates while sandboxed runs are live: ask_immediately"},
		{false, liveRunPolicyDefer, ""},
	} {
		var b bytes.Buffer
		if err := renderSandboxStatus(&b, sandboxStatusReport{Enabled: tc.enabled, Egress: "internet", Host: "linux", LiveRunUpdatePolicy: tc.policy}); err != nil {
			t.Fatal(err)
		}
		has := strings.Contains(b.String(), "Updates while sandboxed runs are live")
		if tc.want == "" && has || tc.want != "" && !strings.Contains(b.String(), tc.want) {
			t.Fatalf("enabled=%v policy=%s:\n%s", tc.enabled, tc.policy, b.String())
		}
	}
}
