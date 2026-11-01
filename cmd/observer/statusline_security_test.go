//go:build !sbo_omit_security

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/statusline"
)

func TestSecurityStatuslineLabels(t *testing.T) {
	cases := []struct {
		p    policy.SecurityPosture
		n    int
		want string
	}{
		{policy.SecurityPostureClean, 0, "sec ok"},
		{policy.SecurityPostureDirty, 0, "sec *"},
		{policy.SecurityPostureUnknown, 0, "sec ?"},
		{policy.SecurityPostureBlocking, 2, "sec 2!"},
	}
	for _, c := range cases {
		if got := securityStatuslineLabel(c.p, c.n); got == nil || *got != c.want {
			t.Errorf("%s: %v, want %q", c.p, got, c.want)
		}
	}
	if securityStatuslineLabel(policy.SecurityPostureAbsent, 0) != nil {
		t.Error("an absent posture shows a segment")
	}
	if got := withSecuritySegment(nil); got[len(got)-1] != statusline.SegmentSecurity || len(got) != len(statusline.DefaultSegments)+1 {
		t.Errorf("default plus security: %v", got)
	}
	if got := withSecuritySegment([]string{"model", "security"}); len(got) != 2 {
		t.Errorf("already listed: %v", got)
	}
}

// TestStatuslineSecuritySegment: the provider's label lands at the end of
// the line; with no provider (the segment off) the line is unchanged; the
// provider is nil while [security.statusline].segment is off.
func TestStatuslineSecuritySegment(t *testing.T) {
	setTestHome(t, t.TempDir())
	run := func(sec func(statusline.Input) *string) string {
		dbDir := t.TempDir()
		deps := statuslineDeps{
			getenv:   func(string) string { return "" },
			resolve:  func() (string, string, error) { return dbDir, "", nil },
			stdinTTY: func() bool { return false },
			security: sec,
		}
		cmd := newStatuslineCmdWith(deps)
		var out, errBuf bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errBuf)
		cmd.SetIn(strings.NewReader(`{"model":{"display_name":"m"},"workspace":{"current_dir":"/w"}}`))
		cmd.SetArgs([]string{})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute: %v %s", err, errBuf.String())
		}
		return strings.TrimRight(out.String(), "\n")
	}
	label := "sec 2!"
	if got := run(func(in statusline.Input) *string {
		if in.Workspace == nil || in.Workspace.CurrentDir == nil || *in.Workspace.CurrentDir != "/w" {
			return nil
		}
		return &label
	}); !strings.HasSuffix(got, " · sec 2!") {
		t.Fatalf("with the segment: %q", got)
	}
	if got := run(nil); strings.Contains(got, "sec") {
		t.Fatalf("without the segment: %q", got)
	}
	if statuslineSecurityProvider(config.Default()) != nil {
		t.Fatal("the segment is off by default")
	}
}
