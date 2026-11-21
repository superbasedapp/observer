//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// TestSeizeStatusLine (lane ptrace): `observer sandbox status` and doctor
// say whether the strace switch is on and, when it is, what it gives each
// sandbox here (its ground, or why strace stays blocked); the line shows
// only while the filter is on.
func TestSeizeStatusLine(t *testing.T) {
	rows := []dashapi.SandboxSeizeRow{
		{Backend: "bwrap", Lifted: true, Ground: "pid_namespace"},
		{Backend: "process_lite", Reason: "strace stays blocked (PTRACE_SEIZE denied): Yama ptrace_scope reads 0"},
	}
	if l := seizeStatusLine(false, rows); !strings.Contains(l, "seccomp_allow_seize off, the default") {
		t.Errorf("off: %q", l)
	}
	l := seizeStatusLine(true, rows)
	if !strings.Contains(l, "bwrap: allowed (pid_namespace)") || !strings.Contains(l, "process_lite: strace stays blocked") {
		t.Errorf("on: %q", l)
	}
	for _, c := range []struct {
		seccomp bool
		want    bool
	}{{true, true}, {false, false}} {
		var b bytes.Buffer
		if err := renderSandboxStatus(&b, sandboxStatusReport{Enabled: true, Egress: "internet", Host: "linux", Seccomp: c.seccomp, SeccompAllowSeize: true, SeizeRows: rows}); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(b.String(), "strace in a sandbox"); got != c.want {
			t.Errorf("filter %v: the strace line shown %v:\n%s", c.seccomp, got, b.String())
		}
	}
}

// TestSandboxSeizeRows: bwrap is lifted on its own pid namespace whatever
// Yama says; process_lite only on Yama 1 or more, else with the reason; no
// row that does not load Observer's filter is listed.
func TestSandboxSeizeRows(t *testing.T) {
	for _, c := range []struct {
		scope      int
		known      bool
		liteLifted bool
		liteReason string
	}{
		{1, true, true, ""},
		{0, true, false, "reads 0"},
		{0, false, false, "could not be read"},
	} {
		stubYamaScope(t, c.scope, c.known)
		host := sandboxSeizeHostNow()
		if host.YamaScope != c.scope || host.YamaKnown != c.known {
			t.Fatalf("Yama %+v", host)
		}
		got := map[string]dashapi.SandboxSeizeRow{}
		for _, r := range host.Rows {
			got[r.Backend] = r
		}
		if len(got) != 2 {
			t.Fatalf("rows %+v: want bwrap and process_lite only", host.Rows)
		}
		if bw := got["bwrap"]; !bw.Lifted || bw.Ground != "pid_namespace" || bw.Reason != "" {
			t.Errorf("Yama %d/%v: bwrap %+v", c.scope, c.known, bw)
		}
		lite := got["process_lite"]
		if lite.Lifted != c.liteLifted || (c.liteLifted && lite.Ground != "yama") || !strings.Contains(lite.Reason, c.liteReason) {
			t.Errorf("Yama %d/%v: process_lite %+v", c.scope, c.known, lite)
		}
	}
}
