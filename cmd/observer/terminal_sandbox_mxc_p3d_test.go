//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestMXCProbeArgvPassesTheObserverDir (SBX-P3D audit finding 5): the
// daemon hands the probe helper its own observer directory, so the helper
// reads the daemon's content store, never the default config's; the host
// helper's argv carries it too.
func TestMXCProbeArgvPassesTheObserverDir(t *testing.T) {
	got := mxcProbeArgv(`C:\obs`)
	if !slices.Equal(got, []string{mxcProbeVerb, "--active", mxcFlagObserverDir, `C:\obs`}) {
		t.Fatalf("probe argv %q", got)
	}
	if !slices.Contains(mxcWrapArgv("observer", `C:\p.json`, "r1", `C:\obs`), `C:\obs`) {
		t.Fatal("the host helper's argv lacks the observer directory")
	}
}

// TestMXCProbeAnswerReportsTheSignedRefusal (SBX-P3D audit finding 6): a
// signed manifest that refuses the set makes the probe answer
// artifact_unverified, the launch's own refusal, never probe_failed or
// available.
func TestMXCProbeAnswerReportsTheSignedRefusal(t *testing.T) {
	refused := sandboxmxc.ResolveSigned(sandboxmxc.SignedInput{Compiled: sandboxmxc.ManifestX64, HasCompiled: true, Arch: "amd64", Installed: true, Freshness: "unknown"})
	if refused.OK {
		t.Fatal("an expired signed manifest resolved")
	}
	got := mxcProbeAnswer(sandboxmxc.ProbeResult{}, errors.New(refused.Verdict.Error()), refused)
	if got.Verdict.Code != sandboxmxc.VerdictArtifactUnverified || got.Rule != mxcSignedRuleID("age") || !strings.Contains(got.Verdict.Reason, "observer sandbox content fetch") {
		t.Fatalf("answer %+v", got)
	}
	ok := sandboxmxc.SignedResult{OK: true}
	if a := mxcProbeAnswer(sandboxmxc.ProbeResult{}, errors.New("hung"), ok); a.Verdict.Code != sandboxmxc.VerdictProbeFailed {
		t.Fatalf("a helper failure: %+v", a)
	}
	through := availableMXC()
	if a := mxcProbeAnswer(through, nil, ok); a.Rule != through.Rule {
		t.Fatalf("a clean gather: %+v", a)
	}
}

// TestMXCAgeRefusalStartsARefresh (SBX-P3D audit finding 4): a probe that
// says the signed manifest is past its age floor starts the background
// refresh of sandbox.native_files for the daemon's observer directory; any
// other answer does not.
func TestMXCAgeRefusalStartsARefresh(t *testing.T) {
	var asked []string
	prev := sandboxContentRefreshFn
	sandboxContentRefreshFn = func(k content.Kind, dir string) { asked = append(asked, string(k)+"@"+dir) }
	t.Cleanup(func() { sandboxContentRefreshFn = prev })

	countMXCProbes(t, "windows", availableMXC())
	rt := ociTestRuntime(t, mxcTestConfig(t, true, "mxc-process"))
	_ = rt.driverProbes(context.Background())[sandboxbackend.BackendMXCProcess]
	if len(asked) != 0 {
		t.Fatalf("an available probe refreshed: %v", asked)
	}

	countMXCProbes(t, "windows", sandboxmxc.ProbeResult{Verdict: sandboxmxc.Verdict{Code: sandboxmxc.VerdictArtifactUnverified, Reason: "past its age floor"}, Rule: mxcSignedRuleID("age")})
	rt = ociTestRuntime(t, mxcTestConfig(t, true, "mxc-process"))
	_ = rt.driverProbes(context.Background())[sandboxbackend.BackendMXCProcess]
	if len(asked) != 1 || !strings.HasPrefix(asked[0], string(content.SandboxNative)+"@") || strings.HasSuffix(asked[0], "@") {
		t.Fatalf("refresh asked %v, want sandbox.native_files for the observer directory", asked)
	}
}
