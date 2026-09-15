package intervention

import (
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

func TestMatchInstalledProcessNativeAndRefusals(t *testing.T) {
	t.Parallel()

	executable := ExecutableIdentity{Device: 11, Inode: 22}
	id := Identity{BootID: "boot", PID: 1200, StartTicks: 33, UID: 1000, Executable: executable}
	manifest := InstallManifest{Surfaces: []SurfaceManifest{{
		Spec:  integration.InterventionSurfaceSpec{ID: "goose/cli", Tool: "goose", Class: integration.SurfaceDedicatedProcess},
		State: BindingReady,
		Targets: []InstallTarget{{
			Kind:       TargetNativeExecutable,
			Executable: InstalledFile{Path: "/opt/goose", Identity: executable},
		}},
	}}}

	evidence := ProcessEvidence{Identity: id, Invocations: []InvocationEvidence{{SurfaceID: "goose/cli", Target: TargetNativeExecutable, Class: InvocationCLI}}}
	got := MatchInstalledProcess(manifest, evidence, MatchOptions{TargetUID: 1000})
	if got.State != MatchBound || len(got.Matches) != 1 || got.Matches[0].SurfaceID != "goose/cli" {
		t.Fatalf("native match = %+v", got)
	}
	if got := MatchInstalledProcess(manifest, ProcessEvidence{Identity: id}, MatchOptions{TargetUID: 1000}); got.State != MatchRefused || got.Reason != MatchReasonInvocationUnknown {
		t.Fatalf("missing native invocation classification = %+v", got)
	}
	nonCLI := ProcessEvidence{Identity: id, Invocations: []InvocationEvidence{{SurfaceID: "goose/cli", Target: TargetNativeExecutable, Class: InvocationNonCLI}}}
	if got := MatchInstalledProcess(manifest, nonCLI, MatchOptions{TargetUID: 1000}); got.State != MatchRefused || got.Reason != MatchReasonNonCLI {
		t.Fatalf("declared non-CLI invocation = %+v", got)
	}
	if got := MatchInstalledProcess(manifest, ProcessEvidence{Identity: id}, MatchOptions{TargetUID: 1001}); got.Reason != MatchReasonWrongUID {
		t.Fatalf("wrong uid reason = %q", got.Reason)
	}
	if got := MatchInstalledProcess(manifest, ProcessEvidence{Identity: id}, MatchOptions{TargetUID: 1000, ForbiddenPIDs: []int{5, id.PID}}); got.Reason != MatchReasonForbiddenPID {
		t.Fatalf("forbidden pid reason = %q", got.Reason)
	}
}

func TestMatchInstalledProcessRequiresExactScript(t *testing.T) {
	t.Parallel()

	interpreter := ExecutableIdentity{Device: 1, Inode: 2}
	script := ExecutableIdentity{Device: 3, Inode: 4}
	id := Identity{BootID: "boot", PID: 1201, StartTicks: 34, UID: 1000, Executable: interpreter}
	entrypoint := InstalledFile{Path: "/opt/tool/cli.js", Identity: script}
	manifest := InstallManifest{Surfaces: []SurfaceManifest{{
		Spec:  integration.InterventionSurfaceSpec{ID: "gemini-cli/cli", Tool: "gemini-cli", Class: integration.SurfaceDedicatedProcess},
		State: BindingReady,
		Targets: []InstallTarget{{
			Kind:       TargetInterpretedEntrypoint,
			Executable: InstalledFile{Path: "/usr/bin/node", Identity: interpreter},
			Entrypoint: &entrypoint,
		}},
	}}}

	for name, evidence := range map[string]ProcessEvidence{
		"missing":        {Identity: id},
		"wrong path":     {Identity: id, Entrypoint: &EntrypointEvidence{Path: "/opt/other/cli.js", Identity: script}},
		"wrong identity": {Identity: id, Entrypoint: &EntrypointEvidence{Path: entrypoint.Path, Identity: ExecutableIdentity{Device: 3, Inode: 5}}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := MatchInstalledProcess(manifest, evidence, MatchOptions{TargetUID: 1000}); got.State != MatchNone {
				t.Fatalf("match = %+v", got)
			}
		})
	}
	exact := ProcessEvidence{
		Identity: id, Entrypoint: &EntrypointEvidence{Path: entrypoint.Path, Identity: script},
		Invocations: []InvocationEvidence{{SurfaceID: "gemini-cli/cli", Target: TargetInterpretedEntrypoint, Class: InvocationCLI}},
	}
	if got := MatchInstalledProcess(manifest, exact, MatchOptions{TargetUID: 1000}); got.State != MatchBound {
		t.Fatalf("exact script match = %+v", got)
	}
}

func TestMatchInstalledProcessRefusesAmbiguousSurface(t *testing.T) {
	t.Parallel()

	executable := ExecutableIdentity{Device: 7, Inode: 8}
	id := Identity{BootID: "boot", PID: 1202, StartTicks: 35, UID: 1000, Executable: executable}
	manifest := InstallManifest{}
	for _, tool := range []string{"one", "two"} {
		manifest.Surfaces = append(manifest.Surfaces, SurfaceManifest{
			Spec:    integration.InterventionSurfaceSpec{ID: tool + "/cli", Tool: tool, Class: integration.SurfaceDedicatedProcess},
			State:   BindingReady,
			Targets: []InstallTarget{{Kind: TargetNativeExecutable, Executable: InstalledFile{Path: "/same", Identity: executable}}},
		})
	}
	got := MatchInstalledProcess(manifest, ProcessEvidence{Identity: id, Invocations: []InvocationEvidence{
		{SurfaceID: "one/cli", Target: TargetNativeExecutable, Class: InvocationCLI},
		{SurfaceID: "two/cli", Target: TargetNativeExecutable, Class: InvocationCLI},
	}}, MatchOptions{TargetUID: 1000})
	if got.State != MatchAmbiguous || got.Reason != MatchReasonAmbiguous || len(got.Matches) != 2 {
		t.Fatalf("ambiguous match = %+v", got)
	}
}

func TestMatchInstalledProcessNeverTargetsUnsupportedSurface(t *testing.T) {
	t.Parallel()

	executable := ExecutableIdentity{Device: 9, Inode: 10}
	id := Identity{BootID: "boot", PID: 1203, StartTicks: 36, UID: 1000, Executable: executable}
	manifest := InstallManifest{Surfaces: []SurfaceManifest{{
		Spec:    integration.InterventionSurfaceSpec{ID: "cline/ide", Tool: "cline", Class: integration.SurfaceSharedHost},
		State:   BindingReady,
		Targets: []InstallTarget{{Kind: TargetNativeExecutable, Executable: InstalledFile{Path: "/usr/bin/code", Identity: executable}}},
	}}}
	if got := MatchInstalledProcess(manifest, ProcessEvidence{Identity: id}, MatchOptions{TargetUID: 1000}); got.State != MatchNone {
		t.Fatalf("shared host matched: %+v", got)
	}
}

func TestRecordScanMatchScopesUnknownInvocationToItsSurface(t *testing.T) {
	t.Parallel()
	id := Identity{BootID: "boot", PID: 1204, StartTicks: 37, UID: 1000, Executable: ExecutableIdentity{Device: 11, Inode: 12}}
	result := ScanResult{Complete: true}
	recordScanMatch(&result, ProcessEvidence{Identity: id}, MatchResult{State: MatchRefused, Reason: MatchReasonNonCLI})
	if !result.Complete || len(result.Refused) != 1 || len(result.UnclassifiedSurfaces) != 0 {
		t.Fatalf("known non-CLI scan result = %+v", result)
	}
	recordScanMatch(&result, ProcessEvidence{Identity: id}, MatchResult{
		State: MatchRefused, Reason: MatchReasonInvocationUnknown,
		UnclassifiedSurfaces: []string{"two/cli"},
	})
	recordScanMatch(&result, ProcessEvidence{Identity: id}, MatchResult{
		State: MatchRefused, Reason: MatchReasonInvocationUnknown,
		UnclassifiedSurfaces: []string{"two/cli", "one/cli"},
	})
	if !result.Complete {
		t.Fatalf("an unclassified invocation degraded the whole scan: %+v", result)
	}
	if len(result.Refused) != 3 || !slices.Equal(result.UnclassifiedSurfaces, []string{"one/cli", "two/cli"}) {
		t.Fatalf("unknown native invocation scan result = %+v", result)
	}
}

// TestMatchInstalledProcessGovernsArgumentBearingInvocation pins the inverted
// contract end to end: an ordinary argument-bearing launch of an exactly
// matched installed executable is now a governed workload, while a declared
// server mode is refused with its own reason and reports no surface as
// unclassified.
func TestMatchInstalledProcessGovernsArgumentBearingInvocation(t *testing.T) {
	t.Parallel()

	spec, ok := integration.InterventionFor("codex")
	if !ok || len(spec) == 0 {
		t.Fatal("codex intervention surfaces missing")
	}
	executable := ExecutableIdentity{Device: 21, Inode: 22}
	id := Identity{BootID: "boot", PID: 1301, StartTicks: 40, UID: 1000, Executable: executable}
	manifest := InstallManifest{Surfaces: []SurfaceManifest{{
		Spec:    spec[0],
		State:   BindingReady,
		Targets: []InstallTarget{{Kind: TargetNativeExecutable, Executable: InstalledFile{Path: "/opt/codex", Identity: executable}}},
	}}}

	for _, tc := range []struct {
		name    string
		leading string
		state   MatchState
		reason  MatchReason
	}{
		{name: "model flag", leading: "--model", state: MatchBound, reason: MatchReasonNone},
		{name: "declared verb", leading: "exec", state: MatchBound, reason: MatchReasonNone},
		{name: "future verb", leading: "future-mode", state: MatchBound, reason: MatchReasonNone},
		{name: "declared server mode", leading: "app-server", state: MatchRefused, reason: MatchReasonNonCLI},
		{name: "universal maintenance", leading: "login", state: MatchRefused, reason: MatchReasonNonCLI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evidence := ProcessEvidence{Identity: id, Invocations: []InvocationEvidence{{
				SurfaceID: spec[0].ID,
				Target:    TargetNativeExecutable,
				Class:     ClassifyInvocation(spec[0].Binding.Invocation, tc.leading, true),
			}}}
			got := MatchInstalledProcess(manifest, evidence, MatchOptions{TargetUID: 1000})
			if got.State != tc.state || got.Reason != tc.reason || len(got.UnclassifiedSurfaces) != 0 {
				t.Fatalf("match for %q = %+v", tc.leading, got)
			}
		})
	}
}

// TestMatchInstalledProcessNamesTheAbstainingSurface covers the only remaining
// abstention: a surface that declares RequireDeclaredCLI reports itself, and
// nothing else, as unclassified.
func TestMatchInstalledProcessNamesTheAbstainingSurface(t *testing.T) {
	t.Parallel()

	executable := ExecutableIdentity{Device: 23, Inode: 24}
	id := Identity{BootID: "boot", PID: 1302, StartTicks: 41, UID: 1000, Executable: executable}
	manifest := InstallManifest{Surfaces: []SurfaceManifest{{
		Spec: integration.InterventionSurfaceSpec{
			ID: "ambiguous/cli", Tool: "ambiguous", Class: integration.SurfaceDedicatedProcess,
			Binding: integration.ProcessBindingSpec{AllowNative: true, Invocation: integration.InvocationSpec{
				AllowNoArguments: true, CLILeadingArguments: []string{"run"}, RequireDeclaredCLI: true,
			}},
		},
		State:   BindingReady,
		Targets: []InstallTarget{{Kind: TargetNativeExecutable, Executable: InstalledFile{Path: "/opt/ambiguous", Identity: executable}}},
	}}}
	evidence := ProcessEvidence{Identity: id, Invocations: []InvocationEvidence{{
		SurfaceID: "ambiguous/cli",
		Target:    TargetNativeExecutable,
		Class:     ClassifyInvocation(manifest.Surfaces[0].Spec.Binding.Invocation, "--future", true),
	}}}
	got := MatchInstalledProcess(manifest, evidence, MatchOptions{TargetUID: 1000})
	if got.State != MatchRefused || got.Reason != MatchReasonInvocationUnknown ||
		!slices.Equal(got.UnclassifiedSurfaces, []string{"ambiguous/cli"}) {
		t.Fatalf("ambiguous surface match = %+v", got)
	}
}
