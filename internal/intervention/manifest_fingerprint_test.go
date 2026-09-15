package intervention

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

func TestInstallManifestFingerprintBindsCurrentTargetsWithoutPathsOrRetainedProcesses(t *testing.T) {
	spec := integration.InterventionSurfaceSpec{
		ID: "fixture/cli", Tool: "fixture", Class: integration.SurfaceDedicatedProcess,
		NativeUsage: integration.NativeUsagePresent,
		Binding:     integration.ProcessBindingSpec{AllowNative: true, Invocation: integration.InvocationSpec{AllowNoArguments: true}},
	}
	base := InstallManifest{Surfaces: []SurfaceManifest{{
		Spec: spec, State: BindingReady,
		Targets: []InstallTarget{{Kind: TargetNativeExecutable, Executable: InstalledFile{
			Path: "/one/private/path", Identity: ExecutableIdentity{Device: 1, Inode: 2},
		}}},
	}}}
	pathChanged := base
	pathChanged.Surfaces = append([]SurfaceManifest(nil), base.Surfaces...)
	pathChanged.Surfaces[0].Targets = append([]InstallTarget(nil), base.Surfaces[0].Targets...)
	pathChanged.Surfaces[0].Targets[0].Executable.Path = "/another/private/path"
	if got, want := InstallManifestFingerprint(pathChanged), InstallManifestFingerprint(base); got != want {
		t.Fatalf("path changed fingerprint: got %q want %q", got, want)
	}

	retained := base
	retained.Surfaces = append([]SurfaceManifest(nil), base.Surfaces...)
	retained.Surfaces[0].Targets = append([]InstallTarget(nil), base.Surfaces[0].Targets...)
	id := Identity{PID: 42}
	retained.Surfaces[0].Targets = append(retained.Surfaces[0].Targets, InstallTarget{
		Kind: TargetNativeExecutable, Executable: InstalledFile{Path: "/removed", Identity: ExecutableIdentity{Device: 3, Inode: 4}}, BoundProcess: &id,
	})
	if got, want := InstallManifestFingerprint(retained), InstallManifestFingerprint(base); got != want {
		t.Fatalf("retained process changed fingerprint: got %q want %q", got, want)
	}

	identityChanged := pathChanged
	identityChanged.Surfaces[0].Targets[0].Executable.Identity.Inode++
	if InstallManifestFingerprint(identityChanged) == InstallManifestFingerprint(base) {
		t.Fatal("current installed identity did not change fingerprint")
	}
	declarationChanged := base
	declarationChanged.Surfaces = append([]SurfaceManifest(nil), base.Surfaces...)
	declarationChanged.Surfaces[0].Spec.Binding.Invocation.AllowNoArguments = false
	if InstallManifestFingerprint(declarationChanged) == InstallManifestFingerprint(base) {
		t.Fatal("surface declaration did not change fingerprint")
	}
}
