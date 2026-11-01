//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/sandboxsbpl"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandbox_p3d_test.go is lane SBX-P3D's integration test: a mirrored
// sandbox.image installed through the node's fetch and read by the
// container driver's existing resolution, and a Seatbelt Codex launch
// planned end to end through the shared composition, all against fakes.

// p3dImageKind is a sandbox.image publication signed by a TEST key: the
// descriptor, the SBOM and the envelope, as the org mirror would hold them.
func p3dImageKind(t *testing.T, priv ed25519.PrivateKey) (env []byte, arts map[string][]byte, ref string) {
	t.Helper()
	d := sandboximage.Descriptor{
		Schema: sandboximage.DescriptorSchema, Repository: "registry.example/observer-sandbox",
		Digest: "sha256:" + strings.Repeat("a", 64), ConfigDigests: map[string]string{"linux/amd64": "sha256:" + strings.Repeat("b", 64)},
		Version: "1.0.0", MinVersion: "1.0.0", Platforms: []string{"linux/amd64"},
		Recipe: "deploy/sandbox-image/Dockerfile", RecipeSHA256: strings.Repeat("c", 64), SourceCommit: strings.Repeat("d", 40),
		BaseImage: "debian:bookworm-slim@sha256:" + strings.Repeat("e", 64), SBOM: sandboximage.SBOMName,
	}
	desc, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	pkgs := map[string][]sandboximage.Package{"linux/amd64": {{Name: "bash", Version: "5.2", Arch: "amd64"}}}
	created := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	sbom, err := sandboximage.SPDX(sandboximage.SBOMInput{Descriptor: d, Created: created, Packages: pkgs})
	if err != nil {
		t.Fatal(err)
	}
	m, err := sandboximage.BuildManifest(sandboximage.ManifestInput{
		Descriptor: desc, SBOM: sbom, ManifestVersion: 1, Epoch: 1, Issued: time.Now().UTC().Add(-time.Minute), Valid: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	e, err := content.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	env, _ = content.EncodeEnvelope(e)
	return env, map[string][]byte{sandboximage.DescriptorName: desc, sandboximage.SBOMName: sbom}, d.Ref()
}

// p3dMirror is a fake org mirror: what orgclient.InstallSecurityContent
// does with the org server's content route, over an in-memory copy.
type p3dMirror struct {
	env   []byte
	arts  map[string][]byte
	calls int
}

func (m *p3dMirror) InstallSecurityContent(_ context.Context, st contentchan.Store, kind content.Kind, tr contentchan.Trust) (orgclient.SecurityContentResult, error) {
	m.calls++
	s, err := st.Install(kind, m.env, m.arts, tr)
	return orgclient.SecurityContentResult{Kind: kind, State: s}, err
}

// TestP3DMirroredSandboxImageInstall: an enrolled node with the container
// driver active fetches sandbox.image from its org mirror into
// ~/.observer/sandbox-content, and the driver's existing resolution then
// uses Observer's default image by digest; with the driver inactive
// nothing is fetched.
func TestP3DMirroredSandboxImageInstall(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, arts, ref := p3dImageKind(t, priv)
	mirror := &p3dMirror{env: env, arts: arts}
	feed := &fakeSandboxFeed{files: map[string][]byte{}}
	cfg := ociTestConfig(t, true, "oci-runc")
	observerDir := t.TempDir()
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}
	e := sandboxContentEnv{
		store: sandboxContentStore(observerDir), trust: tr,
		enrolled: func(context.Context) (bool, error) { return true, nil },
		org:      func(context.Context) (sandboxMirrorInstaller, func(), error) { return mirror, func() {}, nil },
		feed:     func() sandboxFeedClient { return feed },
		active:   sandboxContentActiveFor(cfg),
	}
	out, err := e.fetch(context.Background(), content.SandboxImage)
	if err != nil || out.Source != sandboxSourceOrg || mirror.calls != 1 || feed.calls.Load() != 0 {
		t.Fatalf("fetch: %+v %v (mirror %d, feed %d)", out, err, mirror.calls, feed.calls.Load())
	}
	got := ociResolveImage(config.TerminalSandboxOCIConfig{}, ociImageStore(observerDir), tr)
	if got.refusal != "" || got.image != ref || got.desc == nil || got.stale {
		t.Fatalf("resolve: %+v", got)
	}
	// The driver inactive: nothing is fetched into a fresh store.
	off := e
	off.store = sandboxContentStore(t.TempDir())
	off.active = sandboxContentActiveFor(ociTestConfig(t, false, "oci-runc"))
	if out, err := off.fetch(context.Background(), content.SandboxImage); err != nil || out.Skipped == "" || mirror.calls != 1 {
		t.Fatalf("inactive: %+v %v", out, err)
	}
}

// p3dSandboxer is a fake Sandboxer that plans the Seatbelt driver's native
// decision for the tool, the way its Create does, and returns the run's
// evidence.
type p3dSandboxer struct{ dir string }

func (s p3dSandboxer) Prepare(_ context.Context, req termsvc.PrepareRequest) (termsvc.PrepareResult, error) {
	dec := sandboxsbpl.DecideNative(seatbeltNative(req.Tool))
	if dec.Outcome == sandboxsbpl.NativeRefuse {
		return termsvc.PrepareResult{}, &nativeRefusal{dec.Reason}
	}
	return termsvc.PrepareResult{
		Dir: s.dir, WrapArgv: []string{"observer", "sandbox-seatbelt-host", "--"},
		Isolation: termrun.Isolation{Class: "process", NativeSandboxState: string(seatbeltNativeState(req.Tool, dec))},
	}, nil
}

type nativeRefusal struct{ why string }

func (e *nativeRefusal) Error() string { return e.why }

// p3dLauncher records the launch.
type p3dLauncher struct{ req termsvc.LaunchRequest }

func (l *p3dLauncher) Spawn(req termsvc.LaunchRequest) (string, error) { l.req = req; return "H", nil }

// TestP3DSeatbeltCodexLaunchPlan: a dashboard Codex launch under Seatbelt
// (refused before lane SBX-P3D) is planned with Codex's own sandbox off for
// the run: the argv carries its documented flag after the launcher's
// separator, the evidence says disabled_by_observer, and the CLI path's
// argv is the same.
func TestP3DSeatbeltCodexLaunchPlan(t *testing.T) {
	fakeNativeFiles(t, "darwin", nil, "")
	root := t.TempDir()
	l := &p3dLauncher{}
	svc := termsvc.New(termsvc.Options{
		Policy:   termsvc.Policy{AllowFresh: true, AllowedTools: []string{"codex"}, AllowedProjectRoots: []string{root}},
		Recorder: nopP3DRecorder{}, Launcher: l, Sandboxer: p3dSandboxer{dir: root},
	})
	if _, err := svc.LaunchFresh(context.Background(), termsvc.FreshRequest{Tool: "codex", Subcommand: "codex", Sandbox: true, ProjectRoot: root}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(l.req.ExtraArgs, " "); got != "-- --sandbox danger-full-access" {
		t.Fatalf("dashboard ExtraArgs %q", got)
	}
	state := seatbeltNativeState("codex", sandboxsbpl.DecideNative(seatbeltNative("codex")))
	if state != vocab.NativeDisabledByObserver {
		t.Fatalf("evidence %q", state)
	}
	args, _ := integration.NativeSwitchArgsForState("codex", state)
	cli := sandboxCLIInnerArgv(l.req.WrapArgv, "observer", "codex", integration.AppendNativeArgs(nil, args))
	dash := append(append(append([]string(nil), l.req.WrapArgv...), "observer", "codex"), l.req.ExtraArgs...)
	if strings.Join(cli, " ") != strings.Join(dash, " ") {
		t.Fatalf("cli %v, dashboard %v", cli, dash)
	}
	// Claude Code (kept today, off by default) gets nothing new.
	l.req = termsvc.LaunchRequest{}
	svc2 := termsvc.New(termsvc.Options{
		Policy:   termsvc.Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{root}},
		Recorder: nopP3DRecorder{}, Launcher: l, Sandboxer: p3dSandboxer{dir: root},
	})
	if _, err := svc2.LaunchFresh(context.Background(), termsvc.FreshRequest{Tool: "claude-code", Subcommand: "claude", Sandbox: true, ProjectRoot: root}); err != nil {
		t.Fatal(err)
	}
	if len(l.req.ExtraArgs) != 0 {
		t.Fatalf("claude-code gained %v", l.req.ExtraArgs)
	}
}

// nopP3DRecorder records nothing.
type nopP3DRecorder struct{}

func (nopP3DRecorder) RecordRun(context.Context, termrun.Run) error { return nil }
func (nopP3DRecorder) EndRun(context.Context, string, time.Time, int, string) error {
	return nil
}
func (nopP3DRecorder) RecordCorrelation(context.Context, termrun.Correlation) error { return nil }
func (nopP3DRecorder) RecordGUISpawn(context.Context, termrun.Run) error            { return nil }
