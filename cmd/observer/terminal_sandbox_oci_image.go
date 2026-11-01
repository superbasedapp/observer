//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// terminal_sandbox_oci_image.go is the container driver's side of the
// signed image trust root (sandbox plan v2 section 12.3, SBX-IMG-1, lane
// SBX-P3B): which image a run uses, and whether the trust check refuses it.
//
// Nothing changes until a signed sandbox.image manifest is installed in the
// node's content store, which no release does yet: with none installed an
// empty [terminal.sandbox.oci].image keeps the "not published yet" refusal
// and a configured image is used as before. Once one is installed, an empty
// image resolves to Observer's default image by digest through
// internal/sandboximage (refused as artifact_unverified when the manifest,
// descriptor or SBOM fails), and a configured image the manifest revokes is
// refused too.

// sandboxImageContentDir is the content store root under the observer
// directory; the sandbox.image kind sits in its own subdirectory.
const sandboxImageContentDir = "sandbox-content"

// ociImageTrust is the image a run uses and the trust check's answer.
type ociImageTrust struct {
	// image is the reference a run uses ("" when none).
	image string
	// refusal is the probe's artifact_unverified reason ("" when none).
	refusal string
	// desc is set when image is Observer's verified default image.
	desc *sandboximage.Descriptor
	// stale: used as last-known-good under an expired manifest.
	stale bool
	// revoked reports whether the loaded manifest revokes a sha256 hex (a
	// digest or an image id); nil when no manifest verified (lane SBX-P3C:
	// the prune of revoked images reads it).
	revoked func(hex string) bool
}

// ociImageStore is the node's content store for sandbox artifacts.
func ociImageStore(observerDir string) contentchan.Store {
	return contentchan.Store{Root: filepath.Join(observerDir, sandboxImageContentDir)}
}

func init() {
	sandboxContentSetJudges[content.SandboxImage] = func(st contentchan.Store, tr contentchan.Trust) string {
		t := ociResolveImage(config.TerminalSandboxOCIConfig{}, st, tr)
		if !sandboximage.IsRevokedRefusal(t.refusal) {
			return ""
		}
		return "; REVOKED, not available: " + t.refusal
	}
}

// ociResolveImageFn is the resolution (a variable so a test can install a
// manifest signed with a test key and trust that key).
var ociResolveImageFn = func(cfg config.TerminalSandboxOCIConfig, observerDir string) ociImageTrust {
	return ociResolveImage(cfg, ociImageStore(observerDir), contentchan.Trust{VendorKeys: sandboxImageVendorKeys()})
}

// ociResolveImage loads the sandbox.image kind and decides the run's image.
func ociResolveImage(cfg config.TerminalSandboxOCIConfig, store contentchan.Store, tr contentchan.Trust) ociImageTrust {
	configured := strings.TrimSpace(cfg.Image)
	l, err := store.Load(content.SandboxImage, tr, 0)
	if errors.Is(err, contentchan.ErrNotInstalled) {
		return ociImageTrust{image: configured}
	}
	var revoked func(string) bool
	if err == nil {
		m := l.Manifest
		revoked = func(hex string) bool { return content.IsRevoked(m, hex) }
	}
	if configured != "" {
		// The user's own image is theirs to vouch for; the only thing the
		// channel adds is the project's withdrawal of an image it published.
		if err == nil && sandboximage.RevokedRef(l.Manifest, configured) {
			return ociImageTrust{refusal: "the configured image " + configured + ": " + sandboximage.VerdictArtifactUnverified + " (" + sandboximage.ReasonRevoked + "): it is revoked " + sandboximage.RevokedRefBy(l.Manifest, configured), revoked: revoked}
		}
		return ociImageTrust{image: configured, revoked: revoked}
	}
	in := sandboximage.Input{LoadErr: err}
	if err == nil {
		in.Manifest, in.Freshness = l.Manifest, l.Freshness
		in.Descriptor, in.DescriptorErr = l.ReadArtifact(sandboximage.DescriptorName)
		in.SBOM, in.SBOMErr = l.ReadArtifact(sandboximage.SBOMName)
	}
	r := sandboximage.Resolve(in)
	if !r.OK {
		return ociImageTrust{refusal: "Observer's default image: " + r.Error(), revoked: revoked}
	}
	d := r.Descriptor
	return ociImageTrust{image: r.Ref, desc: &d, stale: r.Stale, revoked: revoked}
}

// ociEffectiveConfig is cfg with the resolved image, for the probe.
func ociEffectiveConfig(cfg config.TerminalSandboxOCIConfig, observerDir string) (config.TerminalSandboxOCIConfig, ociImageTrust) {
	t := ociResolveImageFn(cfg, observerDir)
	cfg.Image = t.image
	return cfg, t
}

// ociCheckDefaultImage is the engine-side half: the verified default image
// must be in the engine at the signed digest and id before a run starts.
func ociCheckDefaultImage(t ociImageTrust, id sandboxengine.ImageIdentity) sandboximage.Result {
	if t.desc == nil {
		return sandboximage.Result{OK: true, Ref: t.image}
	}
	return sandboximage.CheckEngineImage(*t.desc, sandboximage.ImageFacts{
		Present: id.Present, ID: id.ID, RepoDigests: id.RepoDigests, Platform: id.OS + "/" + id.Architecture,
	})
}

// imageTrust resolves the driver's image now (a manifest installed or
// revoked while the daemon runs takes effect at the next launch).
func (d *ociDriver) imageTrust() ociImageTrust {
	return ociResolveImageFn(d.cfg, d.r.observerDir)
}
