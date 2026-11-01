package sandboximage

import (
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// VerdictArtifactUnverified is the one refusal of the image trust check
// (plan 12.3): an artifact not covered by a valid manifest.
const VerdictArtifactUnverified = "artifact_unverified"

// The reasons a refusal carries, beside the content channel's own.
const (
	ReasonNotInstalled = "not_installed"
	ReasonUnknownAge   = "past_age_floor"
	ReasonNeedsFresh   = "expired_needs_fresh"
	ReasonDescriptor   = "descriptor"
	ReasonSBOM         = "sbom"
	ReasonBelowMinimum = "below_minimum"
	ReasonRevoked      = "revoked"
	ReasonNotPresent   = "image_not_present"
	ReasonTampered     = "image_tampered"
)

// Input is one resolution: what the content channel load returned.
type Input struct {
	// LoadErr is contentchan's Load error; nil on success.
	LoadErr error
	// NotInstalled reports that nothing was ever accepted for the kind
	// (contentchan.ErrNotInstalled), which is not an error: the default
	// image is simply not available.
	NotInstalled bool
	// Manifest and Freshness are the loaded manifest and its freshness.
	Manifest  content.Manifest
	Freshness content.Freshness
	// Descriptor and SBOM are ReadArtifact's results (each re-checked
	// against its digest by the channel on every read).
	Descriptor    []byte
	DescriptorErr error
	SBOM          []byte
	SBOMErr       error
	// NeedFresh is set when the run would need the image fetched (it is not
	// in the engine yet): an expired manifest is then refused, because only
	// an image already present may run as last-known-good.
	NeedFresh bool
	// Floor is the agent's own minimum version; "" means MinVersion.
	Floor string
}

// Result is a resolution.
type Result struct {
	// OK reports whether the image may be used.
	OK bool
	// Descriptor is the verified descriptor (set when OK).
	Descriptor Descriptor
	// Ref is the digest reference a run uses (set when OK).
	Ref string
	// Stale reports a last-known-good use of an expired manifest.
	Stale bool
	// Reason is a refusal's reason; Detail says more.
	Reason string
	Detail string
}

// RevokedBy names the signed manifest that revokes sha, for a refusal and
// for `observer sandbox status`: its kind, its version and, when the
// revocation gives one, its reason (R-015).
func RevokedBy(m content.Manifest, sha string) string {
	out := fmt.Sprintf("by the signed %s manifest version %d", m.Kind, m.ManifestVersion)
	for _, r := range m.Revoked {
		if strings.EqualFold(r.SHA256, sha) && r.Reason != "" {
			return out + " (reason: " + r.Reason + ")"
		}
	}
	return out
}

// IsRevokedRefusal reports whether a refusal line (Result.Error or
// VMSetResult.Error) is a revocation, so a status surface can show the row
// as revoked rather than as a generic unverified artifact.
func IsRevokedRefusal(line string) bool {
	return strings.Contains(line, VerdictArtifactUnverified+" ("+ReasonRevoked+")")
}

// RevokedRefBy is RevokedRef's naming half: the revoking manifest of ref's
// digest, "" when m does not revoke it.
func RevokedRefBy(m content.Manifest, ref string) string {
	_, digest, ok := strings.Cut(strings.TrimSpace(ref), "@sha256:")
	if !ok || !content.IsRevoked(m, digest) {
		return ""
	}
	return RevokedBy(m, digest)
}

// Error is the refusal as one line, verdict first.
func (r Result) Error() string {
	if r.OK {
		return ""
	}
	if r.Detail == "" {
		return VerdictArtifactUnverified + " (" + r.Reason + ")"
	}
	return VerdictArtifactUnverified + " (" + r.Reason + "): " + r.Detail
}

// pass is one resolution in progress.
type pass struct {
	in  Input
	d   Descriptor
	out Result
}

// resolveRule is one row of the resolution table: a non-empty reason
// refuses.
type resolveRule struct {
	name  string
	check func(p *pass) (reason, detail string)
}

// resolveRules are walked top-down; one test case per row.
var resolveRules = []resolveRule{
	{"installed", func(p *pass) (string, string) {
		if p.in.NotInstalled {
			return ReasonNotInstalled, "no signed sandbox.image manifest is installed; Observer's own default image is not published yet"
		}
		return "", ""
	}},
	{"manifest verifies", func(p *pass) (string, string) {
		if p.in.LoadErr == nil {
			return "", ""
		}
		if r := content.ReasonOf(p.in.LoadErr); r != "" {
			return string(r), p.in.LoadErr.Error()
		}
		return string(content.ContentReasonEnvelope), p.in.LoadErr.Error()
	}},
	{"manifest kind", func(p *pass) (string, string) {
		if p.in.Manifest.Kind != content.SandboxImage {
			return string(content.ContentReasonKind), fmt.Sprintf("the manifest is %q, not %q", p.in.Manifest.Kind, content.SandboxImage)
		}
		return "", ""
	}},
	{"freshness", func(p *pass) (string, string) {
		switch p.in.Freshness {
		case content.Fresh:
			return "", ""
		case content.Stale:
			if p.in.NeedFresh {
				return ReasonNeedsFresh, "the manifest has expired and the image is not present; only an image already present runs as last-known-good"
			}
			p.out.Stale = true
			return "", ""
		}
		return ReasonUnknownAge, "the manifest is past its age floor"
	}},
	{"descriptor covered", func(p *pass) (string, string) {
		if p.in.DescriptorErr == nil {
			return "", ""
		}
		if content.ReasonOf(p.in.DescriptorErr) == content.ContentReasonRevoked {
			return ReasonRevoked, p.in.DescriptorErr.Error()
		}
		if content.ReasonOf(p.in.DescriptorErr) == content.ContentReasonArtifact {
			return ReasonTampered, p.in.DescriptorErr.Error()
		}
		return ReasonDescriptor, p.in.DescriptorErr.Error()
	}},
	{"descriptor parses", func(p *pass) (string, string) {
		d, err := ParseDescriptor(p.in.Descriptor)
		if err != nil {
			return ReasonDescriptor, err.Error()
		}
		p.d = d
		return "", ""
	}},
	{"image digest not revoked", func(p *pass) (string, string) {
		if d := strings.TrimPrefix(p.d.Digest, "sha256:"); content.IsRevoked(p.in.Manifest, d) {
			return ReasonRevoked, "image " + p.d.Digest + " is revoked " + RevokedBy(p.in.Manifest, d)
		}
		for _, id := range p.d.ConfigDigests {
			if d := strings.TrimPrefix(id, "sha256:"); content.IsRevoked(p.in.Manifest, d) {
				return ReasonRevoked, "image id " + id + " is revoked " + RevokedBy(p.in.Manifest, d)
			}
		}
		return "", ""
	}},
	{"at or above the minimum", func(p *pass) (string, string) {
		v, _ := ParseVersion(p.d.Version)
		floor := p.in.Floor
		if floor == "" {
			floor = MinVersion
		}
		for _, m := range []string{floor, p.d.MinVersion} {
			mv, err := ParseVersion(m)
			if err != nil {
				return ReasonBelowMinimum, "the minimum version " + m + " cannot be read"
			}
			if v.Less(mv) {
				return ReasonBelowMinimum, fmt.Sprintf("image version %s is below the minimum %s", p.d.Version, m)
			}
		}
		return "", ""
	}},
	{"sbom covered", func(p *pass) (string, string) {
		if p.in.SBOMErr != nil {
			if content.ReasonOf(p.in.SBOMErr) == content.ContentReasonRevoked {
				return ReasonRevoked, p.in.SBOMErr.Error()
			}
			return ReasonSBOM, p.in.SBOMErr.Error()
		}
		if err := CheckSBOM(p.in.SBOM); err != nil {
			return ReasonSBOM, err.Error()
		}
		return "", ""
	}},
}

// Resolve decides whether the default image may be used. It never returns
// a reference for a refused image.
func Resolve(in Input) Result {
	p := &pass{in: in}
	for _, r := range resolveRules {
		if reason, detail := r.check(p); reason != "" {
			return Result{Reason: reason, Detail: detail}
		}
	}
	p.out.OK = true
	p.out.Descriptor = p.d
	p.out.Ref = p.d.Ref()
	return p.out
}

// ImageFacts is what the engine reports for the reference (GET
// /images/{ref}/json): whether it is present, its id and its repo digests.
type ImageFacts struct {
	Present     bool
	ID          string
	RepoDigests []string
	// Platform is the image's os/arch.
	Platform string
}

// ErrNotPresent is CheckEngineImage's refusal for an image the engine does
// not have.
var ErrNotPresent = errors.New("sandboximage: the image is not present in the engine")

// CheckEngineImage checks the engine's view of the verified image before a
// run: the image must be present, the engine must list the repository at
// the signed digest among its repo digests, and, where the descriptor names
// a per-platform id, the engine's id must equal it. A locally re-tagged or
// rebuilt image is refused as tampered.
func CheckEngineImage(d Descriptor, f ImageFacts) Result {
	switch {
	case !f.Present:
		return Result{Reason: ReasonNotPresent, Detail: "pull it by digest first: " + d.Ref()}
	case !hasRepoDigest(f.RepoDigests, d.Ref()):
		return Result{Reason: ReasonTampered, Detail: "the engine does not list " + d.Ref() + " for this image"}
	}
	if want, ok := d.ConfigDigests[f.Platform]; ok && !strings.EqualFold(want, f.ID) {
		return Result{Reason: ReasonTampered, Detail: fmt.Sprintf("the engine's image id %s is not the signed %s", f.ID, want)}
	}
	if len(d.ConfigDigests) > 0 {
		if _, ok := d.ConfigDigests[f.Platform]; !ok {
			return Result{Reason: ReasonTampered, Detail: "the signed descriptor names no image id for platform " + f.Platform}
		}
	}
	return Result{OK: true, Descriptor: d, Ref: d.Ref()}
}

func hasRepoDigest(list []string, ref string) bool {
	for _, r := range list {
		if r == ref {
			return true
		}
	}
	return false
}

// RevokedRef reports whether a loaded sandbox.image manifest revokes the
// digest of ref (any image pinned by digest, the configured one included),
// so an Observer image withdrawn by the project is refused at the next
// launch even where a developer pinned it by hand.
func RevokedRef(m content.Manifest, ref string) bool {
	_, digest, ok := strings.Cut(strings.TrimSpace(ref), "@sha256:")
	return ok && content.IsRevoked(m, digest)
}
