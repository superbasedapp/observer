package sandboximage

import (
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// ManifestInput is one sandbox.image publication.
type ManifestInput struct {
	Descriptor []byte
	SBOM       []byte
	// ManifestVersion is the kind's monotonic publish counter; Epoch its
	// data epoch.
	ManifestVersion, Epoch int64
	// Issued is the issue time; Valid the life (at most the kind's
	// MaxValidity, required: an expiry is never optional).
	Issued time.Time
	Valid  time.Duration
	// Revoked withdraws earlier artifacts by digest.
	Revoked []content.Revocation
}

// BuildManifest assembles the unsigned sandbox.image manifest that covers
// the descriptor and the SBOM, after checking both. Signing is
// content.Sign, with the vendor key at the release step (or a test key in
// a test).
func BuildManifest(in ManifestInput) (content.Manifest, error) {
	d, err := ParseDescriptor(in.Descriptor)
	if err != nil {
		return content.Manifest{}, err
	}
	if err := CheckSBOM(in.SBOM); err != nil {
		return content.Manifest{}, err
	}
	spec, _ := content.KindOf(content.SandboxImage)
	if in.Valid <= 0 || in.Valid > spec.MaxValidity {
		return content.Manifest{}, fmt.Errorf("sandboximage: the validity must be set and at most %s", spec.MaxValidity)
	}
	if in.ManifestVersion < 1 || in.Epoch < 1 {
		return content.Manifest{}, errors.New("sandboximage: the manifest version and epoch start at 1")
	}
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.SandboxImage, ManifestVersion: in.ManifestVersion, Epoch: in.Epoch,
		IssuedAt:  in.Issued.UTC().Format(time.RFC3339),
		ExpiresAt: in.Issued.Add(in.Valid).UTC().Format(time.RFC3339),
		Entries: []content.Entry{
			{
				Name: DescriptorName, Version: d.Version, SizeBytes: int64(len(in.Descriptor)), SHA256: content.HashBytes(in.Descriptor),
				Source: d.Repository + "@" + d.Digest, License: "Apache-2.0", Upstream: content.UpstreamCheck{Method: content.UpstreamNone},
			},
			{
				Name: SBOMName, Version: d.Version, SizeBytes: int64(len(in.SBOM)), SHA256: content.HashBytes(in.SBOM),
				Source: d.Recipe + "@" + d.SourceCommit, License: "CC0-1.0", Upstream: content.UpstreamCheck{Method: content.UpstreamNone},
			},
		},
		Revoked: in.Revoked,
	}
	content.SortEntries(m.Entries)
	if err := content.Validate(m); err != nil {
		return content.Manifest{}, err
	}
	return m, nil
}
