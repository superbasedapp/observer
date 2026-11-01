package sandboximage

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// vmmanifest.go builds the two unsigned manifests of a guest image set
// (lane SBX-P4 decision 2): ONE sandbox.rootfs manifest over the
// descriptor, the SBOM, the kernel, the initramfs, the rootfs and its
// verity tree; ONE sandbox.guest_binary manifest with one entry per
// architecture, its version the host agent's. Signing is content.Sign with
// the vendor key at the release step (scripts/vendorsign sandboxrootfs and
// sandboxguest), or a test key in a test.

// FileFacts is one bulk entry's measured size and digest (streamed by the
// caller, never held in memory).
type FileFacts struct {
	SizeBytes int64
	SHA256    string
}

// RootfsManifestInput is one sandbox.rootfs publication.
type RootfsManifestInput struct {
	Descriptor []byte
	SBOM       []byte
	// Files are the four bulk entries (kernel, initramfs, rootfs, verity).
	Files                  map[string]FileFacts
	ManifestVersion, Epoch int64
	Issued                 time.Time
	Valid                  time.Duration
	Revoked                []content.Revocation
}

// vmBulkEntries are the bulk entries a rootfs manifest must cover.
var vmBulkEntries = []string{VMKernelName, VMInitramfsName, VMRootfsName, VMVerityName}

func checkWindow(kind content.Kind, version, epoch int64, valid time.Duration) error {
	spec, _ := content.KindOf(kind)
	if valid <= 0 || valid > spec.MaxValidity {
		return fmt.Errorf("sandboximage: the validity must be set and at most %s", spec.MaxValidity)
	}
	if version < 1 || epoch < 1 {
		return errors.New("sandboximage: the manifest version and epoch start at 1")
	}
	return nil
}

func checkFacts(name string, f FileFacts) error {
	if f.SizeBytes <= 0 || f.SizeBytes > vmEntryCaps[name] {
		return fmt.Errorf("sandboximage: %s is %d bytes, over its cap %d or empty", name, f.SizeBytes, vmEntryCaps[name])
	}
	if !hexRE.MatchString(f.SHA256) {
		return fmt.Errorf("sandboximage: %s has no sha256", name)
	}
	return nil
}

// BuildRootfsManifest assembles the unsigned sandbox.rootfs manifest.
func BuildRootfsManifest(in RootfsManifestInput) (content.Manifest, error) {
	d, err := ParseVMDescriptor(in.Descriptor)
	if err != nil {
		return content.Manifest{}, err
	}
	if err := CheckSBOM(in.SBOM); err != nil {
		return content.Manifest{}, err
	}
	if err := checkWindow(content.SandboxRootfs, in.ManifestVersion, in.Epoch, in.Valid); err != nil {
		return content.Manifest{}, err
	}
	entries := []content.Entry{
		{Name: VMDescriptorName, Version: d.Version, SizeBytes: int64(len(in.Descriptor)), SHA256: content.HashBytes(in.Descriptor), Source: d.Recipe + "@" + d.SourceCommit, License: "Apache-2.0", Upstream: content.UpstreamCheck{Method: content.UpstreamNone}},
		{Name: VMSBOMName, Version: d.Version, SizeBytes: int64(len(in.SBOM)), SHA256: content.HashBytes(in.SBOM), Source: d.Recipe + "@" + d.SourceCommit, License: "CC0-1.0", Upstream: content.UpstreamCheck{Method: content.UpstreamNone}},
	}
	for _, name := range vmBulkEntries {
		f, ok := in.Files[name]
		if !ok {
			return content.Manifest{}, fmt.Errorf("sandboximage: the image set has no %s", name)
		}
		if err := checkFacts(name, f); err != nil {
			return content.Manifest{}, err
		}
		lic := "GPL-2.0-only"
		if name == VMRootfsName || name == VMVerityName {
			lic = "NOASSERTION"
		}
		entries = append(entries, content.Entry{Name: name, Version: d.Version, OS: "linux", Arch: d.Arch, SizeBytes: f.SizeBytes, SHA256: f.SHA256, Source: d.Recipe + "@" + d.SourceCommit, License: lic, Upstream: content.UpstreamCheck{Method: content.UpstreamNone}})
	}
	if len(in.Files) != len(vmBulkEntries) {
		return content.Manifest{}, errors.New("sandboximage: the image set lists files beyond the kernel, initramfs, rootfs and verity tree")
	}
	return finishManifest(content.SandboxRootfs, in.ManifestVersion, in.Epoch, in.Issued, in.Valid, entries, in.Revoked)
}

// GuestManifestInput is one sandbox.guest_binary publication.
type GuestManifestInput struct {
	// Version is the agent release the guest binaries were built from.
	Version string
	// Commit is the source commit.
	Commit string
	// Binaries are per architecture (amd64, arm64).
	Binaries               map[string]FileFacts
	ManifestVersion, Epoch int64
	Issued                 time.Time
	Valid                  time.Duration
	Revoked                []content.Revocation
}

// BuildGuestManifest assembles the unsigned sandbox.guest_binary manifest.
func BuildGuestManifest(in GuestManifestInput) (content.Manifest, error) {
	if _, err := ParseVersion(in.Version); err != nil {
		return content.Manifest{}, err
	}
	if !commitRE.MatchString(in.Commit) {
		return content.Manifest{}, fmt.Errorf("sandboximage: commit %q is not a full hex commit id", in.Commit)
	}
	if err := checkWindow(content.SandboxGuest, in.ManifestVersion, in.Epoch, in.Valid); err != nil {
		return content.Manifest{}, err
	}
	if len(in.Binaries) == 0 {
		return content.Manifest{}, errors.New("sandboximage: no guest binary")
	}
	arches := make([]string, 0, len(in.Binaries))
	for a := range in.Binaries {
		arches = append(arches, a)
	}
	sort.Strings(arches)
	var entries []content.Entry
	for _, a := range arches {
		if !archRE.MatchString(a) {
			return content.Manifest{}, fmt.Errorf("sandboximage: arch %q is not amd64 or arm64", a)
		}
		if err := checkFacts(GuestBinaryName, in.Binaries[a]); err != nil {
			return content.Manifest{}, err
		}
		f := in.Binaries[a]
		entries = append(entries, content.Entry{Name: GuestBinaryName, Version: in.Version, OS: "linux", Arch: a, SizeBytes: f.SizeBytes, SHA256: f.SHA256, Source: "cmd/observer@" + in.Commit, License: "NOASSERTION", Upstream: content.UpstreamCheck{Method: content.UpstreamNone}})
	}
	return finishManifest(content.SandboxGuest, in.ManifestVersion, in.Epoch, in.Issued, in.Valid, entries, in.Revoked)
}

func finishManifest(kind content.Kind, version, epoch int64, issued time.Time, valid time.Duration, entries []content.Entry, revoked []content.Revocation) (content.Manifest, error) {
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: kind, ManifestVersion: version, Epoch: epoch,
		IssuedAt: issued.UTC().Format(time.RFC3339), ExpiresAt: issued.Add(valid).UTC().Format(time.RFC3339),
		Entries: entries, Revoked: revoked,
	}
	content.SortEntries(m.Entries)
	if err := content.Validate(m); err != nil {
		return content.Manifest{}, err
	}
	return m, nil
}
