package seciac

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// ManifestPins is what a verified security.engine manifest says about one
// IaC engine: its pins per platform and the digests it revokes.
type ManifestPins struct {
	Pins    []Pin
	Revoked []string
	// Version is the manifest's publish counter.
	Version int64
}

// EntryPrefix is the name prefix of an engine's entries in the shared
// manifest: secengine reads only "opengrep" entries, and seciac only its
// own engine's.
func EntryPrefix(e EngineID) string { return string(e) }

// upstreamRule is what an engine's manifest entry must carry, by signature
// method: an entry checked any other way is refused, so a manifest cannot
// pin a digest it did not verify the way the engine's release allows.
var upstreamRules = map[SignatureMethod]func(e Engine, en content.Entry) bool{
	SigCosignKeylessBundle: func(e Engine, en content.Entry) bool {
		u := en.Upstream
		return u.Method == content.UpstreamCosignKeylessOnline && u.Identity == e.Identity(en.Version) && u.Issuer == e.Issuer
	},
	SigNone: func(_ Engine, en content.Entry) bool {
		// The release checksum file, carried whole (digest-only).
		return en.Upstream.Method == content.UpstreamSHA256Sums
	},
}

// formatOf reads an archive format from an asset name.
func formatOf(name string) string {
	switch {
	case strings.HasSuffix(name, ".tar.gz"):
		return ArchiveTarGz
	case strings.HasSuffix(name, ".zip"):
		return ArchiveZip
	}
	return ""
}

// FromManifest reads a verified engine manifest for engine id. Entries of
// another engine are skipped; an entry of this engine that lacks a version,
// a platform, an archive format or the engine's upstream check is refused.
func FromManifest(m content.Manifest, id EngineID) (ManifestPins, error) {
	e, ok := Lookup(id)
	if !ok {
		return ManifestPins{}, fmt.Errorf("seciac.FromManifest: unknown engine %q", id)
	}
	if m.Kind != content.Engine {
		return ManifestPins{}, fmt.Errorf("seciac.FromManifest: kind %q", m.Kind)
	}
	out := ManifestPins{Version: m.ManifestVersion}
	for _, en := range m.Entries {
		if !strings.HasPrefix(en.Name, EntryPrefix(id)) {
			continue // another engine's entry in the shared manifest
		}
		format := formatOf(en.Name)
		if secengine.ParseVersion(en.Version) == nil || en.OS == "" || en.Arch == "" || format == "" {
			return ManifestPins{}, fmt.Errorf("seciac.FromManifest: entry %q needs a version, an OS, an arch and a .tar.gz or .zip name", en.Name)
		}
		if rule := upstreamRules[e.Signature]; rule == nil || !rule(e, en) {
			return ManifestPins{}, fmt.Errorf("seciac.FromManifest: entry %q was not checked the way %s releases allow (%s)", en.Name, e.Title, e.Signature)
		}
		member := e.Binary
		if en.OS == "windows" {
			member += ".exe"
		}
		out.Pins = append(out.Pins, Pin{
			Engine: id, Version: strings.TrimPrefix(en.Version, "v"), OS: en.OS, Arch: en.Arch, Asset: en.Name, Format: format, Member: member,
			AssetSHA256: strings.ToLower(en.SHA256), Status: PinPinned, Source: "manifest", SizeBytes: en.SizeBytes, ApproxBytes: en.SizeBytes,
			DigestOnly: e.Signature == SigNone,
		})
	}
	out.Revoked = secengine.RevocationsOf(m)
	return out, nil
}
