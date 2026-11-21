package cloudsession

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// npm.go is the npm install source of the setup script. Live grounding
// (CA-A2) found that a Claude Code cloud session at its default network
// level reaches registry.npmjs.org but is refused GitHub release assets, and
// that the npm platform packages carry no SHA256SUMS or vendor signature. So
// the default install fetches the platform package tarball straight from the
// registry and checks it against the sha512 the registry published for that
// exact version (dist.integrity), pinned into the committed script by `init`
// on the developer's machine. A vendor signature inside the package is
// verified too when one is present (the proposal in
// docs/plans/cloud-agents/npm-vendor-signature-proposal-2026-10-31.md).

// InstallSource is where the setup script fetches observer from.
type InstallSource string

// The install sources.
const (
	// InstallNpm fetches the npm platform package tarball and checks it
	// against the pinned dist.integrity (sha512). The default: the registry
	// is reachable at the default network level of the sandboxes grounded
	// so far.
	InstallNpm InstallSource = "npm"
	// InstallRelease fetches the release archive and checks its sha256
	// (SHA256SUMS) and raw Ed25519 vendor signature: for hosts that can
	// reach the release assets (a Copilot setup step, a Claude Code
	// environment with the release host allowed).
	InstallRelease InstallSource = "release"
)

// InstallSources returns every install source, default first.
func InstallSources() []InstallSource { return []InstallSource{InstallNpm, InstallRelease} }

// DefaultNpmRegistry is the npm registry the setup script fetches from.
const DefaultNpmRegistry = "https://registry.npmjs.org"

// npmScope and npmPlatformPrefix name the per-platform packages
// (npm/observer-linux-<arch>/package.json).
const (
	npmScope          = "@superbased"
	npmPlatformPrefix = "observer-linux-"
)

// NpmArches are the Linux architectures the npm platform packages ship, in
// the setup script's spelling (uname -m x86_64 is x64, aarch64 is arm64).
var NpmArches = []string{"x64", "arm64"}

// NpmPin is the pinned integrity of one platform package version.
type NpmPin struct {
	// Arch is x64 or arm64.
	Arch string
	// Integrity is the registry's dist.integrity, "sha512-<base64>".
	Integrity string
}

func knownArch(arch string) bool {
	for _, a := range NpmArches {
		if a == arch {
			return true
		}
	}
	return false
}

// npmVersion is the package version of a release tag ("v1.36.0" -> "1.36.0").
func npmVersion(tag string) string { return strings.TrimPrefix(tag, "v") }

// NpmMetadataURL is the registry document of one platform package version,
// the one `init` reads dist.integrity from.
func NpmMetadataURL(registry, arch, tag string) string {
	return strings.TrimRight(registry, "/") + "/" + url.PathEscape(npmScope+"/"+npmPlatformPrefix+arch) + "/" + npmVersion(tag)
}

// NpmTarballURL is where the registry serves one platform package version.
func NpmTarballURL(registry, arch, tag string) string {
	pkg := npmPlatformPrefix + arch
	return strings.TrimRight(registry, "/") + "/" + npmScope + "/" + pkg + "/-/" + pkg + "-" + npmVersion(tag) + ".tgz"
}

// IntegritySHA512Hex turns an npm "sha512-<base64>" integrity string into
// the hex digest sha512sum prints. Any other algorithm is refused: sha1
// shasum is not an integrity pin.
func IntegritySHA512Hex(integrity string) (string, error) {
	integrity = strings.TrimSpace(integrity)
	// An SRI string may list several hashes; npm writes one.
	if strings.ContainsAny(integrity, " \t\n") {
		return "", fmt.Errorf("cloudsession: npm integrity %q lists more than one hash", integrity)
	}
	b64, ok := strings.CutPrefix(integrity, "sha512-")
	if !ok {
		return "", fmt.Errorf("cloudsession: npm integrity must be sha512-<base64>, got %q", integrity)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 64 {
		return "", fmt.Errorf("cloudsession: npm integrity %q is not base64 of a 64-byte sha512", integrity)
	}
	return hex.EncodeToString(raw), nil
}

// ParseNpmVersionMetadata reads the pin out of a registry version document
// (the body of NpmMetadataURL). It checks that the document is the package
// and version asked for and that dist.tarball is exactly NpmTarballURL, so
// the committed script fetches from the place the pin was read for.
func ParseNpmVersionMetadata(body []byte, registry, arch, tag string) (NpmPin, error) {
	var doc struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Dist    struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return NpmPin{}, fmt.Errorf("cloudsession: npm metadata: %w", err)
	}
	wantName := npmScope + "/" + npmPlatformPrefix + arch
	switch {
	case doc.Name != wantName:
		return NpmPin{}, fmt.Errorf("cloudsession: npm metadata is for %q, want %q", doc.Name, wantName)
	case doc.Version != npmVersion(tag):
		return NpmPin{}, fmt.Errorf("cloudsession: npm metadata is for version %q, want %q", doc.Version, npmVersion(tag))
	case doc.Dist.Tarball != NpmTarballURL(registry, arch, tag):
		return NpmPin{}, fmt.Errorf("cloudsession: npm tarball %q is not %q", doc.Dist.Tarball, NpmTarballURL(registry, arch, tag))
	}
	if _, err := IntegritySHA512Hex(doc.Dist.Integrity); err != nil {
		return NpmPin{}, err
	}
	return NpmPin{Arch: arch, Integrity: doc.Dist.Integrity}, nil
}

// validateNpm checks the npm options of PlanOptions.
func validateNpm(registry string, pins []NpmPin) error {
	if registry != "" {
		u, err := url.Parse(registry)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
			strings.ContainsAny(registry, " \t\n'\"$`\\") {
			return fmt.Errorf("cloudsession: --npm-registry must be a plain https URL")
		}
	}
	if len(pins) == 0 {
		return fmt.Errorf("cloudsession: the npm install needs the pinned dist.integrity of at least one platform package (init reads it from the registry; offline, pass --npm-integrity x64=sha512-...)")
	}
	seen := map[string]bool{}
	for _, p := range pins {
		if !knownArch(p.Arch) {
			return fmt.Errorf("cloudsession: npm pin for unknown architecture %q (want one of %v)", p.Arch, NpmArches)
		}
		if seen[p.Arch] {
			return fmt.Errorf("cloudsession: two npm pins for %s", p.Arch)
		}
		seen[p.Arch] = true
		if _, err := IntegritySHA512Hex(p.Integrity); err != nil {
			return err
		}
	}
	return nil
}

// npmPinHex returns the hex sha512 pinned for arch, "" when none is.
func npmPinHex(pins []NpmPin, arch string) string {
	for _, p := range pins {
		if p.Arch == arch {
			h, _ := IntegritySHA512Hex(p.Integrity)
			return h
		}
	}
	return ""
}
