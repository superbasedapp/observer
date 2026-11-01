package seciac

import "strings"

// PinStatus says whether a platform has a digest (the secengine shape).
type PinStatus string

// The PinStatus values.
const (
	// PinPinned: a digest recorded after the asset and its checksum were
	// fetched and compared (or a verified manifest entry).
	PinPinned PinStatus = "pinned"
	// PinOwed: no digest yet. A managed node refuses the engine
	// (driver_unverified); an individual node runs one it finds, labelled.
	PinOwed PinStatus = "pin_owed"
)

// Archive formats of a release asset.
const (
	ArchiveTarGz = "tar.gz"
	ArchiveZip   = "zip"
)

// Pin is one platform's release asset of one engine version.
type Pin struct {
	Engine  EngineID
	Version string
	OS      string
	Arch    string
	// Asset is the release file name; Format its archive format; Member
	// the executable's name inside it.
	Asset  string
	Format string
	Member string
	// AssetSHA256 is the archive's digest (what the download is checked
	// against); BinarySHA256 the extracted executable's (what a run is
	// decided on). A manifest entry states only the archive's: the guided
	// install records the binary it extracted from a verified archive.
	AssetSHA256  string
	BinarySHA256 string
	Status       PinStatus
	// Source is "compiled" or "manifest".
	Source string
	// SizeBytes is exact when a manifest entry states it; ApproxBytes is
	// the size the consent states before anything is downloaded.
	SizeBytes   int64
	ApproxBytes int64
	// DigestOnly: the engine publishes no signature, so the pin rests on
	// its digest alone (labelled wherever it is shown).
	DigestOnly bool
}

// URL is the vendor download URL of the pin's asset ("" when the engine
// publishes no release binaries).
func (p Pin) URL() string {
	e, ok := Lookup(p.Engine)
	if !ok || e.ReleaseBase == "" || p.Asset == "" {
		return ""
	}
	return e.ReleaseBase + strings.TrimPrefix(p.Version, "v") + "/" + p.Asset
}

// BundleURL is the URL of the asset's sigstore bundle ("" when the engine
// publishes none).
func (p Pin) BundleURL() string {
	e, ok := Lookup(p.Engine)
	if !ok || e.Signature != SigCosignKeylessBundle || p.URL() == "" {
		return ""
	}
	return p.URL() + ".sigstore.json"
}

// trivyAsset is Trivy's goreleaser archive name at the tag (goreleaser.yml
// at v0.75.0: Linux / macOS / windows, 64bit / ARM64; zip on Windows).
func trivyAsset(version, goos, goarch string) (asset, format string) {
	osName := map[string]string{"linux": "Linux", "darwin": "macOS", "windows": "windows"}[goos]
	archName := map[string]string{"amd64": "64bit", "arm64": "ARM64"}[goarch]
	format = ArchiveTarGz
	if goos == "windows" {
		format = ArchiveZip
	}
	return "trivy_" + version + "_" + osName + "-" + archName + "." + format, format
}

func trivyPin(goos, goarch, assetSHA256, binarySHA256 string) Pin {
	e, _ := Lookup(Trivy)
	asset, format := trivyAsset(e.TestedVersion, goos, goarch)
	member := "trivy"
	if goos == "windows" {
		member = "trivy.exe"
	}
	return Pin{
		Engine: Trivy, Version: e.TestedVersion, OS: goos, Arch: goarch, Asset: asset, Format: format, Member: member,
		AssetSHA256: assetSHA256, BinarySHA256: binarySHA256,
		Status: PinPinned, Source: "compiled", ApproxBytes: e.ApproxBytes,
	}
}

// SourceOrgMirrorRow is the Source of a compiled row that only names the
// archive an org mirror must publish: the vendor releases no binary, so the
// row carries no digest (pin_owed) and no download URL, and a pin arrives
// only through the org mirror's signed security.engine manifest.
const SourceOrgMirrorRow = "org_mirror"

// MirrorAsset is the archive name an org mirror publishes for an engine
// with no vendor release binaries: <binary>_<version>_<GOOS>_<GOARCH>,
// .zip on Windows and .tar.gz elsewhere (Observer's convention; KICS
// v2.2.0 defines none). The archive holds the executable at its root.
func MirrorAsset(e Engine, goos, goarch string) (asset, format string) {
	format = ArchiveTarGz
	if goos == "windows" {
		format = ArchiveZip
	}
	return e.Binary + "_" + e.TestedVersion + "_" + goos + "_" + goarch + "." + format, format
}

// kicsMirrorPin is the org mirror row of one KICS platform (lane LEFT2-SEC
// item R-018): pin owed and digest-only, because KICS v2.2.0 publishes no
// release binaries and no signature; a managed node installs KICS only
// from its org mirror's manifest entry for the platform.
func kicsMirrorPin(goos, goarch string) Pin {
	e, _ := Lookup(KICS)
	asset, format := MirrorAsset(e, goos, goarch)
	member := e.Binary
	if goos == "windows" {
		member += ".exe"
	}
	return Pin{
		Engine: KICS, Version: e.TestedVersion, OS: goos, Arch: goarch, Asset: asset, Format: format, Member: member,
		Status: PinOwed, Source: SourceOrgMirrorRow, DigestOnly: true,
	}
}

// compiledPins is the pin table.
//
// Trivy 0.75.0 (lane LEFT2-SEC item R-018, 2026-10-25): each archive was
// fetched from https://github.com/aquasecurity/trivy/releases/download/
// v0.75.0/<asset>, its sha256 compared with that release's
// trivy_0.75.0_checksums.txt (all five agree), and its
// <asset>.sigstore.json bundle passed PrecheckBundle (secengine.Precheck)
// under the pinned identity
// https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.75.0
// and issuer https://token.actions.githubusercontent.com. BinarySHA256 is
// the executable extracted from that archive. The full online cosign
// verification (the Rekor entry) was not run; the install pre-checks the
// bundle again before it places a binary.
//
// KICS 2.2.0 publishes no release binaries (its getting-started page at
// the tag offers the Docker image or a source build, and no
// releases/download asset exists), so its rows only name what an org
// mirror must publish; they stay pin_owed and are never downloaded from
// anywhere but the mirror.
var compiledPins = []Pin{
	trivyPin("linux", "amd64", "c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f", "93f9da8e4ba5e0c1c76d8234ed2494cf9afb0a96fd21953e424bb795f3299b8e"),
	trivyPin("linux", "arm64", "a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3", "869e310e208f0f2e3e90e4f842cc6adaa2b2c046fecbaade481e6b23fcc8f2a9"),
	trivyPin("darwin", "arm64", "4a77108cccf8e55c8d6823e1e759939a622277e66cd0daa3c1fc621ed69e4568", "32b84c068e11e5381fc85d3fe2e8ac238659ab22524ce1b2b9dfcbd0b1f7331a"),
	trivyPin("darwin", "amd64", "291edaa9778acbe4693d067b5ad60ee11570e5ac68296e85595417528ca641e4", "484287e06ab2e4038c42ba396da8637aaaca0967e3e65840563706a0284169b4"),
	trivyPin("windows", "amd64", "4e43bd71a30f51aee39525f60f2b47043af77eb8df8fe082aae4372b69c6660f", "3b4fcf6fec53c4c73c325cfd518c7264100695b19e6c59c6a777e4a67dc9f0e6"),
	kicsMirrorPin("linux", "amd64"),
	kicsMirrorPin("linux", "arm64"),
	kicsMirrorPin("darwin", "arm64"),
	kicsMirrorPin("darwin", "amd64"),
	kicsMirrorPin("windows", "amd64"),
}

// CompiledPins returns a copy of the pin table of engine.
func CompiledPins(engine EngineID) []Pin {
	var out []Pin
	for _, p := range compiledPins {
		if p.Engine == engine {
			out = append(out, p)
		}
	}
	return out
}

// pinFor returns the row of a platform in pins.
func pinFor(pins []Pin, goos, goarch string) (Pin, bool) {
	for _, p := range pins {
		if p.OS == goos && p.Arch == goarch {
			return p, true
		}
	}
	return Pin{}, false
}
