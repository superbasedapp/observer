package secengine

// The engine and the versions it is pinned at.
const (
	// Engine names the engine.
	Engine = "opengrep"
	// TestedVersion is the version JSP-8 measured: its flags, exit codes,
	// SARIF shape and extraction cache are what the driver relies on.
	TestedVersion = "1.30.1"
	// MinVersion: an older Opengrep is refused.
	MinVersion = TestedVersion
	// Issuer is the OIDC issuer of Opengrep's keyless signatures.
	Issuer = "https://token.actions.githubusercontent.com"
	// identityPrefix and identitySuffix frame the branch-form identity.
	identityPrefix = "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v"
	// releaseBase is the vendor's release download base.
	releaseBase = "https://github.com/opengrep/opengrep/releases/download/v"
)

// Identity is the pinned signing identity of a version: the branch form
// the release workflow signs from (JSP-8: a branch, not the tag).
func Identity(version string) string { return identityPrefix + version }

// PinStatus says whether a platform has a digest.
type PinStatus string

// The PinStatus values.
const (
	// PinPinned: a digest recorded after verification.
	PinPinned PinStatus = "pinned"
	// PinOwed: no digest yet (the platform's live check is owed); refused
	// as driver_unverified until a pin or a manifest fills it.
	PinOwed PinStatus = "pin_owed"
)

// Pin is one platform's release asset.
type Pin struct {
	Version string
	OS      string
	Arch    string
	// Asset is the release file name (JSP-8 read the names from the
	// release workflow at the tag).
	Asset  string
	SHA256 string
	Status PinStatus
	// Source says where the pin came from: "compiled" or "manifest".
	Source string
	// SizeBytes is the asset's exact size when a manifest entry states it
	// (0 for a compiled pin: JSP-8 recorded the size only to a tenth of a
	// megabyte). A guided install refuses a download larger than it.
	SizeBytes int64
	// ApproxBytes is the asset's size, about, as the install consent states
	// it before anything is downloaded (0: not known).
	ApproxBytes int64
	// TreeBytes and TreeFiles are the size and file count of the tree the
	// self-extracting bundle unpacks into its cache on its first run, as
	// measured (0: not measured on this platform).
	TreeBytes int64
	TreeFiles int
}

// URL is the vendor download URL of the pin's asset.
func (p Pin) URL() string { return releaseBase + p.Version + "/" + p.Asset }

// compiledPins is the pin table: JSP-8's linux amd64 digest, and every
// other platform the release publishes, owed. Asset names for the owed
// rows come from the v1.30.1 release workflow; their digests come from a
// verification run on that platform (run-elsewhere.sh) or an engine
// manifest.
var compiledPins = []Pin{
	{Version: TestedVersion, OS: "linux", Arch: "amd64", Asset: "opengrep_manylinux_x86", SHA256: "d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4", Status: PinPinned, Source: "compiled", ApproxBytes: 46_600_000, TreeBytes: 246_000_000, TreeFiles: 102},
	{Version: TestedVersion, OS: "linux", Arch: "arm64", Asset: "opengrep_manylinux_aarch64", Status: PinOwed, Source: "compiled"},
	{Version: TestedVersion, OS: "darwin", Arch: "arm64", Asset: "opengrep_osx_arm64", Status: PinOwed, Source: "compiled"},
	{Version: TestedVersion, OS: "darwin", Arch: "amd64", Asset: "opengrep_osx_x86", Status: PinOwed, Source: "compiled"},
	{Version: TestedVersion, OS: "windows", Arch: "amd64", Asset: "opengrep_windows_x86.exe", Status: PinOwed, Source: "compiled"},
}

// CompiledPins returns a copy of the pin table.
func CompiledPins() []Pin { return append([]Pin(nil), compiledPins...) }

// CompiledPin returns the compiled pin row of a platform.
func CompiledPin(goos, goarch string) (Pin, bool) {
	for _, p := range compiledPins {
		if p.OS == goos && p.Arch == goarch {
			return p, true
		}
	}
	return Pin{}, false
}
