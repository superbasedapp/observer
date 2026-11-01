package sandboxmxc

// manifest.go is the sandbox plan section 12.3 entry for the bundled MXC
// files: the upstream package, its version and hash, and each file's hash,
// size and expected Authenticode signer. The release job fetches the
// package by this hash, checks each file's hash and signature, and bundles
// the files into the win32 artifacts of the distros that compile the
// driver (docs/release-runbook.md "The MXC files of the Windows sandbox
// driver"); the helper checks each
// file's hash again before anything is loaded or run. The same pins are
// written into scripts/mxc-files.sh, which the release workflow runs;
// TestManifestMatchesReleaseScript keeps them equal. A signed
// sandbox.native_files manifest (signed.go, lane SBX-P3D) may revoke this
// set, raise its minimum version and expire, but never name other files:
// these compiled pins stay the floor.

// File names of the bundled files (installed in BundleDir beside the
// observer executable).
const (
	FileFFI  = "mxc_ffi.dll"
	FileExec = "wxc-exec.exe"
	// BundleDir is the directory beside observer.exe that holds them.
	BundleDir = "mxc"
)

// BundledFile is one pinned file.
type BundledFile struct {
	Name string
	// PackagePath is the file's path inside the upstream package.
	PackagePath string
	SHA256      string
	Size        int64
}

// Manifest is the pinned upstream artifact set for one architecture.
type Manifest struct {
	// Upstream is the package the files come from.
	Upstream string
	Version  string
	// PackageURL and PackageSHA256 pin the package itself.
	PackageURL    string
	PackageSHA256 string
	// PackageIntegrity is the registry's own sha512 integrity string.
	PackageIntegrity string
	// Signer is the Authenticode subject every file must carry.
	Signer string
	// Arch is the Windows architecture these files are for.
	Arch  string
	Files []BundledFile
}

// ManifestX64 is the pinned set for windows/amd64: @microsoft/mxc-sdk
// 1.0.1 from the npm registry (its x64 files are byte-identical to the
// NuGet package Microsoft.Mxc.Sdk 1.0.1's runtimes/win-x64/native ones).
// Both files were checked to carry an Authenticode signature by Microsoft
// Corporation when they were pinned (2026-10-22).
var ManifestX64 = Manifest{
	Upstream:         "npm:@microsoft/mxc-sdk",
	Version:          "1.0.1",
	PackageURL:       "https://registry.npmjs.org/@microsoft/mxc-sdk/-/mxc-sdk-1.0.1.tgz",
	PackageSHA256:    "416d9607c9d4652395d95c3d9c5f5605f1f2f845da1a63228bee41b7392cef49",
	PackageIntegrity: "sha512-2cP925G5+lQyKzjBVha8uNtVd7XESgDBtgi1yCYYSo9M3xiFyZWtCO4SWPGTk509rdI6nqjyGcZxvEP3t6l8Hg==",
	Signer:           "Microsoft Corporation",
	Arch:             "x64",
	Files: []BundledFile{
		{Name: FileFFI, PackagePath: "package/bin/x64/mxc_ffi.dll", SHA256: "bd45522f06dc9cc8001dcd5d7320bc2bf303fb08a39bf10f3404bd9a8001812c", Size: 6123320},
		{Name: FileExec, PackagePath: "package/bin/x64/wxc-exec.exe", SHA256: "090f5d1f7bb93104ab08dcd4e8034ef954aeefcdaf6658dde5f7dff4cfc12f3a", Size: 12152632},
	},
}

// ManifestFor returns the pinned set for a GOARCH, or false (no pinned set:
// the row refuses with artifact_missing).
func ManifestFor(goarch string) (Manifest, bool) {
	if goarch == "amd64" {
		return ManifestX64, true
	}
	return Manifest{}, false
}

// File returns the pin for name.
func (m Manifest) File(name string) (BundledFile, bool) {
	for _, f := range m.Files {
		if f.Name == name {
			return f, true
		}
	}
	return BundledFile{}, false
}
