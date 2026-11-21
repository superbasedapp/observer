package sandboxsetup

// pins.go is the compiled download pin table (plan sections 3.2 and 4.11,
// decision O2=B: vendor release assets pinned by sha256 and size compiled
// into each Observer release, Cloud Hypervisor only in this arc). It never
// names "latest" or a moving tag: every grounded row is one exact asset of
// one exact release, and its digest is one this lane computed itself.
//
// Grounding (2026-11-06, lane sbxinstall-download): both assets of the
// Cloud Hypervisor v54.0 release
// (github.com/cloud-hypervisor/cloud-hypervisor, tag v54.0, the version
// the cloud-hypervisor registry row's DriverPins name: RequiredMin,
// TestedLow and TestedHigh all "54") were downloaded through the release
// download URL below, which redirects once to
// release-assets.githubusercontent.com. Each file was hashed with
// sha256sum, its size recorded from the byte count, and the transfer
// cross-checked against the asset store's own Content-MD5 header
// (amd64 NvSyob4vSvV5k0hD8LGP1Q==, arm64 kbk5Q178yi16I/M/TnPk7w==, both
// equal to the MD5 of the bytes received; asset Last-Modified 2026-10-14).
// `file` reports a static x86-64 ELF and a static aarch64 ELF, and the
// amd64 binary embeds the version string "54.0". The release publishes no
// checksum file (SHA256SUMS, sha256sums.txt, checksums.txt and
// cloud-hypervisor-static.sha256 all answer 404) and the GitHub API was not
// reachable from the grounding session, so the API's per-asset digest was
// not cross-checked: the sha256 below is this lane's own computation, and
// the release assets are not signed upstream (Signer "").

// pinCloudHypervisor is the pin id the cloud-hypervisor prerequisite's
// pinned_download remedy names (prereqs.go).
const pinCloudHypervisor = "cloud-hypervisor"

// compiledPins is this release's pin table. An owed row (Status PinOwed)
// carries a Version and a URL only and never downloads.
var compiledPins = []Pin{
	{
		ID: pinCloudHypervisor, Version: "54.0", GOOS: "linux", GOARCH: "amd64",
		URL:    "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.0/cloud-hypervisor-static",
		SHA256: "4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b",
		Size:   7365360,
		Status: PinGrounded,
	},
	{
		ID: pinCloudHypervisor, Version: "54.0", GOOS: "linux", GOARCH: "arm64",
		URL:    "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.0/cloud-hypervisor-static-aarch64",
		SHA256: "e8a6d9786ea678e739f1a386682846e93742dcb9c7b6e3e0c62e3bda6cff0ef3",
		Size:   5824616,
		Status: PinGrounded,
	},
}

func init() { pins = append(pins, compiledPins...) }

// Pins returns a copy of the compiled pin table, for the egress lane's
// host check and the cmd-side placement; the planner reads it through
// pinMatching.
func Pins() []Pin { return append([]Pin(nil), compiledPins...) }
