package secimage

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// Limits are the reader's caps. A cap that trips refuses the image
// (ReasonCapExceeded): a partial read is never reported as the image.
type Limits struct {
	// MaxInputBytes caps the tar file's size.
	MaxInputBytes int64
	// MaxOuterEntries caps the entries of the outer (image) tar.
	MaxOuterEntries int
	// MaxDocBytes caps manifest.json, index.json and a manifest blob.
	MaxDocBytes int64
	// MaxLayers caps the manifest's layer count.
	MaxLayers int
	// MaxEntries caps the layer entries walked, all layers together.
	MaxEntries int
	// MaxPathLen caps an entry's path; a longer one is refused.
	MaxPathLen int
	// MaxEntryBytes caps one extracted file.
	MaxEntryBytes int64
	// MaxOutputBytes caps everything extracted.
	MaxOutputBytes int64
	// MaxRatio caps one layer's decompressed bytes at MaxRatio times its
	// compressed size, above RatioFloor (a gzip or zstd bomb).
	MaxRatio   int64
	RatioFloor int64
	// MaxDecompressedBytes caps the decompressed bytes of all layers.
	MaxDecompressedBytes int64
}

// DefaultLimits are the production caps. The spike's largest image
// (buildpack-deps:noble, 271 MB compressed, 799 MB unpacked, 20,172
// entries, max layer ratio 22.9) sits far below every one of them.
func DefaultLimits() Limits {
	return Limits{
		MaxInputBytes:        16 << 30,
		MaxOuterEntries:      100_000,
		MaxDocBytes:          4 << 20,
		MaxLayers:            256,
		MaxEntries:           2_000_000,
		MaxPathLen:           4096,
		MaxEntryBytes:        512 << 20,
		MaxOutputBytes:       1 << 30,
		MaxRatio:             200,
		RatioFloor:           64 << 20,
		MaxDecompressedBytes: 64 << 30,
	}
}

// The closed Error.Reason vocabulary.
const (
	// ReasonNotAnImage: neither manifest.json nor index.json, or one that
	// does not parse.
	ReasonNotAnImage = "not_an_image"
	// ReasonMultipleImages: the tar holds more than one image (or an index
	// of several platforms); the developer saves one.
	ReasonMultipleImages = "multiple_images"
	// ReasonLayerMissing: the manifest names a layer the tar lacks.
	ReasonLayerMissing = "layer_missing"
	// ReasonCapExceeded: a Limits cap tripped.
	ReasonCapExceeded = "image_cap_exceeded"
	// ReasonCorrupt: a truncated or malformed tar, layer or document.
	ReasonCorrupt = "image_corrupt"
	// ReasonUnsafe: the manifest names a path outside the archive.
	ReasonUnsafe = "image_unsafe_path"
	// ReasonOutputFailed: the run directory could not be written.
	ReasonOutputFailed = "image_output_failed"
	// ReasonNotADirectory: a directory input that is not one.
	ReasonNotADirectory = "not_a_directory"
)

// Error is a refusal with a closed reason. Detail is a plain sentence for
// logs; surfaces show Reason.
type Error struct {
	Reason string
	Detail string
}

func (e *Error) Error() string { return "secimage: " + e.Reason + ": " + e.Detail }

func refuse(reason, format string, args ...any) error {
	return &Error{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// ReasonOf returns err's closed reason, "" for nil, ReasonCorrupt for an
// error this package did not classify.
func ReasonOf(err error) string {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ReasonCorrupt
}

// Result is what one read extracted.
type Result struct {
	// Format is "docker-save", "oci-layout" or "dir".
	Format string
	// Digest is "sha256:<hex>" of the image manifest for a tar (for an OCI
	// layout it equals the manifest's own digest); the caller sets it for
	// a directory (DirDigest).
	Digest string
	// Layers is the manifest's layer count (0 for a directory).
	Layers int
	// Files are the extracted paths, relative, forward slashes, sorted.
	Files []string
	// OSRelease is the parsed etc/os-release of the result (nil when the
	// image has none).
	OSRelease map[string]string
	// OSReleaseCopied: etc/os-release was a symlink or absent, so
	// usr/lib/os-release was copied there.
	OSReleaseCopied bool
	// RefusedWanted are allow-listed paths whose final entry the reader
	// could not use (a package database that is a link, a hard link to a
	// file the reader did not extract): the caller reports the image
	// partial, never clean. Sorted.
	RefusedWanted []string
	// Refused counts entries refused for their path or link target.
	Refused int
	// Whiteouts, OpaqueWhiteouts and RemovedByWhiteout count whiteout
	// handling between layers.
	Whiteouts, OpaqueWhiteouts, RemovedByWhiteout int
	// EntriesWalked counts layer entries read.
	EntriesWalked int
	// CompressedBytes and DecompressedBytes sum the layers.
	CompressedBytes, DecompressedBytes int64
	// Compression counts layers by compression ("gzip", "zstd", "none").
	Compression map[string]int
}

// The allow-list (plan section 6.2): the files the dpkg, apk and rpm
// extractors and osrelease read.
var (
	wantExact = map[string]bool{
		"etc/os-release":           true,
		"usr/lib/os-release":       true,
		"var/lib/dpkg/status":      true,
		"lib/apk/db/installed":     true,
		"var/lib/apk/db/installed": true,
		"usr/lib/apk/db/installed": true,
	}
	// wantDirAny: every file directly in the directory (distroless
	// status.d), except the md5sums the dpkg extractor skips.
	wantDirAny = []string{"var/lib/dpkg/status.d"}
	// rpmDirs and rpmNames: the rpm extractor's directories and the
	// database names it opens (with SQLite's journal files, which a
	// database copied without them may lose rows to).
	rpmDirs  = []string{"var/lib/rpm", "usr/lib/sysimage/rpm", "usr/share/rpm"}
	rpmNames = map[string]bool{
		"Packages": true, "Packages.db": true, "rpmdb.sqlite": true,
		"rpmdb.sqlite-wal": true, "rpmdb.sqlite-shm": true,
	}
)

// Wanted reports whether a cleaned relative path is on the allow-list.
func Wanted(p string) bool {
	if wantExact[p] {
		return true
	}
	dir, base := path.Split(p)
	dir = strings.TrimSuffix(dir, "/")
	for _, d := range wantDirAny {
		if dir == d && base != "" && !strings.HasSuffix(base, ".md5sums") {
			return true
		}
	}
	if rpmNames[base] {
		for _, d := range rpmDirs {
			if dir == d {
				return true
			}
		}
	}
	return false
}

// isPackageDB reports whether an allow-listed path is a package database
// (everything but the two os-release files), which must be a regular file.
func isPackageDB(p string) bool {
	return Wanted(p) && p != "etc/os-release" && p != "usr/lib/os-release"
}
