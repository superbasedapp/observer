// Package secimage is the selective layer reader of OS-package scanning in
// container images (OS and CI vulnerability scanning plan sections 6.2 and
// 6.6.1, spike JSP-OS): Observer never links a container client, talks to
// no daemon and pulls from no registry, so an image reaches the scanner as
// a tar the developer or CI produced (`docker save`, `podman save`, an OCI
// layout from `skopeo copy` or `buildx --output type=oci`), or as a root
// filesystem directory.
//
// Flatten walks a tar's manifest layers in order (gzip, zstd or
// uncompressed) and extracts ONLY the allow-listed files the OS package
// extractors read (Wanted: the two os-release files, the dpkg status file
// and status.d directory, the apk installed database, the rpm databases),
// applying whiteouts (.wh.<name>, .wh..wh..opq) between layers; everything
// else is decompressed and skipped unread. ReadRoot reads the same
// allow-list from a directory, read-confined, with no flattening. Both
// always create etc/ and copy usr/lib/os-release to etc/os-release when
// etc/os-release is a symlink or absent: OSV-SCALIBR's osrelease refuses a
// root with no etc/, and etc/os-release is a symlink on every distribution
// but Alpine.
//
// Safety rules, each a refusal and never a best effort:
//
//   - caps (Limits): total input, outer entries, document size, layer
//     count, entries walked, path length, per-entry size, total output,
//     the per-layer decompression ratio (a gzip or zstd bomb) and the total
//     decompressed bytes; a cap that trips refuses the image;
//   - a layer entry with an absolute path, a ".." segment or a NUL is
//     refused (counted, never written); a hard link whose target leaves the
//     root is refused; links are never followed and never written: the
//     output holds regular files and directories only, written through a
//     Sink (DirSink confines every write to the run directory with os.Root);
//   - a package database must be a regular file: one that is a link the
//     reader cannot resolve to an extracted regular file is reported in
//     Result.RefusedWanted, so the caller reports the image partial, never
//     clean;
//   - a manifest naming a layer the tar lacks is not scanned
//     (ReasonLayerMissing), never clean.
//
// The package is pure apart from the reader and the sink it is handed: no
// database, network, process execution or file watching (imports_test.go
// pins it). Its only importer is cmd/observer's `observer security scan
// image`, compiled out with sbo_omit_security_scan_os.
package secimage
