// Package sandboxhcs is the planner and the lazy C ABI loader of the `hcs`
// sandbox row (Hyper-V isolated containers through the Host Compute
// Service v2 compute system API; sandbox plan v2 plan 17.1 row 59, lane
// GATES-SBX decision 7): the probe ladder over gathered facts, the compute
// system documents (a utility VM with no network adapter and the container
// it hosts, the workspace and protected paths as mapped directories), and
// a loader for computecore.dll that resolves its functions lazily without
// CGO (loader_windows.go, golang.org/x/sys/windows, the internal/
// sandboxmxcdll precedent) and is used only in a per-run helper, never in
// the daemon.
//
// No utility VM image can be pinned and verified without a release
// artifact, so the probe refuses image_missing and the row is probe-only in
// this release. Apart from loader_windows.go the package is pure
// (imports_test.go pins it).
package sandboxhcs
