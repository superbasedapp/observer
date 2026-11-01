// Package sandboxmxc is the pure planner of the MXC ProcessContainer
// sandbox driver (sandbox plan v2 sections 4.2, 4.7, 5.2, 7.3 and 13 P6;
// lane SBX-P6): Microsoft Execution Containers on Windows 11, driven
// through MXC's own C ABI (mxc_ffi) for the version, the probe and the
// validation, and through `wxc-exec --config <file>` (an owner-only file,
// never the document on a command line) inside an Observer-owned ConPTY for
// the interactive run.
//
// It holds only decisions over data, never I/O:
//
//   - the MXC config document of the published "1.0.0" contract that one
//     run is started with (document.go), with fallback.allowDaclMutation
//     always false, so MXC never rewrites host ACLs;
//   - the version contract: the library version mxc_version() reports
//     against the row's pins, and the exact contract string (contract.go);
//   - the Windows build floor of ProcessContainer (build.go);
//   - the probe ladder over the facts the host helper gathered (probe.go):
//     the platform, the build, the bundled files and their hashes, the
//     signature check, the library version, MXC's own request probe read as
//     data, and its create-and-close check;
//   - the manifest of the bundled MXC files with their pinned hashes
//     (manifest.go, the sandbox plan section 12.3 entry);
//   - the shared loopback port (port.go): one port per run carries the
//     capture relay, the model proxy, the egress gateway and the OOB
//     stream, and the run's token authorizes only its tier's streams.
//
// The C ABI loader is internal/sandboxmxcdll; the helper, the port server
// and the driver are in cmd/observer/terminal_sandbox_mxc*.go. The import
// pin (imports_test.go) keeps this package free of the network, the
// filesystem, exec and every observer-internal package.
package sandboxmxc
