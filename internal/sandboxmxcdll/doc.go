// Package sandboxmxcdll is the boundary to MXC's mxc_ffi C ABI (sandbox
// plan v2 sections 4.8 and 13 P6; lane SBX-P6): it gathers the probe
// ladder's facts in order and loads the library only after every earlier
// row passed, without CGO (golang.org/x/sys/windows, lib_windows.go).
//
// Three rules hold by construction:
//
//   - the library is loaded only in a per-run host helper process (the
//     `observer sandbox-mxc-host` and `sandbox-mxc-probe` verbs), never in
//     the daemon, so a fault in native code cannot take down the proxy
//     (review R2-15); the daemon's driver reads the helper's JSON answer;
//   - every bundled file is opened denying writers, hashed against the pin
//     compiled into this build (sandboxmxc.Manifest) and checked for its
//     Authenticode signature while that handle is held, and the library is
//     loaded from the same held file, so nothing can swap it between the
//     check and the load;
//   - nothing here runs while the driver is inactive: Gather stops at the
//     "active" row before any file is opened.
//
// The pure decisions are internal/sandboxmxc's; this package only fills
// sandboxmxc.HostFacts. Every OS call is behind Env, so the order and the
// stops are tested on any host with a fake library (gather_test.go).
package sandboxmxcdll
