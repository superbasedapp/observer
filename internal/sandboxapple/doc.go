// Package sandboxapple is the pure core of the Apple container sandbox row
// (sandbox plan v2 section 13 P5, scope item 2, lane SBX-P5): the argv of
// `container run -it` (no network, the workspace mounted, the protected
// paths made read-only inside the guest, the capture relay's tunnel
// published from the guest, labels, memory and CPU limits, an explicit
// entrypoint and no progress output), the refusal of `container machine`
// (nesting rule N10: a shared VM that mounts the home read-write is no
// per-run layer), parsers for the JSON of `container ls --format json`,
// `container inspect` and `container image list --format json`, the
// read-back and the orphan sweep they feed, the in-guest mount check the
// box's init runs on its own mount table, and the probe ladder (macOS 26 on
// Apple silicon with the CLI options the driver uses; an Intel Mac and an
// older macOS are refused with named verdicts).
//
// Nothing here runs `container`: the cmd layer
// (cmd/observer/terminal_sandbox_applecontainer*.go) supplies every fact
// and runs every process. The package is pinned pure by imports_test.go.
// The shapes were first built from Apple's container documentation and are
// checked against Apple container 1.6.0 on a bare-metal Mac (2026-10-23
// and 2026-10-24, the *_live fixtures); the row stays beta until the
// section 13.9 register (MAC-11 to MAC-19, MAC-27, MAC-33) has receipts.
package sandboxapple
