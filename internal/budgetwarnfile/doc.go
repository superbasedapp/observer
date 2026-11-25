// Package budgetwarnfile is the on-disk read model of the node's budget
// warnings (2026-10-02 budget-latency arc): ONE daemon-owned file,
// budget-status.json, beside the database (the governance sidecar's
// placement rule, so a WSL-daemon / Windows-tool hook bridge resolves the same
// file), read by every out-of-process surface - the prompt hooks, the
// statusline, `observer guard status` - without a database or a network call.
//
// Ownership (CLAUDE.md #4):
//
//   - budget-status.json has ONE writer, the daemon's budget-warning service
//     (cmd/observer/budgetwarn_wire.go). Everything else only reads it.
//   - budget-notices-shown.json has ONE writer class, the prompt hooks: it is
//     the node-wide "this notice was already shown in-band" marker, so each
//     crossing is announced in a prompt ONCE per budget period.
//
// stdlib only, because it is read on the hook path (the govern/sidecar
// precedent).
package budgetwarnfile
