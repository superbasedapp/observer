// Package hookbridgesvc runs one bridged hook for `observer hook-bridge`
// (surface-gap AW-37): it starts wsl.exe with the argument list
// internal/hookbridge built, passes stdin straight through, and captures
// stdout and stderr (bounded) so the caller can replay them byte for byte
// when the hook ran, or discard them and write the fail-closed reply when it
// did not. The decision itself is internal/hookbridge.Decide; this package
// only owns the process.
package hookbridgesvc
