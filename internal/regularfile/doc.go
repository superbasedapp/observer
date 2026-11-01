// Package regularfile is the one capped regular-file read of a file a user
// or a tool controls (a vendor settings file): it refuses a FIFO, a device,
// a directory and anything past a byte cap, without blocking and without
// reading it. internal/agentconfigsvc.ReadRegularFile is a shim over Read
// (moved here so internal/proxyroute and internal/hook can use the same
// reader without importing the settings-editor service). Stdlib only.
package regularfile
