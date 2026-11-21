package config

import (
	"fmt"
	"time"
)

// SecurityReachConfig is [security.reach]: the reachability checks' own
// settings (OS and CI vulnerability scanning plan section 14.5).
type SecurityReachConfig struct {
	// Go is [security.reach.go] (component security.reach.go).
	Go SecurityReachGoConfig `toml:"go"`
}

// SecurityReachGoConfig is [security.reach.go]: the caps of the Go source
// check, 3b-src (spike RG-0 "Answer" item 2), which runs osv-scanner's call
// analysis, and with it the project's own Go toolchain, once per go.mod.
// Every run reads them, so a change needs no restart. They are the
// developer's: an agent can never change one (guard rule R-165, the
// [security] section).
type SecurityReachGoConfig struct {
	// SourceMemoryMiB caps each go.mod run's memory, osv-scanner and the
	// toolchain it starts together; GOMEMLIMIT is set to 90 % of it. 0, the
	// default, is 12288 (12 GiB: RG-0 measured 2.6 to 3.6 GiB on two large
	// public repositories and 9.8 GiB on Observer's own). Otherwise 512 to
	// 65536. A run that passes it reads "ran out of memory: not checked".
	SourceMemoryMiB int `toml:"source_memory_mib"`
	// SourceTimeoutSeconds caps each go.mod run's wall time. 0, the
	// default, is 1200. Otherwise 60 to 7200. A run that passes it reads
	// "timed out: not checked".
	SourceTimeoutSeconds int `toml:"source_timeout_seconds"`
	// SourceMaxModules caps how many go.mod files one check runs, one
	// after another. 0, the default, is 16. Otherwise 1 to 64; the rest
	// read "not checked".
	SourceMaxModules int `toml:"source_max_modules"`
}

// The [security.reach.go] defaults (a 0 key).
const (
	SecurityReachGoSourceMemoryMiBDefault = 12288
	SecurityReachGoSourceTimeoutDefault   = 1200 * time.Second
	SecurityReachGoSourceMaxModsDefault   = 16
)

// MemoryBytes is the effective memory cap in bytes.
func (c SecurityReachGoConfig) MemoryBytes() int64 {
	mib := c.SourceMemoryMiB
	if mib == 0 {
		mib = SecurityReachGoSourceMemoryMiBDefault
	}
	return int64(mib) << 20
}

// Timeout is the effective per-go.mod wall cap.
func (c SecurityReachGoConfig) Timeout() time.Duration {
	if c.SourceTimeoutSeconds == 0 {
		return SecurityReachGoSourceTimeoutDefault
	}
	return time.Duration(c.SourceTimeoutSeconds) * time.Second
}

// MaxModules is the effective go.mod cap.
func (c SecurityReachGoConfig) MaxModules() int {
	if c.SourceMaxModules == 0 {
		return SecurityReachGoSourceMaxModsDefault
	}
	return c.SourceMaxModules
}

// validateSecurityReachGo checks [security.reach.go] (0 is each key's
// default).
func validateSecurityReachGo(c SecurityReachGoConfig) error {
	switch {
	case c.SourceMemoryMiB != 0 && (c.SourceMemoryMiB < 512 || c.SourceMemoryMiB > 65536):
		return fmt.Errorf("config: security.reach.go.source_memory_mib %d not 0 or 512 to 65536", c.SourceMemoryMiB)
	case c.SourceTimeoutSeconds != 0 && (c.SourceTimeoutSeconds < 60 || c.SourceTimeoutSeconds > 7200):
		return fmt.Errorf("config: security.reach.go.source_timeout_seconds %d not 0 or 60 to 7200", c.SourceTimeoutSeconds)
	case c.SourceMaxModules < 0 || c.SourceMaxModules > 64:
		return fmt.Errorf("config: security.reach.go.source_max_modules %d not 0 to 64", c.SourceMaxModules)
	}
	return nil
}
