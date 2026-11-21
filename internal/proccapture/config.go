package proccapture

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Config is the pure mirror of [observer.process.capture] (plan §9.1). The
// daemon maps the TOML block onto it at the boundary
// (config.ProcessCaptureConfig.Capture); this package never imports
// internal/config. The zero value is "disabled": Classify then keeps every
// run, which is the pre-budget behaviour.
type Config struct {
	// Enabled applies the decision table. False keeps every captured run.
	Enabled bool
	// PerToolCall, PerSession and PerMinute are the exemplar budgets (R8).
	// A value <= 0 leaves that budget uncapped.
	PerToolCall int
	PerSession  int
	PerMinute   int
	// TrackServices tracks services the agent spawns (R5). False drops a
	// service's subtree (counted); the service root row is still kept.
	TrackServices bool
	// DetachAfter is the detach heuristic's grace: a run that outlives its
	// tool call by this long and keeps spawning becomes a service root.
	// <= 0 disables the heuristic (the service table still applies).
	DetachAfter time.Duration
	// ExemplarsPerService is how many rows are kept under one service root
	// before the rest roll up. <= 0 keeps none.
	ExemplarsPerService int
	// ServiceTail stops tracking a service this long after the session's
	// last activity; later runs are dropped (counted). <= 0 never stops.
	ServiceTail time.Duration
	// ExtraServiceBasenames extends the built-in service table.
	ExtraServiceBasenames []string
	// FoldEnabled applies the fold table (R6).
	FoldEnabled bool
	// ExtraFoldBasenames extends the built-in fold table: any run with one of
	// these executables folds into its parent.
	ExtraFoldBasenames []string
	// RingMinLifetime keeps the metric ring only for runs alive this long.
	RingMinLifetime time.Duration
	// Bucket is the rollup bucket width. <= 0 uses one minute.
	Bucket time.Duration
	// PendingHours is how long an unattributed row waits for correlation.
	PendingHours int
	// UnattributedMode is "rollup" or "drop" once the wait is over.
	UnattributedMode string
}

// Unattributed policy modes (plan §8 ruling 3).
const (
	UnattributedRollup = "rollup"
	UnattributedDrop   = "drop"
)

// DefaultConfig returns the plan §9.1 defaults (the same values
// config.Default seeds for [observer.process.capture]).
func DefaultConfig() Config {
	return Config{
		Enabled:             true,
		PerToolCall:         200,
		PerSession:          5000,
		PerMinute:           300,
		TrackServices:       true,
		DetachAfter:         10 * time.Minute,
		ExemplarsPerService: 20,
		ServiceTail:         30 * time.Minute,
		FoldEnabled:         true,
		RingMinLifetime:     30 * time.Second,
		Bucket:              time.Minute,
		PendingHours:        24,
		UnattributedMode:    UnattributedRollup,
	}
}

// bucket returns the effective rollup bucket width.
func (c Config) bucket() time.Duration {
	if c.Bucket <= 0 {
		return time.Minute
	}
	return c.Bucket
}

// ConfigKeys are the plan §9.1 keys, dotted relative to
// [observer.process.capture], in table order. The estimate endpoint takes
// these as query parameters and Estimate reports by_setting rows keyed by
// them.
var ConfigKeys = []string{
	"enabled",
	"budget.per_tool_call",
	"budget.per_session",
	"budget.per_minute",
	"services.track",
	"services.detach_after_minutes",
	"services.exemplars_per_service",
	"services.tail_minutes",
	"services.extra_basenames",
	"fold.enabled",
	"fold.extra_basenames",
	"metrics.ring_min_lifetime_seconds",
	"rollups.bucket_seconds",
	"unattributed.pending_hours",
	"unattributed.mode",
}

// Get returns the value of one ConfigKeys key as the string Set accepts
// (lists comma-joined). An unknown key returns ok=false.
func (c Config) Get(key string) (string, bool) {
	switch key {
	case "enabled":
		return strconv.FormatBool(c.Enabled), true
	case "budget.per_tool_call":
		return strconv.Itoa(c.PerToolCall), true
	case "budget.per_session":
		return strconv.Itoa(c.PerSession), true
	case "budget.per_minute":
		return strconv.Itoa(c.PerMinute), true
	case "services.track":
		return strconv.FormatBool(c.TrackServices), true
	case "services.detach_after_minutes":
		return strconv.Itoa(int(c.DetachAfter / time.Minute)), true
	case "services.exemplars_per_service":
		return strconv.Itoa(c.ExemplarsPerService), true
	case "services.tail_minutes":
		return strconv.Itoa(int(c.ServiceTail / time.Minute)), true
	case "services.extra_basenames":
		return strings.Join(c.ExtraServiceBasenames, ","), true
	case "fold.enabled":
		return strconv.FormatBool(c.FoldEnabled), true
	case "fold.extra_basenames":
		return strings.Join(c.ExtraFoldBasenames, ","), true
	case "metrics.ring_min_lifetime_seconds":
		return strconv.Itoa(int(c.RingMinLifetime / time.Second)), true
	case "rollups.bucket_seconds":
		return strconv.Itoa(int(c.Bucket / time.Second)), true
	case "unattributed.pending_hours":
		return strconv.Itoa(c.PendingHours), true
	case "unattributed.mode":
		return c.UnattributedMode, true
	}
	return "", false
}

// Set parses value into one ConfigKeys key. Booleans take strconv.ParseBool
// spellings, numbers are integers in the key's unit, lists are
// comma-separated. It is how the estimate endpoint turns its dotted query
// parameters into a proposed Config.
func (c *Config) Set(key, value string) error {
	value = strings.TrimSpace(value)
	parseBool := func(dst *bool) error {
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("proccapture.Config.Set(%s): %w", key, err)
		}
		*dst = b
		return nil
	}
	parseInt := func(set func(int)) error {
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("proccapture.Config.Set(%s): %w", key, err)
		}
		set(n)
		return nil
	}
	parseList := func() []string {
		var out []string
		for _, p := range strings.Split(value, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	switch key {
	case "enabled":
		return parseBool(&c.Enabled)
	case "budget.per_tool_call":
		return parseInt(func(n int) { c.PerToolCall = n })
	case "budget.per_session":
		return parseInt(func(n int) { c.PerSession = n })
	case "budget.per_minute":
		return parseInt(func(n int) { c.PerMinute = n })
	case "services.track":
		return parseBool(&c.TrackServices)
	case "services.detach_after_minutes":
		return parseInt(func(n int) { c.DetachAfter = time.Duration(n) * time.Minute })
	case "services.exemplars_per_service":
		return parseInt(func(n int) { c.ExemplarsPerService = n })
	case "services.tail_minutes":
		return parseInt(func(n int) { c.ServiceTail = time.Duration(n) * time.Minute })
	case "services.extra_basenames":
		c.ExtraServiceBasenames = parseList()
		return nil
	case "fold.enabled":
		return parseBool(&c.FoldEnabled)
	case "fold.extra_basenames":
		c.ExtraFoldBasenames = parseList()
		return nil
	case "metrics.ring_min_lifetime_seconds":
		return parseInt(func(n int) { c.RingMinLifetime = time.Duration(n) * time.Second })
	case "rollups.bucket_seconds":
		return parseInt(func(n int) { c.Bucket = time.Duration(n) * time.Second })
	case "unattributed.pending_hours":
		return parseInt(func(n int) { c.PendingHours = n })
	case "unattributed.mode":
		if value != UnattributedRollup && value != UnattributedDrop {
			return fmt.Errorf("proccapture.Config.Set(%s): %q is not %q or %q", key, value, UnattributedRollup, UnattributedDrop)
		}
		c.UnattributedMode = value
		return nil
	}
	return fmt.Errorf("proccapture.Config.Set: unknown key %q", key)
}

// changedKeys lists the ConfigKeys whose value differs between c and other,
// in table order.
func (c Config) changedKeys(other Config) []string {
	var out []string
	for _, k := range ConfigKeys {
		a, _ := c.Get(k)
		b, _ := other.Get(k)
		if a != b {
			out = append(out, k)
		}
	}
	return out
}

// with returns c with key copied from other.
func (c Config) with(key string, other Config) Config {
	v, ok := other.Get(key)
	if !ok {
		return c
	}
	out := c
	out.ExtraServiceBasenames = slices.Clone(c.ExtraServiceBasenames)
	out.ExtraFoldBasenames = slices.Clone(c.ExtraFoldBasenames)
	_ = out.Set(key, v)
	return out
}
