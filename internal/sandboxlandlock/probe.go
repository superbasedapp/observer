package sandboxlandlock

import (
	"strconv"
)

// probe.go is the process_lite probe ladder (sandbox plan v2 section 4.7):
// a pure ordered table over injected facts. Nothing reads the Landlock ABI
// while the row is inactive.

// The verdicts (section 4.7; all take the 501 default but
// disabled_by_config, which is 403).
const (
	VerdictAvailable           = "available"
	VerdictUnsupportedPlatform = "unsupported_platform"
	VerdictDisabledByConfig    = "disabled_by_config"
	// VerdictLandlockUnavailable: the kernel has no Landlock, or it is
	// disabled (lsm= without landlock); the ABI query failed.
	VerdictLandlockUnavailable = "landlock_unavailable"
	// VerdictLandlockABITooOld: section 4.7's landlock_abi_too_old.
	VerdictLandlockABITooOld = "landlock_abi_too_old"
)

// Verdict is one ladder answer.
type Verdict struct {
	Code   string
	Reason string
}

// OK reports whether v passes.
func (v Verdict) OK() bool { return v.Code == VerdictAvailable }

// Error makes a refusal usable as an error.
func (v Verdict) Error() string {
	if v.Reason == "" {
		return v.Code
	}
	return v.Code + ": " + v.Reason
}

// Host is the daemon's host as the ladder needs it.
type Host string

// The Host values.
const (
	HostLinux Host = "linux"
	HostWSL2  Host = "wsl2"
	HostOther Host = "other"
)

// ProbeEnv is the injected I/O.
type ProbeEnv struct {
	Host Host
	// Active: [terminal.sandbox].enabled, the module and the driver active,
	// and process_lite in [terminal.sandbox].backends.
	Active bool
	// MinABI is [terminal.sandbox.landlock].min_abi (0: the row's floor).
	MinABI int
	// ABI reads the kernel's Landlock ABI (landlock_create_ruleset with the
	// VERSION flag); an error means no usable Landlock.
	ABI func() (int, error)
}

// ProbeResult is the ladder's answer plus what it read.
type ProbeResult struct {
	Verdict  Verdict
	ABI      int
	Features Features
	Rule     string
}

type probeRow struct {
	id  string
	run func(env ProbeEnv, r *ProbeResult) Verdict
}

var probeRows = []probeRow{
	{"L1 platform", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if env.Host != HostLinux && env.Host != HostWSL2 {
			return Verdict{VerdictUnsupportedPlatform, "process_lite (Landlock) runs on Linux only"}
		}
		return Verdict{Code: VerdictAvailable}
	}},
	{"L2 active", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if !env.Active {
			return Verdict{VerdictDisabledByConfig, "the Landlock driver is not active, or process_lite is not in [terminal.sandbox].backends; nothing was probed"}
		}
		return Verdict{Code: VerdictAvailable}
	}},
	{"L3 abi", func(env ProbeEnv, r *ProbeResult) Verdict {
		if env.ABI == nil {
			return Verdict{VerdictLandlockUnavailable, "the Landlock ABI could not be read"}
		}
		abi, err := env.ABI()
		if err != nil || abi < 1 {
			why := "the kernel reports no Landlock ABI"
			if err != nil {
				why = "the kernel has no usable Landlock (" + err.Error() + "); it may be built without it or not in the lsm= list"
			}
			return Verdict{VerdictLandlockUnavailable, why}
		}
		r.ABI, r.Features = abi, FeaturesFor(abi)
		return Verdict{Code: VerdictAvailable}
	}},
	{"L4 floor", func(env ProbeEnv, r *ProbeResult) Verdict {
		floor := Floor(env.MinABI)
		if r.ABI < floor {
			why := "the kernel's Landlock ABI is " + strconv.Itoa(r.ABI) + ", below " + strconv.Itoa(floor) + floorReason(floor)
			if env.Host == HostWSL2 {
				why += " (WSL2's kernel reports 7; use bwrap there)"
			}
			return Verdict{VerdictLandlockABITooOld, why}
		}
		return Verdict{Code: VerdictAvailable}
	}},
}

// floorReason says why the floor in force is what it is, naming the real
// floor (Linux live check 2026-10-23: the refusal said "without ABI 9"
// while a configured min_abi of 11 was the floor).
func floorReason(floor int) string {
	if floor > MinABI {
		return ", the floor [terminal.sandbox.landlock].min_abi sets (the row itself needs ABI " + strconv.Itoa(MinABI) + ")"
	}
	return ": below ABI " + strconv.Itoa(floor) + " the daemon's relay endpoint and the attach socket would be reachable from the box"
}

// Probe walks the ladder.
func Probe(env ProbeEnv) ProbeResult {
	var r ProbeResult
	for _, row := range probeRows {
		v := row.run(env, &r)
		r.Rule = row.id
		if !v.OK() {
			r.Verdict = v
			return r
		}
	}
	r.Verdict = Verdict{Code: VerdictAvailable}
	return r
}
