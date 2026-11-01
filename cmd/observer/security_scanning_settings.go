//go:build !sbo_omit_security

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_scanning_settings.go is the node side of the settings lane
// LEFT-SEC milestone 1 built: the four security.scanning axes that had no
// node setting ([security.scanning] quick_scan_budget_s,
// max_scan_staleness_min, min_blocking_severity, history_scan_on_enrol), the
// commit hold's reflog caps, the two unknown-package actions
// ([security.deps] unknown_action, online_unknown_action), the local
// pre-launch trust step ([security.trust] prelaunch) and the post-write
// cap's managed refusal. Every key defaults to the built-in value it
// replaced; an org floor in force only raises a key (securityFloorRows), and
// a managed node refuses the one looser value a picker offers (the 64 KiB
// post-write cap, SECP-18). Each consumer reads its key through the read
// seam (securityFloorsApplied or securityFloorsAppliedAt), never the raw
// config, and securityNodeSettingLines is what `observer security status`
// and doctor say about each key whose value is not the default or that a
// floor or the managed rule overrides.

// depsActionAxis maps a [security.deps] unknown-package action onto its
// floor axis (flag < ask, and for the online axis < deny). On the
// install_unknown axis, which tops out at ask, the node's own "deny" reads
// as the axis maximum, so no floor writes over it.
func depsActionAxis(action string, online bool) string {
	switch action {
	case "ask":
		return "ask"
	case "deny":
		if online {
			return "deny"
		}
		return "ask"
	}
	return "flag"
}

// depsActionFromAxis maps a floor value back to the setting's vocabulary.
func depsActionFromAxis(v string) string {
	if v == "flag" || v == "" {
		return "default"
	}
	return v
}

// securityPostWriteManagedCapKiB is the post-write cap a managed node keeps:
// the 64 KiB picker value scans less and is honoured on an individual node
// only (security plan 4.4, SECP-18).
const securityPostWriteManagedCapKiB = 256

// securityManagedRefusal is one picker value a managed node refuses: the
// key, whether a block holds the looser value, how the built-in value is
// put back, and why (the status line names it).
type securityManagedRefusal struct {
	Key    string
	Looser func(config.SecurityConfig) bool
	Refuse func(*config.SecurityConfig)
	Why    string
}

// securityManagedRefusalRows is the table securityManagedRefusals walks: the
// 64 KiB post-write cap scans less, and either reflog cap turns the S-792
// push hold into an ask (lane LEFT-SEC audit F2), so both are individual
// only.
var securityManagedRefusalRows = []securityManagedRefusal{
	{
		Key:    "security.secrets.postwrite_cap_kib",
		Looser: func(c config.SecurityConfig) bool { return c.Secrets.PostWriteCapKiB < securityPostWriteManagedCapKiB },
		Refuse: func(c *config.SecurityConfig) { c.Secrets.PostWriteCapKiB = securityPostWriteManagedCapKiB },
		Why:    "it scans less",
	},
	{
		Key:    "security.scanning.reflog_hold_max_age_days",
		Looser: func(c config.SecurityConfig) bool { return c.Scanning.ReflogHoldMaxAgeDays > 0 },
		Refuse: func(c *config.SecurityConfig) { c.Scanning.ReflogHoldMaxAgeDays = 0 },
		Why:    "it turns the push hold into an ask",
	},
	{
		Key:    "security.scanning.reflog_hold_max_entries",
		Looser: func(c config.SecurityConfig) bool { return c.Scanning.ReflogHoldMaxEntries > 0 },
		Refuse: func(c *config.SecurityConfig) { c.Scanning.ReflogHoldMaxEntries = 0 },
		Why:    "it turns the push hold into an ask",
	},
}

// securityManagedRefusals puts back, on a managed node, every local value a
// picker offers that is looser than the built-in one
// (securityManagedRefusalRows). It runs inside the read seam (appliedWith),
// before the floors, so the floors' raise-only merge never sees the looser
// value.
func securityManagedRefusals(sc config.SecurityConfig, managed bool) config.SecurityConfig {
	if !managed {
		return sc
	}
	for _, r := range securityManagedRefusalRows {
		if r.Looser(sc) {
			r.Refuse(&sc)
		}
	}
	return sc
}

// securityManagedRefusalFor is the refusal row of key, if it has one.
func securityManagedRefusalFor(key string) (securityManagedRefusal, bool) {
	for _, r := range securityManagedRefusalRows {
		if r.Key == key {
			return r, true
		}
	}
	return securityManagedRefusal{}, false
}

// securityLocalNow is the node's own [security] block as the floors node
// last read it from config.toml (re-read at most every securityBaseTTL), so
// a picker change reaches the daemon's consumers within 30 seconds with no
// restart; fallback (the block the consumer started with) when the node is
// not bound or the file has not loaded.
func securityLocalNow(fallback config.SecurityConfig) config.SecurityConfig {
	secScanning.mu.Lock()
	bound := secScanning.load != nil
	secScanning.mu.Unlock()
	if !bound {
		return fallback
	}
	if base, ok := secScanning.baseNow(); ok {
		return base.Security
	}
	return fallback
}

// securityPostureScanning is the posture writer's per-project read of
// [security.scanning] (secsvc.Options.Scanning): the budget and staleness
// signed into each project's posture and the least blocking severity its
// list is computed with, through the project seam.
func securityPostureScanning(fallback config.SecurityConfig) func(root string) secsvc.ScanningFloors {
	return func(root string) secsvc.ScanningFloors {
		s := securityScanningAt(securityLocalNow(fallback), root)
		return secsvc.ScanningFloors{
			QuickScanBudgetS:    s.QuickScanBudgetS,
			MaxScanStalenessMin: s.MaxScanStalenessMin,
			MinBlocking:         secfinding.Severity(s.MinBlockingSeverity),
		}
	}
}

// securityPostWriteCapInForce is the post-write cap the daemon scans with:
// [security.secrets].postwrite_cap_kib through the read seam.
func securityPostWriteCapInForce(sc config.SecurityConfig) int {
	return securityFloorsApplied(securityLocalNow(sc)).Secrets.PostWriteCapKiB
}

// securityScanningAt is [security.scanning] in force at a project root (the
// org-wide floor and the root's matched project sections over the node's
// own); "" is the node-wide value.
func securityScanningAt(sc config.SecurityConfig, root string) config.SecurityScanningConfig {
	return securityFloorsAppliedAt(sc, root).Scanning
}

// securityNodeSetting is one row of the settings this lane built, as data:
// the key, how to read its value off a [security] block, and its default.
type securityNodeSetting struct {
	Key     string
	Value   func(config.SecurityConfig) string
	Default string
}

// securityNodeSettings is the table securityNodeSettingLines walks.
var securityNodeSettings = []securityNodeSetting{
	{"security.scanning.quick_scan_budget_s", func(c config.SecurityConfig) string { return strconv.Itoa(c.Scanning.QuickScanBudgetS) }, "2"},
	{"security.scanning.max_scan_staleness_min", func(c config.SecurityConfig) string { return strconv.Itoa(c.Scanning.MaxScanStalenessMin) }, "0"},
	{"security.scanning.min_blocking_severity", func(c config.SecurityConfig) string { return c.Scanning.MinBlockingSeverity }, "high"},
	{"security.scanning.history_scan_on_enrol", func(c config.SecurityConfig) string { return strconv.FormatBool(c.Scanning.HistoryScanOnEnrol) }, "false"},
	{"security.scanning.reflog_hold_max_age_days", func(c config.SecurityConfig) string { return strconv.Itoa(c.Scanning.ReflogHoldMaxAgeDays) }, "0"},
	{"security.scanning.reflog_hold_max_entries", func(c config.SecurityConfig) string { return strconv.Itoa(c.Scanning.ReflogHoldMaxEntries) }, "0"},
	{"security.secrets.postwrite_cap_kib", func(c config.SecurityConfig) string { return strconv.Itoa(c.Secrets.PostWriteCapKiB) }, "256"},
	{"security.deps.unknown_action", func(c config.SecurityConfig) string { return c.Deps.UnknownAction }, "default"},
	{"security.deps.online_unknown_action", func(c config.SecurityConfig) string { return c.Deps.OnlineUnknownAction }, "default"},
	{"security.trust.prelaunch", securityTrustStepOf, "warn"},
}

// securityTrustStepOf is the launch's least trust step a [security] block
// asks for: the stronger of the node's own [security.trust].prelaunch and
// the org floor the read seam wrote (warn < ask < refuse).
func securityTrustStepOf(c config.SecurityConfig) string {
	order := map[string]int{"warn": 0, "ask": 1, "refuse": 2}
	step := c.Trust.Prelaunch
	if step == "" {
		step = "warn"
	}
	if f := c.PrelaunchTrustFloor; order[f] > order[step] {
		step = f
	}
	return step
}

// securityNodeSettingLines names every built key whose own value is not the
// default, and every key whose value in force differs from the node's own
// (raised by an org floor in force, or refused on a managed node), so a
// looser local value is never silently dropped. local is the node's own
// [security] block, inForce the same block through the read seam, managed
// whether the node is managed. No line means every key is at its default
// and in force as set.
func securityNodeSettingLines(local, inForce config.SecurityConfig, managed bool) []string {
	var out []string
	for _, s := range securityNodeSettings {
		own, eff := s.Value(local), s.Value(inForce)
		if own == s.Default && eff == own {
			continue
		}
		line := fmt.Sprintf("  %s: %s", s.Key, own)
		if own != s.Default {
			line += " (default " + s.Default + ")"
		}
		if eff != own {
			if r, ok := securityManagedRefusalFor(s.Key); managed && ok && r.Looser(local) {
				line += fmt.Sprintf("; refused on a managed node (%s), %s applies", r.Why, eff)
			} else {
				line += "; overridden by the org floor in force: " + eff
			}
		}
		out = append(out, line)
	}
	if len(out) > 0 {
		out = append([]string{"Code security settings (non-default or overridden):"}, out...)
	}
	return out
}

// securityHistoryOnEnrolMarker is the file beside the posture that records
// the one history scan [security.scanning].history_scan_on_enrol asked for
// has run; it is removed while the key is off, so turning it on again runs
// the scan again.
const securityHistoryOnEnrolMarker = "history-on-enrol.done"

// securityHistoryOnEnrolEvery is how often the daemon re-reads the key (it
// runs at daemon start and then at this interval, so a key set or a floor
// accepted while the daemon runs is honoured without a restart).
const securityHistoryOnEnrolEvery = 30 * time.Minute

// securityHistoryOnEnrolMaxProjects bounds the projects one run scans.
const securityHistoryOnEnrolMaxProjects = 32

// securityHistoryOnEnrolDeps are the seams of one check (tests swap them).
type securityHistoryOnEnrolDeps struct {
	dir      string
	enabled  func() bool
	projects func(context.Context) ([]string, error)
	scan     func(context.Context, string) error
}

// securityHistoryOnEnrolOnce runs the history scan of every listed project
// when the key in force is on and its marker is absent, then writes the
// marker; with the key off it removes the marker. It reports whether it
// scanned. Local git reads only, never a network call.
func securityHistoryOnEnrolOnce(ctx context.Context, d securityHistoryOnEnrolDeps) (bool, error) {
	marker := filepath.Join(d.dir, securityHistoryOnEnrolMarker)
	if !d.enabled() {
		if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		return false, nil
	}
	if _, err := os.Stat(marker); err == nil {
		return false, nil
	}
	roots, err := d.projects(ctx)
	if err != nil {
		return false, err
	}
	if len(roots) > securityHistoryOnEnrolMaxProjects {
		roots = roots[:securityHistoryOnEnrolMaxProjects]
	}
	for _, r := range roots {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		// A project git cannot read is skipped; the run still counts.
		_ = d.scan(ctx, r)
	}
	if err := os.MkdirAll(d.dir, 0o700); err != nil {
		return true, err
	}
	return true, os.WriteFile(marker, []byte("1\n"), 0o600)
}

// securityHistoryOnEnrolLoop runs [security.scanning].history_scan_on_enrol
// beside the posture writer (its goroutine, like the retention pass): the
// key is read through the floors' seam (an org floor raises it), at start
// and every securityHistoryOnEnrolEvery, and runs the bounded history scan
// for secrets (secsvc.ScanHistory) over every active project once.
func securityHistoryOnEnrolLoop(ctx context.Context, resolved string, start config.SecurityConfig, st *store.Store, logger *slog.Logger) {
	deps := securityHistoryOnEnrolDeps{
		dir:     secposture.LayoutFor(resolved).Dir,
		enabled: func() bool { return securityScanningAt(securityLocalNow(start), "").HistoryScanOnEnrol },
		projects: func(ctx context.Context) ([]string, error) {
			return st.SecActiveProjectRoots(ctx, time.Now().Add(-secsvc.DefaultActiveWithin))
		},
		scan: func(ctx context.Context, root string) error {
			_, err := secsvc.ScanHistory(ctx, secsvc.LocalHistoryDeps(resolved, secrules.PackVersion, st), commitScanRoot(root), secsvc.HistoryOptions{})
			return err
		},
	}
	t := time.NewTicker(securityHistoryOnEnrolEvery)
	defer t.Stop()
	for {
		if ran, err := securityHistoryOnEnrolOnce(ctx, deps); err != nil && ctx.Err() == nil {
			logger.Warn("security: history scan on enrolment", "err", err)
		} else if ran {
			logger.Info("security: ran the history scan [security.scanning].history_scan_on_enrol asked for")
			securityRT.notify()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// securityNodeSettingStatus is securityNodeSettingLines for a CLI process:
// the floors bound from the verified cache (bindSecurityFloorsForCLI) and
// the managed rule resolved from the stored grant.
func securityNodeSettingStatus(ctx context.Context, configPath string, cfg config.Config, st *store.Store) []string {
	managed := false
	if st != nil {
		bindSecurityFloorsForCLI(ctx, configPath, cfg, st)
		if m, err := securityNodeManaged(ctx, st, time.Now()); err == nil {
			managed = m
		}
	}
	return securityNodeSettingLines(cfg.Security, securityFloorsApplied(cfg.Security), managed)
}
