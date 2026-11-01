package diag

import (
	"github.com/marmutapp/superbased-observer/internal/config"
)

// guardOrgLockRows map the org lock's state onto the doctor row (CLAUDE.md
// rule 5: one row per state, walked top-down).
var guardOrgLockRows = []struct {
	match   func(l config.GuardOrgLock) bool
	status  Status
	message func(l config.GuardOrgLock) string
}{
	{
		func(l config.GuardOrgLock) bool { return l.State == "" },
		StatusOK,
		func(config.GuardOrgLock) string {
			return "no org lock on this node (not managed, or no daemon has written one)"
		},
	},
	{
		func(l config.GuardOrgLock) bool { return l.State == "tampered" },
		StatusFail,
		func(l config.GuardOrgLock) string {
			return "the daemon's org lock (guard-org-lock.json) does not verify (" + l.Detail +
				"): the guard runs on the conservative floor until the daemon repairs it and reports the tamper"
		},
	},
	{
		// A governance pin replacing a local value is an override too
		// (T-881): the old row read only the floor's list and said "no
		// local setting is below it" over a pinned [guard] enabled=false.
		func(l config.GuardOrgLock) bool { return len(l.OverrideLines()) > 0 },
		StatusWarn,
		func(config.GuardOrgLock) string {
			return "local [guard] settings are overridden by organization policy on this managed node (details below)"
		},
	},
	{
		func(l config.GuardOrgLock) bool { return l.Managed },
		StatusOK,
		func(config.GuardOrgLock) string {
			return "managed node: the organization's guard floor is in force; no local setting is below it"
		},
	},
	{
		func(config.GuardOrgLock) bool { return true },
		StatusOK,
		func(config.GuardOrgLock) string { return "individual node: local [guard] settings are in full control" },
	},
}

// checkGuardOrgLock reports the managed-node guard floor (T-839 / D-672):
// which local [guard] settings the organization's floor raised, and whether
// the daemon's MAC'd org lock verifies. It reads the lock record config.Load
// already resolved onto cfg.Guard.Lock, so the doctor says exactly what every
// hook on this node sees.
func checkGuardOrgLock(cfg config.Config) Check {
	const name = "guard.org_lock"
	l := cfg.Guard.Lock
	for _, row := range guardOrgLockRows {
		if !row.match(l) {
			continue
		}
		c := Check{Name: name, Status: row.status, Message: row.message(l)}
		for _, o := range l.OverrideLines() {
			c.Details = append(c.Details, "overridden by org policy: "+o)
		}
		return c
	}
	return Check{Name: name, Status: StatusOK}
}
