package main

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hookspool"
)

// hookSpoolCheck is the doctor's hooks.spool row (R-188 F5): how many hook
// activity records the hooks skipped because the hook spool passed
// hookspool.MaxActivitySpoolBytes with nothing draining it (the daemon is not
// running while the hooks stay registered). Lifecycle and action records are
// never skipped; only liveness counts are, so a hook that fired while the
// spool was full is missing from hooks.liveness. The daemon's drainer clears
// the count once it has set the full spool aside. It reads two file sizes,
// never the database. Named "hooks.spool" so `observer doctor hooks` scopes to
// it.
func hookSpoolCheck(configPath string) diag.Check {
	const name = "hooks.spool"
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return diag.Check{Name: name, Status: diag.StatusWarn, Message: "hook spool not located: " + err.Error()}
	}
	spool := hookspool.Path(resolved)
	skipped, err := hookspool.SkippedActivity(spool)
	if err != nil {
		return diag.Check{Name: name, Status: diag.StatusWarn, Message: "hook spool skip count unreadable: " + err.Error()}
	}
	if skipped == 0 {
		return diag.Check{Name: name, Status: diag.StatusOK, Message: "no hook activity record skipped"}
	}
	count := fmt.Sprintf("%d", skipped)
	if skipped >= hookspool.MaxSkippedCount {
		count = "at least " + count
	}
	return diag.Check{
		Name:   name,
		Status: diag.StatusWarn,
		Message: fmt.Sprintf("%s hook activity record(s) skipped: the hook spool passed its %d MiB cap with nothing draining it",
			count, hookspool.MaxActivitySpoolBytes>>20),
		Details: []string{
			"the daemon drains the spool; start it with `observer start` (the count clears after the next drain)",
			"only liveness counts were skipped, never actions or lifecycle records; hooks.liveness misses the calls made meanwhile",
		},
	}
}
