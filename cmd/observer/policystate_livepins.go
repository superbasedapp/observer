package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
)

// Live policy reporting (managed policy visibility G3, 2026-11-12 ruling).
// The node.governance row's EffectivePins used to be read off the config the
// daemon loaded at start, so a local edit to a key every hook re-reads (a
// guard switch, a budget setting) kept showing the old value until a restart;
// and a report waited for the five-minute heartbeat. Now the pins are read off
// the config as it loads now (the same load every hook and new process does,
// governance sidecar applied), and a change to the files a report is built
// from pokes the reporter at once.

// livePinReader returns the EffectivePins reader over the config at path as
// it loads at each report, through overlay (the daemon's component inert
// overlay, so a switch of an inactive component reads as the daemon runs it;
// nil = none). A config that does not load reports the last value that did
// (the daemon's own start config at first), never a guess.
func livePinReader(path func() string, start config.Config, overlay func(config.Config) config.Config) func() map[string]string {
	var mu sync.Mutex
	last := start
	return func() map[string]string {
		mu.Lock()
		defer mu.Unlock()
		// An empty path is the default config, the same reading
		// localGuardPostureFromDisk takes.
		if cfg, err := config.Load(config.LoadOptions{GlobalPath: path()}); err == nil {
			if overlay != nil {
				cfg = overlay(cfg)
			}
			last = cfg
		}
		return effectivePinValues(last)
	}
}

// policyInputsStampProjectLimit bounds how many recently active projects'
// in-repo policy files the stamp watches (review finding 10, 2026-11-12): the
// most recent policyInputsStampProjectLimit roots by last session. An edit to
// the repository file of an older project still reaches the organization at
// the next heartbeat, as every in-repo file did before.
const policyInputsStampProjectLimit = 200

// policyInputsStamp fingerprints the files a policy-state report is built
// from: the config file, the user policy file and its recipe, every file in
// the trusted per-project directory, and the in-repo policy file of each
// recently active project roots returns (at most
// policyInputsStampProjectLimit; name, size, modification time). It is a
// stat per file, no read, so it is cheap to poll. roots may be nil.
func policyInputsStamp(path func() string, home string, roots func() []string) func() string {
	return func() string {
		var b strings.Builder
		p := path()
		if resolved, err := config.ResolveGlobalPath(p); err == nil {
			stampFile(&b, resolved)
		}
		cfg, err := config.Load(config.LoadOptions{GlobalPath: p})
		if err != nil {
			return b.String()
		}
		if up := guard.UserPolicyPath(cfg.Guard, home); up != "" {
			stampFile(&b, up)
			stampFile(&b, guard.UserRecipePolicyPath(cfg.Guard, home))
		}
		if tp := guard.TrustedProjectPolicyPath(cfg.Guard, home, string(filepath.Separator)); tp != "" {
			dir := filepath.Dir(tp)
			entries, _ := os.ReadDir(dir)
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			sort.Strings(names)
			for _, n := range names {
				stampFile(&b, filepath.Join(dir, n))
			}
		}
		if roots != nil {
			rs := roots()
			if len(rs) > policyInputsStampProjectLimit {
				rs = rs[:policyInputsStampProjectLimit]
			}
			for _, root := range rs {
				if pp := guard.ProjectPolicyPath(cfg.Guard, root); pp != "" {
					stampFile(&b, pp)
				}
			}
		}
		return b.String()
	}
}

// recentProjectRootsFor is the roots source policyInputsStamp polls: the
// store's most recently active project roots, policyInputsStampProjectLimit
// of them. A store error reads as none.
func recentProjectRootsFor(st interface {
	RecentProjectRoots(ctx context.Context, limit int) ([]string, error)
},
) func() []string {
	if st == nil {
		return nil
	}
	return func() []string {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		roots, err := st.RecentProjectRoots(ctx, policyInputsStampProjectLimit)
		if err != nil {
			return nil
		}
		return roots
	}
}

// policyInputsCheckInterval is how often watchPolicyInputs stats the files
// (a config load per check: the hook path pays the same per call).
var policyInputsCheckInterval = 10 * time.Second

// stampFile appends one file's stamp ("missing" when it cannot be read).
func stampFile(b *strings.Builder, path string) {
	st := statStamp(path)
	if !st.ok {
		fmt.Fprintf(b, "%s:missing;", path)
		return
	}
	fmt.Fprintf(b, "%s:%d:%d;", path, st.size, st.mod.UnixNano())
}

// watchPolicyInputs pokes the reporter whenever stamp changes, until ctx
// ends. The first reading is the baseline (the start-up report covers it).
func watchPolicyInputs(ctx context.Context, stamp func() string, poke func(), interval time.Duration) {
	if stamp == nil || poke == nil {
		return
	}
	prev := stamp()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if cur := stamp(); cur != prev {
			prev = cur
			poke()
		}
	}
}
