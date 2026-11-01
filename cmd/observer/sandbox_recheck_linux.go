//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
)

// sandbox_recheck_linux.go is the post-launch bwrap re-check (sandbox plan v2
// section 4.4, ledger SBX-BE-1): once bwrap has started, the host helper
// finds bwrap's child (the sandbox's pid 1), reads its namespace links and
// its own, and hands both to the strict parser sandboxselect.RecheckBwrap.
// A launch judged built below its plan is killed before the tool can do
// anything, so a run is judged on what was built, never on what was asked.
//
// Two outcomes are distinguished, and the difference is load-bearing:
//   - the links were read and the parser refuses them (a namespace shared
//     with the host, a missing, truncated or reshaped line): the run is
//     refused (fail closed);
//   - the links could not be read at all (no child appeared in time, or a
//     setuid bwrap whose child the helper may not inspect): nothing was
//     measured, so the run continues and keeps its documented class, as
//     before this check existed. A notice names the posture state
//     (recheckStateNoChild or recheckStateUnreadable), never silence.
//
// The child is found two ways. /proc/<pid>/task/*/children exists only on
// a kernel built with CONFIG_PROC_CHILDREN; a stock non-WSL host can lack
// it (the Docker sandbox host, kernel 6.12.103 with a non-setuid bwrap
// 0.11.1, reported "no child of bwrap within 3s" and measured nothing; live
// check 2026-10-22, D3). Every kernel has /proc/<n>/stat, whose ppid field
// names the parent, so the helper also scans /proc for bwrap's children.
// A non-setuid bwrap forks once into its new user, mount and pid
// namespaces and that child blocks on --block-fd: it is the process to
// measure (recorded on bwrap 0.4.0, TestRecheckChildFromStat).

// recheckChildTimeout bounds the wait for bwrap's child to appear (a
// variable so tests can shorten it).
var recheckChildTimeout = 3 * time.Second

// errRecheckNotMeasured means the namespaces could not be read.
var errRecheckNotMeasured = errors.New("namespaces not measured")

// errRecheckChildExited means the held child ended before it was measured
// (a gated helper that refused on its own); there is nothing to release.
var errRecheckChildExited = errors.New("the held child ended before the re-check")

// recheckBwrapMatched is the line a measured bwrap match prints.
var recheckBwrapMatched = "observer sandbox: the launch re-check measured the sandbox's " + strings.Join(recheckNamespaces, ", ") + " namespaces and they match the plan"

// The re-check's not-measured posture states: what the notice names when
// nothing could be read.
const (
	// recheckStateNoChild: no child of bwrap appeared in time, by either
	// the children files or the /proc ppid scan.
	recheckStateNoChild = "recheck_no_child"
	// recheckStateUnreadable: the child exists but its namespace links (or
	// the helper's own) could not be read, as for a setuid bwrap's child.
	recheckStateUnreadable = "recheck_ns_unreadable"
)

// recheckReadChildrenFiles turns the CONFIG_PROC_CHILDREN reader on (a
// variable so a test can run the /proc ppid scan alone, the shape of a
// kernel without it).
var recheckReadChildrenFiles = true

// recheckScanEvery spaces the /proc ppid scans (each reads every
// process's stat line) within the wait.
const recheckScanEvery = 100 * time.Millisecond

// recheckNamespaces is the namespace set the re-check reads.
var recheckNamespaces = []string{"mnt", "pid", "net"}

// sandboxRecheck is the helper's post-start hook for the bwrap process pid.
// It returns nil when the build matches the plan, errRecheckNotMeasured
// (wrapped) when nothing could be read, and any other error for a measured
// refusal.
func sandboxRecheck(privateNet bool, bwrapPid int) error {
	child, err := waitForChild(bwrapPid, recheckChildTimeout)
	if err != nil {
		return fmt.Errorf("%w, state %s: %w", errRecheckNotMeasured, recheckStateNoChild, err)
	}
	host, err := readNSLinks("self")
	if err != nil {
		return fmt.Errorf("%w, state %s: host: %w", errRecheckNotMeasured, recheckStateUnreadable, err)
	}
	inner, err := readNSLinks(strconv.Itoa(child))
	if err != nil {
		return fmt.Errorf("%w, state %s: sandbox pid %d: %w", errRecheckNotMeasured, recheckStateUnreadable, child, err)
	}
	res := sandboxselect.RecheckBwrap(sandboxselect.PlannedBwrap{PrivateNet: privateNet}, host, inner)
	if !res.OK {
		return fmt.Errorf("%s: %s", res.Verdict, res.Reason)
	}
	return nil
}

// recheckNotice writes the re-check's one line on w and returns the refusal,
// if any. A measured match says so (live check 2026-10-22, D3 follow-up: a
// live check can confirm the re-check measured, not only that it printed
// no failure); a not-measured outcome names its state and lets the run go
// on with its documented class; a measured refusal prints nothing here and
// is returned (the helper's failure line names it).
func recheckNotice(err error, w io.Writer) error {
	return recheckNoticeFor(err, recheckBwrapMatched, w)
}

// recheckNoticeFor is recheckNotice with the matched line of the child's
// own row (a gated helper's, sandboxGatedHelper.matched).
func recheckNoticeFor(err error, matched string, w io.Writer) error {
	switch {
	case err == nil:
		fmt.Fprintln(w, matched)
		return nil
	case errors.Is(err, errRecheckNotMeasured):
		fmt.Fprintf(w, "observer sandbox: the launch re-check did not run (%v); the run keeps its documented isolation class\n", err)
		return nil
	}
	return err
}

// waitForChild finds the first child of pid: from /proc/<pid>/task/*/children
// where the kernel has them, else from a /proc ppid scan.
func waitForChild(pid int, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	var lastScan time.Time
	for {
		if recheckReadChildrenFiles {
			if c := childFromChildrenFiles(pid); c > 0 {
				return c, nil
			}
		}
		if time.Since(lastScan) >= recheckScanEvery {
			lastScan = time.Now()
			if c := childFromStat(pid, readProcStats()); c > 0 {
				return c, nil
			}
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("no child of bwrap pid %d within %s (read the /proc children files and every process's /proc stat parent)", pid, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// childFromChildrenFiles reads /proc/<pid>/task/*/children (present only
// with CONFIG_PROC_CHILDREN); 0 when there is no child or no such file.
func childFromChildrenFiles(pid int) int {
	tasks, _ := filepath.Glob(filepath.Join("/proc", strconv.Itoa(pid), "task", "*", "children"))
	for _, f := range tasks {
		b, err := os.ReadFile(f) //nolint:gosec // G304: a /proc path composed from a pid this helper started
		if err != nil {
			continue
		}
		if fields := strings.Fields(string(b)); len(fields) > 0 {
			if c, err := strconv.Atoi(fields[0]); err == nil && c > 0 {
				return c
			}
		}
	}
	return 0
}

// readProcStats returns every process's /proc/<n>/stat line by pid; a
// process that exits during the scan is skipped.
func readProcStats() map[int]string {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	out := map[int]string{}
	for _, e := range ents {
		n, err := strconv.Atoi(e.Name())
		if err != nil || n <= 0 {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat")) //nolint:gosec // G304: a /proc stat path from the numeric /proc entries
		if err != nil {
			continue
		}
		out[n] = string(b)
	}
	return out
}

// statPPID reads the parent pid from one /proc/<n>/stat line. The command
// name sits in parentheses and may itself hold spaces or parentheses, so
// the fields are read after the LAST ')': state, then ppid.
func statPPID(line string) (int, bool) {
	i := strings.LastIndexByte(line, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(line[i+1:])
	if len(f) < 2 {
		return 0, false
	}
	p, err := strconv.Atoi(f[1])
	return p, err == nil
}

// childFromStat returns the lowest-numbered process whose parent is pid, 0
// when there is none.
func childFromStat(pid int, stats map[int]string) int {
	var kids []int
	for n, line := range stats {
		if p, ok := statPPID(line); ok && p == pid && n != pid {
			kids = append(kids, n)
		}
	}
	if len(kids) == 0 {
		return 0
	}
	sort.Ints(kids)
	return kids[0]
}

// readNSLinks reads /proc/<who>/ns/<name> for each re-checked namespace and
// returns the raw "name:[inode]" link targets for the parser.
func readNSLinks(who string) ([]string, error) {
	out := make([]string, 0, len(recheckNamespaces))
	for _, ns := range recheckNamespaces {
		l, err := os.Readlink(filepath.Join("/proc", who, "ns", ns))
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}
