package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// tempwatch.go — Wave 2 / Phase 3 of the 2026-08-26 disk & compute
// exhaustion remediation
// (docs/plans/observer-disk-compute-remediation-plan-2026-08-26.md,
// audit docs/audits/observer-disk-compute-exhaustion-audit-2026-08-26.md).
//
// T3.1: tempWatchdogLoop is a fail-soft sibling of walWatchdogLoop
// (walwatch.go) that periodically sums, on Linux, the bytes backing this
// process's own deleted-but-open files — a large uncommitted SQLite temp
// spill (an unindexed sort or an operator VACUUM) or an old long-lived
// reader still pinning a huge deleted WAL/temp file — and WARNs loudly
// before the disk fills rather than after. This /proc/self/fd scan is
// process-scoped and location-independent: it catches a spill wherever
// SQLite wrote it (/var/tmp, /tmp, wherever), so it needs no temp-dir
// redirect to work. (An earlier revision also os.Setenv'd SQLITE_TMPDIR +
// TMPDIR to relocate spills under ~/.observer/tmp; that was removed —
// setting TMPDIR process-wide poisons os.TempDir() for everything else in
// the process, and the /proc/self/fd scan below already gives a precise,
// redirect-free signal. temp_store defaults to FILE, so any residual spill
// is bounded and visible here rather than risking an OOM in RAM.)
//
// T3.3: detectStaleBinary / staleBinaryWarning flag a daemon that is still
// executing a binary a build/release has since replaced on disk — visible
// on Linux via `/proc/self/exe`'s kernel-appended " (deleted)" suffix,
// which os.Executable() silently strips (go/src/os/executable_procfs.go).

const (
	// tempWatchdogInterval is how often tempWatchdogLoop re-checks this
	// process's deleted-open files (T3.1).
	tempWatchdogInterval = 5 * time.Minute

	// tempWatchdogThresholdBytes is the WARN threshold: 5 GiB of
	// deleted-but-open file backing is already deep into "about to fill
	// the disk" territory on the reference install (the audit's incident
	// was a multi-GiB unbounded spill).
	tempWatchdogThresholdBytes = 5 * 1024 * 1024 * 1024

	// procSelfFD is the Linux magic-symlink directory listing this
	// process's own open file descriptors.
	procSelfFD = "/proc/self/fd"
)

// isDeletedTarget reports whether a /proc/<pid>/fd readlink target names a
// file that has been unlinked while still open — the Linux kernel appends
// " (deleted)" to the symlink target in that case.
func isDeletedTarget(target string) bool {
	return strings.HasSuffix(target, " (deleted)")
}

// sumDeletedOpenFDBytes sums the sizes of this process's own open file
// descriptors that point at a since-deleted (unlinked) file — e.g. a huge
// SQLite temp spill or WAL file whose directory entry is gone but whose
// bytes are still consuming disk because something in-process still holds
// it open. This is exactly the etilqs_* deleted-but-open signature the
// 2026-08-26 audit traced. Linux-only; returns (0, nil) elsewhere so
// callers don't need a GOOS check of their own.
func sumDeletedOpenFDBytes() (int64, error) {
	if runtime.GOOS != "linux" {
		return 0, nil
	}
	entries, err := os.ReadDir(procSelfFD)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range entries {
		fdPath := filepath.Join(procSelfFD, e.Name())
		target, rerr := os.Readlink(fdPath)
		if rerr != nil || !isDeletedTarget(target) {
			continue
		}
		// Stat the fd's magic symlink itself (not the now-nonexistent
		// target path) — the kernel keeps the inode alive for an open fd,
		// so this resolves to the real, current size even though the path
		// on disk is gone.
		info, serr := os.Stat(fdPath)
		if serr != nil {
			continue
		}
		total += info.Size()
	}
	return total, nil
}

// tempWatchdogLoop is T3.1's entry point: a fail-soft sibling of
// walWatchdogLoop (walwatch.go) with its own short-lived config load (no DB
// handle needed — this loop only reads /proc/self/fd). Runs until ctx is
// cancelled; any setup failure logs nothing further and exits quietly,
// never touching proxy/watcher/dashboard health.
func tempWatchdogLoop(ctx context.Context, configPath string) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return
	}
	logger := newLogger(cfg.Observer.LogLevel)

	check := func() {
		fdBytes, _ := sumDeletedOpenFDBytes()
		if fdBytes < tempWatchdogThresholdBytes {
			return
		}
		logger.Warn("large deleted-but-open file backing detected - likely an unindexed sort or a VACUUM temp spill",
			"deleted_open_fd_bytes", fdBytes,
			"threshold_bytes", int64(tempWatchdogThresholdBytes))
	}

	check() // startup pass — catches a spill that already exists when the daemon starts
	ticker := time.NewTicker(tempWatchdogInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

// detectStaleBinary reports whether the currently running observer binary
// has been deleted or replaced on disk since this process started — e.g. a
// build/release overwrote bin/observer while the daemon kept its original
// inode open via its still-running process. A daemon running on a stale
// binary silently executes old code even though `bin/observer --version`
// on disk reports the new one.
//
// Linux-first: os.Executable() strips the kernel's " (deleted)" suffix
// (see go/src/os/executable_procfs.go), so this reads /proc/self/exe
// directly to observe it. Falls back to a plain existence check via
// os.Executable() + Stat where /proc/self/exe isn't readable (non-Linux,
// or a sandboxed environment).
func detectStaleBinary() (stale bool, path string) {
	if runtime.GOOS == "linux" {
		if target, err := os.Readlink("/proc/self/exe"); err == nil {
			if isDeletedTarget(target) {
				return true, strings.TrimSuffix(target, " (deleted)")
			}
			return false, target
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return false, ""
	}
	if _, statErr := os.Stat(exe); statErr != nil && os.IsNotExist(statErr) {
		return true, exe
	}
	return false, exe
}

// staleBinaryWarning is T3.3's entry point: returns a one-line WARN message
// (newline-terminated, ready to write to stderr) if the running binary is
// stale, or "" if it's current — so callers can no-op cleanly without a
// separate bool check. Best-effort; never fails startup.
func staleBinaryWarning() string {
	stale, path := detectStaleBinary()
	if !stale {
		return ""
	}
	if path == "" {
		return "WARN running a replaced/deleted observer binary - restart the daemon on the current build (a live-replaced binary runs old code)\n"
	}
	return fmt.Sprintf(
		"WARN running a replaced/deleted observer binary (%s) - restart the daemon on the current build (a live-replaced binary runs old code)\n",
		path,
	)
}
