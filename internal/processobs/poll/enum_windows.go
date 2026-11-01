//go:build windows

package poll

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// platformEnumerate reads the current process table via the ToolHelp32
// snapshot API — the Windows arm of the poll backend (§5.4). For each process
// it best-effort opens a PROCESS_QUERY_LIMITED_INFORMATION handle to read the
// creation time (the per-process stamp the PID-reuse-proof ProcessKey needs,
// §9.3) and the full image path. A process we cannot open (a system process,
// another user's, or one at higher integrity) keeps its ToolHelp basename and
// is left HasStart=false, so it is tracked for the tree but never persisted as
// a fresh attributed run.
//
// This is the same APPROXIMATE snapshot-diff model as the Linux /proc reader:
// it does not catch a process born and gone within one poll interval, and does
// not see Linux-only posture (seccomp/caps/namespaces — those stay empty on
// Windows). High-fidelity real-time capture (and network/file events) is the
// ETW backend (§5.2), a later increment.
//
// IMPORTANT (topology): this observes the processes of the OS the observer
// runs ON. A WSL2 daemon does not see Windows-host processes (separate VM
// kernel) — to capture Windows-native AI-tool spawns, run observer on Windows.
func platformEnumerate() ([]ProcInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap) //nolint:errcheck // best-effort close of a read snapshot

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, err
	}

	var out []ProcInfo
	for {
		// PID 0 is ToolHelp's "[System Process]" pseudo-entry (the idle
		// process), not a process: it has no image, no start time and no
		// key, and it crossed the process bridge as a malformed event
		// (Windows 11 Pro rerun 2026-10-25, D5 group 8).
		if entry.ProcessID != 0 {
			out = append(out, procInfoFromEntry(&entry))
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break // ERROR_NO_MORE_FILES (or any error) ends the walk
		}
	}
	return out, nil
}

// procInfoFromEntry turns one ToolHelp entry into a ProcInfo, enriching with
// the creation time + full image path from a process handle when we can open
// one (best-effort).
func procInfoFromEntry(e *windows.ProcessEntry32) ProcInfo {
	p := ProcInfo{
		PID:         int(e.ProcessID),
		PPID:        int(e.ParentProcessID),
		ExePath:     windows.UTF16ToString(e.ExeFile[:]), // basename from ToolHelp; replaced by full path below
		ThreadCount: int32(e.Threads),                    // cntThreads — cheap compute-footprint metric
	}

	// Prefer an open that also permits a PEB read (PROCESS_VM_READ) so we can
	// recover the command line + cwd ToolHelp omits (§5.5). Fall back to the
	// query-only open (start time + full path) for processes we cannot VM_READ
	// — system, another user's, or higher-integrity ones.
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, e.ProcessID)
	canVMRead := err == nil
	if err != nil {
		h, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, e.ProcessID)
		if err != nil {
			return p // basename only, no start time — tracked but not persisted as attributed
		}
	}
	defer windows.CloseHandle(h) //nolint:errcheck // best-effort

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err == nil {
		p.StartTicks = filetime100ns(creation)
		p.HasStart = true
	}
	if full := queryFullPath(h); full != "" {
		p.ExePath = full
	}
	if canVMRead {
		if argv, cwd, ok := readProcessParameters(h); ok {
			if len(argv) > 0 {
				p.Argv = argv
			}
			p.CWD = cwd
		}
	}
	// Resource counters (CPU / memory / disk / handles) — best-effort; a process
	// we can't query leaves them zero (HasMetrics stays false).
	readProcessMetrics(h, &p)
	return p
}

// platformSessionToken recovers an allowlisted session-id env var value from a
// process's PEB environment block (§5.5 P-B6 env-token / EV). It opens a
// VM_READ handle, reads ONLY the allowlisted keys (processobs.SessionTokenEnvKeys
// — the full environment, which holds secrets, never leaves this function), and
// returns the first match's value. Best-effort: a process we cannot open or
// VM_READ (system / another user's / higher-integrity / already exited) yields
// "" and the run simply isn't EV-attributed (it falls back to the medium
// CorrelateCrossOS pass). Called only for NEW processes by the poll diff, so
// the per-poll cost is bounded.
func platformSessionToken(pid int) string {
	if pid <= 0 {
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h) //nolint:errcheck // best-effort close of a read handle
	return readProcessEnvToken(h, processobs.SessionTokenEnvKeys)
}

// filetime100ns packs a FILETIME (100-ns intervals since 1601) into a single
// int64. It is used only as a stable per-process creation stamp for the
// ProcessKey within a boot — not interpreted as a wall-clock time.
func filetime100ns(ft windows.Filetime) int64 {
	return int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime)
}

// queryFullPath returns the full image path for an open process handle, or ""
// on failure. PROCESS_QUERY_LIMITED_INFORMATION is sufficient.
func queryFullPath(h windows.Handle) string {
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}
