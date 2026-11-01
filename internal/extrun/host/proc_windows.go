//go:build windows

package host

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// platformCaps is what Windows holds: the program starts suspended and is
// resumed only inside its job object, so every cap holds from its first
// instruction.
// The CPU cap is the job's user-time limit, which Windows enforces late
// (JSP-12: 8 s for a 1 s limit), so it is best effort and the wall cap is
// the timeliness guarantee. There is no file-size cap.
func platformCaps() map[extrun.Cap]extrun.CapState {
	return map[extrun.Cap]extrun.CapState{
		extrun.CapWall:     extrun.CapEnforced,
		extrun.CapStdout:   extrun.CapEnforced,
		extrun.CapStderr:   extrun.CapEnforced,
		extrun.CapMemory:   extrun.CapEnforced,
		extrun.CapChildren: extrun.CapEnforced,
		extrun.CapCPU:      extrun.CapBestEffort,
	}
}

// trampolineSupported: Windows needs no trampoline; the job object holds
// every cap from the first instruction.
const trampolineSupported = false

// selfPath is never used here (no trampoline).
func selfPath(bool) (string, error) { return os.Executable() }

// appliedCaps reports the job object's mechanisms for every requested cap.
func appliedCaps(l extrun.Limits, _ trampolineStatus, _ bool) map[extrun.Cap]extrun.CapApplied {
	return jobApplied(l)
}

// prepareCmd starts the program suspended, so attach can put it in the job
// before it runs a single instruction.
func prepareCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
}

// jobGroup is a job object holding the program and everything it starts.
type jobGroup struct {
	job windows.Handle
}

// kill terminates every process in the job. The executor calls it at every
// cap and always once more after the program exits.
func (g *jobGroup) kill() {
	if g.job != 0 {
		_ = windows.TerminateJobObject(g.job, 1)
	}
}

// jobAccounting is JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.
type jobAccounting struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

// active returns how many processes are in the job now.
func (g *jobGroup) active() (int, bool) {
	if g.job == 0 {
		return 0, false
	}
	var acc jobAccounting
	if err := windows.QueryInformationJobObject(g.job, windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&acc)), uint32(unsafe.Sizeof(acc)), nil); err != nil {
		return 0, false
	}
	return int(acc.ActiveProcesses), true
}

// count is not polled on Windows: the active-process limit is held by the
// job itself.
func (g *jobGroup) count() (int, bool) { return 0, false }

// close closes the job handle; KILL_ON_JOB_CLOSE ends anything still in it.
func (g *jobGroup) close() {
	if g.job != 0 {
		_ = windows.CloseHandle(g.job)
		g.job = 0
	}
}

// attach builds the job (kill on close, plus the memory and active-process
// limits when requested), assigns the suspended program to it and resumes
// it. Any failure is returned, and the caller kills the still-suspended
// program: a run is never left outside its job.
func attach(cmd *exec.Cmd, l extrun.Limits) (procGroup, error) {
	pid := uint32(cmd.Process.Pid)
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("extrun/host: CreateJobObject: %w", err)
	}
	g := &jobGroup{job: job}
	// The job's limits come from the pure job table (jobplan.go): kill on
	// close always, BREAKAWAY_OK never.
	plan := planJob(l)
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.JobMemoryLimit = uintptr(plan.memory)
	info.BasicLimitInformation.ActiveProcessLimit = plan.activeProcesses
	info.BasicLimitInformation.PerJobUserTimeLimit = plan.userTime100ns
	info.BasicLimitInformation.LimitFlags = plan.flags
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		g.close()
		return nil, fmt.Errorf("extrun/host: SetInformationJobObject: %w", err)
	}
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		g.close()
		return nil, fmt.Errorf("extrun/host: OpenProcess: %w", err)
	}
	err = windows.AssignProcessToJobObject(job, ph)
	_ = windows.CloseHandle(ph)
	if err != nil {
		g.close()
		return nil, fmt.Errorf("extrun/host: AssignProcessToJobObject: %w", err)
	}
	if err := resumeProcess(pid); err != nil {
		g.kill()
		g.close()
		return nil, err
	}
	return g, nil
}

// resumeProcess resumes every thread of the suspended process pid (a newly
// created process has exactly one).
func resumeProcess(pid uint32) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("extrun/host: CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap) //nolint:errcheck // best effort
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	resumed := 0
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid {
			continue
		}
		th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if err != nil {
			return fmt.Errorf("extrun/host: OpenThread: %w", err)
		}
		_, rerr := windows.ResumeThread(th)
		_ = windows.CloseHandle(th)
		if rerr != nil {
			return fmt.Errorf("extrun/host: ResumeThread: %w", rerr)
		}
		resumed++
	}
	if resumed == 0 {
		return fmt.Errorf("extrun/host: no thread of process %d to resume", pid)
	}
	return nil
}

// signalOf: Windows has no signals.
func signalOf(*os.ProcessState) (string, bool) { return "", false }
