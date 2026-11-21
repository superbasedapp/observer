//go:build linux && (amd64 || arm64)

package sandboxseccomp

import (
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSysnumNative pins the running architecture's table against the
// compiled x/sys constants (the source pin covers the other one).
func TestSysnumNative(t *testing.T) {
	want := map[string]uint32{
		"mount": unix.SYS_MOUNT, "umount2": unix.SYS_UMOUNT2, "ptrace": unix.SYS_PTRACE,
		"bpf": unix.SYS_BPF, "keyctl": unix.SYS_KEYCTL, "io_uring_setup": unix.SYS_IO_URING_SETUP,
		"kexec_load": unix.SYS_KEXEC_LOAD, "open_by_handle_at": unix.SYS_OPEN_BY_HANDLE_AT,
		"userfaultfd": unix.SYS_USERFAULTFD, "perf_event_open": unix.SYS_PERF_EVENT_OPEN,
		"fsopen": unix.SYS_FSOPEN, "mount_setattr": unix.SYS_MOUNT_SETATTR,
	}
	spec := archs[runtime.GOARCH]
	for name, nr := range want {
		if spec.nr[name] != nr {
			t.Errorf("%s: %s is %d here, %d in x/sys", runtime.GOARCH, name, spec.nr[name], nr)
		}
	}
	if runtime.GOARCH == ArchAMD64 && spec.audit != unix.AUDIT_ARCH_X86_64 || runtime.GOARCH == ArchARM64 && spec.audit != unix.AUDIT_ARCH_AARCH64 {
		t.Errorf("audit arch %#x", spec.audit)
	}
	if retKillProcess != unix.SECCOMP_RET_KILL_PROCESS || retErrno != unix.SECCOMP_RET_ERRNO || retAllow != unix.SECCOMP_RET_ALLOW {
		t.Error("the seccomp return values differ from x/sys")
	}
	if ptraceAttach != unix.PTRACE_ATTACH || ptraceSeize != unix.PTRACE_SEIZE {
		t.Error("the ptrace request values differ from x/sys")
	}
}
