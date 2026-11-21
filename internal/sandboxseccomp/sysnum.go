package sandboxseccomp

// The architectures the assembler targets, by GOARCH spelling.
const (
	ArchAMD64 = "amd64"
	ArchARM64 = "arm64"
)

// archSpec is one architecture's facts: the seccomp_data.arch value the
// kernel reports for its native ABI, whether the x32 ABI must be refused, and
// the syscall number table.
type archSpec struct {
	audit uint32
	// x32Bit is __X32_SYSCALL_BIT on amd64, 0 elsewhere.
	x32Bit uint32
	nr     map[string]uint32
}

// auditArchX86_64 and auditArchAArch64 are AUDIT_ARCH_X86_64 and
// AUDIT_ARCH_AARCH64 (linux/audit.h).
const (
	auditArchX86_64  = 0xc000003e
	auditArchAArch64 = 0xc00000b7
	// x32SyscallBit is __X32_SYSCALL_BIT (asm/unistd.h on x86).
	x32SyscallBit = 0x40000000
)

// sysnumAMD64 is the x86_64 table, by the kernel's syscall name. Pinned
// against golang.org/x/sys/unix zsysnum_linux_amd64.go by sysnum_test.go.
var sysnumAMD64 = map[string]uint32{
	"acct":              163,
	"add_key":           248,
	"bpf":               321,
	"clock_adjtime":     305,
	"clock_settime":     227,
	"delete_module":     176,
	"finit_module":      313,
	"fsconfig":          431,
	"fsmount":           432,
	"fsopen":            430,
	"fspick":            433,
	"init_module":       175,
	"io_uring_enter":    426,
	"io_uring_register": 427,
	"io_uring_setup":    425,
	"ioperm":            173,
	"iopl":              172,
	"kexec_file_load":   320,
	"kexec_load":        246,
	"keyctl":            250,
	"lookup_dcookie":    212,
	"mount":             165,
	"mount_setattr":     442,
	"move_mount":        429,
	"name_to_handle_at": 303,
	"open_by_handle_at": 304,
	"open_tree":         428,
	"open_tree_attr":    467,
	"perf_event_open":   298,
	"pidfd_getfd":       438,
	"pivot_root":        155,
	"process_vm_readv":  310,
	"process_vm_writev": 311,
	"ptrace":            101,
	"quotactl":          179,
	"quotactl_fd":       443,
	"reboot":            169,
	"request_key":       249,
	"settimeofday":      164,
	"swapoff":           168,
	"swapon":            167,
	"umount2":           166,
	"uselib":            134,
	"userfaultfd":       323,
}

// sysnumARM64 is the aarch64 table (the generic syscall table, so no iopl,
// ioperm or uselib). Pinned against golang.org/x/sys/unix
// zsysnum_linux_arm64.go by sysnum_test.go.
var sysnumARM64 = map[string]uint32{
	"acct":              89,
	"add_key":           217,
	"bpf":               280,
	"clock_adjtime":     266,
	"clock_settime":     112,
	"delete_module":     106,
	"finit_module":      273,
	"fsconfig":          431,
	"fsmount":           432,
	"fsopen":            430,
	"fspick":            433,
	"init_module":       105,
	"io_uring_enter":    426,
	"io_uring_register": 427,
	"io_uring_setup":    425,
	"kexec_file_load":   294,
	"kexec_load":        104,
	"keyctl":            219,
	"lookup_dcookie":    18,
	"mount":             40,
	"mount_setattr":     442,
	"move_mount":        429,
	"name_to_handle_at": 264,
	"open_by_handle_at": 265,
	"open_tree":         428,
	"open_tree_attr":    467,
	"perf_event_open":   241,
	"pidfd_getfd":       438,
	"pivot_root":        41,
	"process_vm_readv":  270,
	"process_vm_writev": 271,
	"ptrace":            117,
	"quotactl":          60,
	"quotactl_fd":       443,
	"reboot":            142,
	"request_key":       218,
	"settimeofday":      170,
	"swapoff":           225,
	"swapon":            224,
	"umount2":           39,
	"userfaultfd":       282,
}

// archs is the architecture table.
var archs = map[string]archSpec{
	ArchAMD64: {audit: auditArchX86_64, x32Bit: x32SyscallBit, nr: sysnumAMD64},
	ArchARM64: {audit: auditArchAArch64, nr: sysnumARM64},
}

// Supported reports whether the assembler targets goarch.
func Supported(goarch string) bool {
	_, ok := archs[goarch]
	return ok
}
