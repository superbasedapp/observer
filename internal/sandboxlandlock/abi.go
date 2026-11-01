package sandboxlandlock

// abi.go is the Landlock ABI table: what each kernel ABI version handles.
// The values are the uapi <linux/landlock.h> access bits (the ones
// golang.org/x/sys/unix spells LANDLOCK_ACCESS_FS_* and
// LANDLOCK_ACCESS_NET_*, restated so this package imports no syscall
// package; TestAccessBitsMatchUnix in cmd/observer keeps them equal).

// Filesystem access rights (uapi bits).
const (
	AccessFSExecute    uint64 = 1 << 0
	AccessFSWriteFile  uint64 = 1 << 1
	AccessFSReadFile   uint64 = 1 << 2
	AccessFSReadDir    uint64 = 1 << 3
	AccessFSRemoveDir  uint64 = 1 << 4
	AccessFSRemoveFile uint64 = 1 << 5
	AccessFSMakeChar   uint64 = 1 << 6
	AccessFSMakeDir    uint64 = 1 << 7
	AccessFSMakeReg    uint64 = 1 << 8
	AccessFSMakeSock   uint64 = 1 << 9
	AccessFSMakeFifo   uint64 = 1 << 10
	AccessFSMakeBlock  uint64 = 1 << 11
	AccessFSMakeSym    uint64 = 1 << 12
	// AccessFSRefer (ABI 2) reparents a file across directories.
	AccessFSRefer uint64 = 1 << 13
	// AccessFSTruncate (ABI 3).
	AccessFSTruncate uint64 = 1 << 14
	// AccessFSIoctlDev (ABI 5) is an ioctl on a device file (a terminal).
	AccessFSIoctlDev uint64 = 1 << 15
	// AccessFSResolveUnix (ABI 9, per sandbox plan section 4.1: the right
	// that governs connecting to a pathname unix socket) is ASSUMED to be the
	// next uapi bit after IOCTL_DEV. It is UNVERIFIED: golang.org/x/sys
	// v0.48.0 does not spell it, so TestLandlockAccessBitsMatchUnix cannot
	// pin it. Check it against the LANDLOCK_ACCESS_FS_* define the 7.1 kernel
	// adds in include/uapi/linux/landlock.h (and the access check on a unix
	// socket connect in security/landlock/fs.c, with LANDLOCK_LAST_ACCESS_FS
	// in security/landlock/limits.h), then add it to that test once x/sys
	// spells it. Until a 7.1 kernel confirms it, register entry LIN-1 stays
	// open, and the exec step's self-test connects to the daemon's sockets
	// and refuses the launch unless the kernel denies each connect
	// (cmd/observer landlockCheckConnects, audit SBX-P3B F2).
	AccessFSResolveUnix uint64 = 1 << 16
)

// Network access rights (uapi bits, ABI 4).
const (
	AccessNetBindTCP    uint64 = 1 << 0
	AccessNetConnectTCP uint64 = 1 << 1
)

// Scopes (uapi bits, ABI 6).
const (
	ScopeAbstractUnixSocket uint64 = 1 << 0
	ScopeSignal             uint64 = 1 << 1
)

// MinABI is the row's floor (section 4.1): ABI 9 is what lets the ruleset
// refuse a connect to the daemon's relay endpoint and the attach socket
// while allowing the run's own relay socket. [terminal.sandbox.landlock]
// .min_abi can only raise it.
const MinABI = 9

// UDPABI is the first ABI that restricts UDP (section 4.1); below it UDP is
// unrestricted and the row discloses that.
const UDPABI = 10

// Features is what one ABI handles.
type Features struct {
	ABI int
	// FS is every filesystem right the ABI handles.
	FS uint64
	// Net is every network right it handles (0 below ABI 4).
	Net uint64
	// Scoped is every scope it handles (0 below ABI 6).
	Scoped uint64
	// ResolveUnix: connecting to a pathname unix socket is a handled right.
	ResolveUnix bool
	// UDP: UDP is restricted (never below UDPABI).
	UDP bool
}

// abiRow is one ABI's additions.
type abiRow struct {
	abi    int
	fs     uint64
	net    uint64
	scoped uint64
}

// abiTable lists what each ABI adds, oldest first.
var abiTable = []abiRow{
	{abi: 1, fs: AccessFSExecute | AccessFSWriteFile | AccessFSReadFile | AccessFSReadDir | AccessFSRemoveDir | AccessFSRemoveFile |
		AccessFSMakeChar | AccessFSMakeDir | AccessFSMakeReg | AccessFSMakeSock | AccessFSMakeFifo | AccessFSMakeBlock | AccessFSMakeSym},
	{abi: 2, fs: AccessFSRefer},
	{abi: 3, fs: AccessFSTruncate},
	{abi: 4, net: AccessNetBindTCP | AccessNetConnectTCP},
	{abi: 5, fs: AccessFSIoctlDev},
	{abi: 6, scoped: ScopeAbstractUnixSocket | ScopeSignal},
	// 7 and 8 add logging and thread-sync flags, no new access right.
	{abi: 9, fs: AccessFSResolveUnix},
}

// FeaturesFor is what abi handles (abi below 1: nothing).
func FeaturesFor(abi int) Features {
	f := Features{ABI: abi}
	for _, r := range abiTable {
		if r.abi > abi {
			break
		}
		f.FS |= r.fs
		f.Net |= r.net
		f.Scoped |= r.scoped
	}
	f.ResolveUnix = f.FS&AccessFSResolveUnix != 0
	f.UDP = abi >= UDPABI
	return f
}

// Floor is the ABI a launch needs: MinABI, raised by a configured min_abi.
func Floor(configured int) int {
	if configured > MinABI {
		return configured
	}
	return MinABI
}
