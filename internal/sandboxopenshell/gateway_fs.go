package sandboxopenshell

import (
	"strconv"
	"strings"
)

// gateway_fs.go is the managed gateway's filesystem refusal table (lane
// O2 M4): the private gateway's state dir (its config and its SQLite
// database of sandboxes) must be on a local Linux filesystem, and its
// runtime dir (the PKI and the CLI registry while it runs) must be a RAM
// filesystem owned by the user with no group or other access. A DrvFs or
// 9p share (WSL2's view of a Windows drive), a FUSE mount (sshfs, rclone)
// or a network filesystem (NFS, SMB/CIFS, Ceph, Lustre) is refused: their
// owner and mode bits do not mean what the checks read, and SQLite's
// locking is not reliable on them. The driver reads statfs and the
// mountinfo row of the dir; this file decides.

// FSFacts is what the driver read about one directory's filesystem.
type FSFacts struct {
	// Magic is statfs's f_type (0: not read).
	Magic int64
	// MountType is the filesystem type field of the dir's mountinfo row
	// ("" not read), for example "ext4", "9p", "fuse.sshfs", "nfs4".
	MountType string
	// MountSource is that row's mount source ("" not read): WSL2 mounts a
	// Windows drive as 9p with the source "drvfs" or "C:\".
	MountSource string
}

// The statfs magic numbers this table reads (linux/magic.h).
const (
	magicExt       = 0xEF53
	magicXFS       = 0x58465342
	magicBtrfs     = 0x9123683E
	magicZFS       = 0x2FC12FC1
	magicF2FS      = 0xF2F52010
	magicBcachefs  = 0xCA451A4E
	magicJFS       = 0x3153464A
	magicReiser    = 0x52654973
	magicEcryptfs  = 0xF15F
	magicOverlay   = 0x794C7630
	magicTmpfs     = 0x01021994
	magicRamfs     = 0x858458F6
	magicV9fs      = 0x01021997
	magicFuse      = 0x65735546
	magicNFS       = 0x6969
	magicSMB       = 0x517B
	magicCIFS      = 0xFF534D42
	magicSMB2      = 0xFE534D42
	magicCeph      = 0x00C36400
	magicAFS       = 0x5346414F
	magicLustre    = 0x0BD00BD0
	magicVirtiofs  = 0x6A656A63
	magicCoda      = 0x73757245
	magicOCFS2     = 0x7461636F
	magicGFS2      = 0x01161970
	magicNCP       = 0x564C
	magicAutofs    = 0x0187
	magicVboxsf    = 0x786F4256
	magicPrlFS     = 0x7C7C6673
	magicOrangeFS  = 0x20030528
	magicHFSPlus   = 0x482B
	magicNTFS3     = 0x7366746E
	magicExFAT     = 0x2011BAB0
	magicMSDOS     = 0x4D44
	magicNilfs     = 0x3434
	magicSquashfs  = 0x73717368
	magicISO9660   = 0x9660
	magicDebugfs   = 0x64626720
	magicProc      = 0x9FA0
	magicSysfs     = 0x62656572
	magicDevpts    = 0x1CD1
	magicCgroup2   = 0x63677270
	magicSecurityF = 0x73636673
)

// fsRow is one row of the filesystem table.
type fsRow struct {
	id    string
	match func(f FSFacts) bool
	tri   Tri
	name  string
}

// mountTypeIs matches the mountinfo type exactly or as a "type." prefix
// (fuse.sshfs).
func mountTypeIs(f FSFacts, types ...string) bool {
	for _, t := range types {
		if f.MountType == t || strings.HasPrefix(f.MountType, t+".") {
			return true
		}
	}
	return false
}

// magicIs matches the statfs magic.
func magicIs(f FSFacts, magics ...int64) bool {
	for _, m := range magics {
		if f.Magic == m {
			return true
		}
	}
	return false
}

// stateFSRows is the state dir's table, walked top-down: a foreign
// filesystem by either reading is refused first, then the local ones are
// accepted, and anything else is unknown (refused, lifecycle row G4).
var stateFSRows = []fsRow{
	{"F1 DrvFs", func(f FSFacts) bool {
		src := strings.ToLower(f.MountSource)
		return mountTypeIs(f, "drvfs") || (mountTypeIs(f, "9p") && (src == "drvfs" || strings.Contains(src, ":\\") || strings.HasSuffix(src, ":")))
	}, TriNo, "DrvFs (a Windows drive mounted into WSL2)"},
	{"F2 9p or a VM share", func(f FSFacts) bool {
		return magicIs(f, magicV9fs, magicVirtiofs, magicVboxsf, magicPrlFS) || mountTypeIs(f, "9p", "virtiofs", "vboxsf", "prl_fs")
	}, TriNo, "a 9p or VM shared folder"},
	{"F3 FUSE", func(f FSFacts) bool { return magicIs(f, magicFuse) || mountTypeIs(f, "fuse", "fuseblk") }, TriNo, "a FUSE mount"},
	{"F4 network filesystem", func(f FSFacts) bool {
		return magicIs(f, magicNFS, magicSMB, magicCIFS, magicSMB2, magicCeph, magicAFS, magicLustre, magicCoda, magicOCFS2, magicGFS2, magicNCP, magicOrangeFS) ||
			mountTypeIs(f, "nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "afs", "lustre", "glusterfs", "gfs2", "ocfs2", "coda", "beegfs", "gpfs")
	}, TriNo, "a network filesystem"},
	{"F5 automount point", func(f FSFacts) bool { return magicIs(f, magicAutofs) || mountTypeIs(f, "autofs") }, TriNo, "an automount point"},
	{"F6 no POSIX owner", func(f FSFacts) bool {
		return magicIs(f, magicHFSPlus, magicNTFS3, magicExFAT, magicMSDOS) || mountTypeIs(f, "vfat", "exfat", "ntfs", "ntfs3", "hfsplus", "msdos")
	}, TriNo, "a filesystem without POSIX owners and modes"},
	{"F7 read-only or virtual", func(f FSFacts) bool {
		return magicIs(f, magicSquashfs, magicISO9660, magicProc, magicSysfs, magicDevpts, magicDebugfs, magicCgroup2, magicSecurityF)
	}, TriNo, "a read-only or virtual filesystem"},
	{"F8 local Linux filesystem", func(f FSFacts) bool {
		return magicIs(f, magicExt, magicXFS, magicBtrfs, magicZFS, magicF2FS, magicBcachefs, magicJFS, magicReiser, magicEcryptfs, magicOverlay, magicTmpfs, magicRamfs, magicNilfs)
	}, TriYes, "a local Linux filesystem"},
}

// GatewayStateFS classifies the state dir's filesystem: TriYes for a local
// Linux filesystem, TriNo with its kind for a foreign one, TriUnknown for
// one this table does not know (refused too, so a new foreign filesystem
// is never taken for local).
func GatewayStateFS(f FSFacts) (Tri, string) {
	for _, r := range stateFSRows {
		if r.match(f) {
			return r.tri, r.name + fsLabel(f)
		}
	}
	return TriUnknown, "an unrecognised filesystem" + fsLabel(f)
}

// fsLabel renders the facts that named a filesystem.
func fsLabel(f FSFacts) string {
	var parts []string
	if f.MountType != "" {
		parts = append(parts, f.MountType)
	}
	if f.Magic != 0 {
		parts = append(parts, "0x"+strconv.FormatInt(f.Magic, 16))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// DirFacts is what the driver read about the runtime dir itself.
type DirFacts struct {
	FS FSFacts
	// Exists, IsDir and IsLink describe the path (read without following
	// a link).
	Exists, IsDir, IsLink bool
	// OwnerUID is its owner and Mode its permission bits.
	OwnerUID int
	Mode     uint32
}

// runtimeRow is one row of the runtime dir table.
type runtimeRow struct {
	fails  func(d DirFacts, uid int) bool
	detail func(d DirFacts) string
}

// runtimeRows is the runtime dir's table ($XDG_RUNTIME_DIR, which systemd
// makes a tmpfs owned by the user with mode 0700), first failing row wins.
var runtimeRows = []runtimeRow{
	{func(d DirFacts, _ int) bool { return !d.Exists }, func(DirFacts) string {
		return "it does not exist (XDG_RUNTIME_DIR is not set, or no user session made it)"
	}},
	{func(d DirFacts, _ int) bool { return d.IsLink || !d.IsDir }, func(DirFacts) string { return "it is not a directory (or is a symbolic link)" }},
	{func(d DirFacts, uid int) bool { return d.OwnerUID != uid }, func(d DirFacts) string { return "it is owned by uid " + strconv.Itoa(d.OwnerUID) + ", not you" }},
	{func(d DirFacts, _ int) bool { return d.Mode&0o077 != 0 }, func(d DirFacts) string {
		return "its mode is " + strconv.FormatUint(uint64(d.Mode&0o777), 8) + ", not private to you (0700)"
	}},
	{func(d DirFacts, _ int) bool { return !magicIs(d.FS, magicTmpfs, magicRamfs) }, func(d DirFacts) string {
		return "it is not a RAM filesystem (tmpfs)" + fsLabel(d.FS) + ", so a key written there would reach a disk"
	}},
}

// GatewayRuntimeFS checks the runtime dir for the user uid: TriYes when it
// is a private RAM directory, TriNo with the reason otherwise.
func GatewayRuntimeFS(d DirFacts, uid int) (Tri, string) {
	for _, r := range runtimeRows {
		if r.fails(d, uid) {
			return TriNo, r.detail(d)
		}
	}
	return TriYes, ""
}
