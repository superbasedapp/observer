package sandboxvm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// disk.go plans a disk_image workspace copy (sandbox plan v2 section 6,
// lane SBX-P4 decision 5): the copy is written into an ext4 image with
// `mkfs.ext4 -d` (no root needed, e2fsprogs 1.43 or later), attached as a
// writable virtio-blk disk, and after the run read back into the copy dir
// with `debugfs -R "rdump / <dir>"`, also without root, before the return
// step scans it. The image is one the guest wrote, so debugfs runs inside
// bwrap (ConfinedDumpArgv) with one writable path, the fresh empty target.
// It is offered for copies only and never the default; a host without the
// programs (bwrap included) refuses the delivery naming the program.

// The delivery values ([terminal.sandbox.vm].workspace_delivery).
const (
	DeliveryVirtiofs  = "virtiofs"
	DeliveryDiskImage = "disk_image"
)

// Disk image size bounds.
const (
	diskHeadroom = 256 << 20
	diskMin      = 64 << 20
	// DiskMax caps a workspace image.
	DiskMax = 64 << 30
)

// DiskImageSize is the image size for a tree of treeBytes: the tree twice
// over plus headroom, at least diskMin, rounded up to a MiB.
func DiskImageSize(treeBytes int64) (int64, error) {
	if treeBytes < 0 {
		return 0, errors.New("sandboxvm: a negative tree size")
	}
	n := 2*treeBytes + diskHeadroom
	if n < diskMin {
		n = diskMin
	}
	n = (n + (1<<20 - 1)) &^ (1<<20 - 1)
	if n > DiskMax {
		return 0, fmt.Errorf("sandboxvm: the workspace needs a %d MiB image, over the %d MiB cap", n>>20, DiskMax>>20)
	}
	return n, nil
}

// MkfsArgv is the image's mkfs.ext4: from src, owned by uid:gid at its
// root, no reserved blocks, the label ws.
func MkfsArgv(mkfs, src, img string, size int64, uid, gid int) ([]string, error) {
	for _, p := range []string{mkfs, src, img} {
		if !cleanAbs(p) {
			return nil, fmt.Errorf("sandboxvm: %q is not a clean absolute path", p)
		}
	}
	if size < diskMin || size > DiskMax || uid < 0 || gid < 0 {
		return nil, errors.New("sandboxvm: a disk image size or owner out of range")
	}
	return []string{
		mkfs, "-q", "-F", "-t", "ext4", "-d", src, "-E", "root_owner=" + strconv.Itoa(uid) + ":" + strconv.Itoa(gid),
		"-L", "ws", "-m", "0", img, strconv.FormatInt(size>>20, 10) + "M",
	}, nil
}

// DumpArgv reads an image back into dst (an empty directory) with debugfs.
func DumpArgv(debugfs, img, dst string) ([]string, error) {
	for _, p := range []string{debugfs, img, dst} {
		if !cleanAbs(p) {
			return nil, fmt.Errorf("sandboxvm: %q is not a clean absolute path", p)
		}
	}
	return []string{debugfs, "-R", "rdump / " + dst, img}, nil
}

// ConfinedDumpArgv is DumpArgv inside bwrap (SBX-BE-5): every structure
// debugfs parses in the image, the raw directory entries included, is
// guest-written, so a path traversal or a parser bug must land nowhere but
// the target. bwrap gives debugfs the host root read-only (the image is
// read through it), a fresh /dev and /proc, every namespace unshared (no
// network), a new session, death with its parent, and exactly one writable
// path: dst, the fresh empty directory, bound alone. The user's home and
// every other path stay read-only. The tree it writes is then judged by
// the return precheck like every copy.
func ConfinedDumpArgv(bwrap, debugfs, img, dst string) ([]string, error) {
	if !cleanAbs(bwrap) {
		return nil, fmt.Errorf("sandboxvm: bwrap %q is not a clean absolute path", bwrap)
	}
	inner, err := DumpArgv(debugfs, img, dst)
	if err != nil {
		return nil, err
	}
	if dst == "/" || within(img, dst) {
		return nil, errors.New("sandboxvm: the image must not lie inside the dump target")
	}
	argv := []string{
		bwrap, "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
		"--bind", dst, dst,
		"--unshare-all", "--die-with-parent", "--new-session", "--",
	}
	return append(argv, inner...), nil
}

// MappingRow is one row of the workspace mapping table: a source and a
// delivery, and what the row does.
type MappingRow struct {
	Source   string
	Delivery string
	// OK: the row is offered; Why: the refusal otherwise.
	OK  bool
	Why string
}

// The workspace sources (internal/workspace spellings, restated so this
// package stays free of it).
const (
	SourceLive        = "live"
	SourceCloneLocal  = "clone-local"
	SourceCloneRemote = "clone-remote"
	SourceWorktree    = "worktree"
)

// mappingTable is THE table (one test case per row).
var mappingTable = []MappingRow{
	{SourceLive, DeliveryVirtiofs, true, "the live workspace through the confined virtiofsd (host-enforced git-dir pins, read back before boot)"},
	{SourceLive, DeliveryDiskImage, false, "a live workspace is never copied into a disk image; use virtiofs"},
	{SourceCloneLocal, DeliveryVirtiofs, true, "the copy shared by a virtiofsd; its commits return through the scanned return step"},
	{SourceCloneLocal, DeliveryDiskImage, true, "the copy written into an ext4 image and read back for the scanned return step"},
	{SourceCloneRemote, DeliveryVirtiofs, true, "the clone shared by a virtiofsd; its commits return into the bare return repository"},
	{SourceCloneRemote, DeliveryDiskImage, true, "the clone written into an ext4 image and read back for the return"},
	{SourceWorktree, DeliveryVirtiofs, false, "a worktree's git dir is its repository's own: shared by a plain virtiofsd it would be writable from the guest with no .git pin and no return scan, so the worktree source is refused on this row; use clone-local"},
	{SourceWorktree, DeliveryDiskImage, false, "a worktree shares its repository's git dir, which a disk image cannot carry; use virtiofs"},
}

// Mapping returns the row for a source and a delivery ("" is virtiofs).
func Mapping(source, delivery string) MappingRow {
	if delivery == "" {
		delivery = DeliveryVirtiofs
	}
	for _, r := range mappingTable {
		if r.Source == source && r.Delivery == delivery {
			return r
		}
	}
	return MappingRow{Source: source, Delivery: delivery, Why: "no mapping row for source " + strconv.Quote(source) + " with delivery " + strconv.Quote(delivery)}
}

// The ext4 superblock fields ImageNeedsRecovery reads (the superblock starts
// at byte 1024 of the image).
const (
	ext4SuperOffset     = 1024
	ext4MagicOffset     = 0x38
	ext4IncompatOffset  = 0x60
	ext4Magic           = 0xEF53
	ext4IncompatRecover = 0x0004
)

// ImageNeedsRecovery reports whether the ext4 image r was left mounted: its
// superblock still carries the journal's needs_recovery flag. debugfs reads
// such an image without replaying the journal, so its rdump returns the tree
// as it was before the guest's journaled changes (the microVM row's second
// live run: a guest commit missing from the read-back, the copy returned
// unchanged). Only the superblock's magic and incompat word are read.
func ImageNeedsRecovery(r io.ReaderAt) (bool, error) {
	var sb [ext4IncompatOffset + 4]byte
	if _, err := r.ReadAt(sb[:], ext4SuperOffset); err != nil {
		return false, fmt.Errorf("sandboxvm: read the image superblock: %w", err)
	}
	if binary.LittleEndian.Uint16(sb[ext4MagicOffset:]) != ext4Magic {
		return false, errors.New("sandboxvm: the workspace image is not ext4")
	}
	return binary.LittleEndian.Uint32(sb[ext4IncompatOffset:])&ext4IncompatRecover != 0, nil
}
