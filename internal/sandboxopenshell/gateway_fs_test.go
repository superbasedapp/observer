package sandboxopenshell

import (
	"strings"
	"testing"
)

// TestGatewayStateFS is one case per row of the state dir's filesystem
// table (F1 to F8), plus the unknown fallthrough and the readings that
// must win over a local-looking magic.
func TestGatewayStateFS(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		f    FSFacts
		tri  Tri
		want string
	}{
		{"F1 DrvFs by type", FSFacts{Magic: magicV9fs, MountType: "drvfs"}, TriNo, "DrvFs"},
		{"F1 DrvFs as 9p with source drvfs", FSFacts{Magic: magicV9fs, MountType: "9p", MountSource: "drvfs"}, TriNo, "DrvFs"},
		{"F1 DrvFs as 9p with a drive source", FSFacts{Magic: magicV9fs, MountType: "9p", MountSource: `C:\`}, TriNo, "DrvFs"},
		{"F2 9p share", FSFacts{Magic: magicV9fs, MountType: "9p", MountSource: "hostshare"}, TriNo, "9p or VM shared"},
		{"F2 virtiofs", FSFacts{Magic: magicVirtiofs, MountType: "virtiofs"}, TriNo, "9p or VM shared"},
		{"F2 VirtualBox shared folder", FSFacts{MountType: "vboxsf"}, TriNo, "VM shared"},
		{"F3 sshfs", FSFacts{Magic: magicFuse, MountType: "fuse.sshfs"}, TriNo, "FUSE"},
		{"F3 FUSE by magic only", FSFacts{Magic: magicFuse}, TriNo, "FUSE"},
		{"F4 NFS", FSFacts{Magic: magicNFS, MountType: "nfs4"}, TriNo, "network"},
		{"F4 CIFS", FSFacts{Magic: magicCIFS, MountType: "cifs"}, TriNo, "network"},
		{"F4 SMB2 magic", FSFacts{Magic: magicSMB2}, TriNo, "network"},
		{"F4 Ceph", FSFacts{MountType: "ceph"}, TriNo, "network"},
		{"F4 GlusterFS over FUSE is FUSE first", FSFacts{Magic: magicFuse, MountType: "fuse.glusterfs"}, TriNo, "FUSE"},
		{"F5 autofs", FSFacts{Magic: magicAutofs}, TriNo, "automount"},
		{"F6 exFAT", FSFacts{Magic: magicExFAT, MountType: "exfat"}, TriNo, "POSIX"},
		{"F6 vfat", FSFacts{MountType: "vfat"}, TriNo, "POSIX"},
		{"F7 squashfs", FSFacts{Magic: magicSquashfs}, TriNo, "read-only or virtual"},
		{"F7 procfs", FSFacts{Magic: magicProc}, TriNo, "read-only or virtual"},
		{"F8 ext4", FSFacts{Magic: magicExt, MountType: "ext4"}, TriYes, "local"},
		{"F8 xfs", FSFacts{Magic: magicXFS}, TriYes, "local"},
		{"F8 btrfs", FSFacts{Magic: magicBtrfs}, TriYes, "local"},
		{"F8 zfs", FSFacts{Magic: magicZFS}, TriYes, "local"},
		{"F8 overlay (a container root)", FSFacts{Magic: magicOverlay}, TriYes, "local"},
		{"F8 tmpfs", FSFacts{Magic: magicTmpfs}, TriYes, "local"},
		{"a foreign mount type wins over a local magic", FSFacts{Magic: magicExt, MountType: "nfs"}, TriNo, "network"},
		{"unknown", FSFacts{Magic: 0x1234}, TriUnknown, "unrecognised"},
		{"nothing read", FSFacts{}, TriUnknown, "unrecognised"},
	}
	ids := map[string]bool{}
	for _, tc := range cases {
		if strings.HasPrefix(tc.name, "F") {
			ids[tc.name[:2]] = true
		}
		tri, name := GatewayStateFS(tc.f)
		if tri != tc.tri || !strings.Contains(name, tc.want) {
			t.Errorf("%s: %q %q, want %q containing %q", tc.name, tri, name, tc.tri, tc.want)
		}
	}
	for _, r := range stateFSRows {
		if !ids[r.id[:2]] {
			t.Errorf("row %s has no case", r.id)
		}
	}
}

// TestGatewayRuntimeFS is one case per row of the runtime dir's table.
func TestGatewayRuntimeFS(t *testing.T) {
	t.Parallel()
	good := DirFacts{FS: FSFacts{Magic: magicTmpfs, MountType: "tmpfs"}, Exists: true, IsDir: true, OwnerUID: 1000, Mode: 0o700}
	cases := []struct {
		name string
		mod  func(d *DirFacts)
		tri  Tri
		want string
	}{
		{"private tmpfs", func(*DirFacts) {}, TriYes, ""},
		{"ramfs", func(d *DirFacts) { d.FS.Magic = magicRamfs }, TriYes, ""},
		{"missing", func(d *DirFacts) { d.Exists = false }, TriNo, "does not exist"},
		{"a link", func(d *DirFacts) { d.IsLink = true }, TriNo, "symbolic link"},
		{"a file", func(d *DirFacts) { d.IsDir = false }, TriNo, "not a directory"},
		{"another owner", func(d *DirFacts) { d.OwnerUID = 0 }, TriNo, "uid 0"},
		{"group readable", func(d *DirFacts) { d.Mode = 0o750 }, TriNo, "750"},
		{"world writable", func(d *DirFacts) { d.Mode = 0o1777 }, TriNo, "777"},
		{"on a disk", func(d *DirFacts) { d.FS = FSFacts{Magic: magicExt, MountType: "ext4"} }, TriNo, "reach a disk"},
	}
	for _, tc := range cases {
		d := good
		tc.mod(&d)
		tri, why := GatewayRuntimeFS(d, 1000)
		if tri != tc.tri || !strings.Contains(why, tc.want) {
			t.Errorf("%s: %q %q, want %q containing %q", tc.name, tri, why, tc.tri, tc.want)
		}
	}
	if len(runtimeRows) != 5 {
		t.Fatalf("%d runtime rows; add a case for the new one", len(runtimeRows))
	}
}
