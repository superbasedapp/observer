package gitroute

import (
	"reflect"
	"testing"
)

// liveMountinfo is the shape of a WSL2 distro's mount table (2026-11-11,
// this repository's development host), with a space-carrying mount, a
// UNC DrvFs share, a WSL1-style drvfs mount and a tmpfs stacked inside a
// drive added.
const liveMountinfo = `85 1 8:48 / / rw,relatime - ext4 /dev/sdd rw,discard,errors=remount-ro,data=ordered
135 85 0:70 / /mnt/c rw,noatime - 9p C:\134 rw,aname=drvfs;path=C:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=0x5,access=client,msize=65536,trans=fd,rfd=6,wfd=6
136 85 0:71 / /mnt/d rw,noatime - 9p D:\134 rw,aname=drvfs;path=D:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=0x5,access=client,msize=65536,trans=fd,rfd=6,wfd=6
137 85 0:72 / /mnt/my\040share rw,noatime - 9p \134\134srv\134share rw,aname=drvfs;path=\\srv\share;uid=1000
138 85 0:73 / /e rw,noatime shared:1 - drvfs E: rw,uid=1000
139 136 0:74 / /mnt/d/tmpfs rw - tmpfs none rw
140 85 0:75 /Users /winusers rw - 9p C:\134 rw,aname=drvfs;path=C:\;uid=1000
not a mount line
`

func TestParseMountinfo(t *testing.T) {
	got := ParseMountinfo([]byte(liveMountinfo))
	want := []Mount{
		{Point: "/", Root: "/", FSType: "ext4"},
		{Point: "/mnt/c", Root: "/", FSType: "9p", DrvFs: true, Drive: 'C'},
		{Point: "/mnt/d", Root: "/", FSType: "9p", DrvFs: true, Drive: 'D'},
		{Point: "/mnt/my share", Root: "/", FSType: "9p"},
		{Point: "/e", Root: "/", FSType: "drvfs", DrvFs: true, Drive: 'E'},
		{Point: "/mnt/d/tmpfs", Root: "/", FSType: "tmpfs"},
		{Point: "/winusers", Root: "/Users", FSType: "9p", DrvFs: true, Drive: 'C'},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseMountinfo =\n%+v\nwant\n%+v", got, want)
	}
}

func TestWindowsPathThroughTheMountTable(t *testing.T) {
	mounts := ParseMountinfo([]byte(liveMountinfo))
	for _, tc := range []struct {
		name, root, want string
		drvfs            bool
	}{
		{"repository on D:", "/mnt/d/programsx/superbased-observer", `D:\programsx\superbased-observer`, true},
		{"drive root", "/mnt/c", `C:\`, true},
		{"trailing slash and dot segments", "/mnt/d/a/./b/../c/", `D:\a\c`, true},
		{"spaces kept", "/mnt/c/Users/Dev User/my repo", `C:\Users\Dev User\my repo`, true},
		{"non-default automount root (WSL1 drvfs)", "/e/work/repo", `E:\work\repo`, true},
		{"a bind of a drive subdirectory", "/winusers/dev/repo", `C:\Users\dev\repo`, true},
		{"the Linux filesystem", "/home/dev/repo", "", false},
		{"a tmpfs mounted inside a drive is not the drive", "/mnt/d/tmpfs/repo", "", false},
		{"a UNC DrvFs share has no drive spelling", "/mnt/my share/repo", "", false},
		{"a directory named like a drive", "/mnt/cfoo/repo", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := MountFor(mounts, tc.root)
			if !ok {
				t.Fatalf("MountFor(%q) found no mount (the root mount holds everything)", tc.root)
			}
			if m.DrvFs != tc.drvfs {
				t.Fatalf("MountFor(%q) = %+v, DrvFs want %v", tc.root, m, tc.drvfs)
			}
			got, ok := WindowsPath(m, tc.root)
			if ok != (tc.want != "") || got != tc.want {
				t.Fatalf("WindowsPath(%q) = %q, %v; want %q", tc.root, got, ok, tc.want)
			}
		})
	}
	if _, ok := MountFor(mounts, "relative/path"); ok {
		t.Fatal("a relative root matched a mount")
	}
}

func TestPrefixMount(t *testing.T) {
	for _, tc := range []struct {
		root, want string
	}{
		{"/mnt/d/programsx/repo", `D:\programsx\repo`},
		{"/mnt/C/x", `C:\x`},
		{"/mnt/c", `C:\`},
		{"/mnt/cfoo/repo", ""},
		{"/mnt/wsl/x", ""},
		{"/mnt/", ""},
		{"/mnt/1/x", ""},
		{"/home/dev", ""},
	} {
		m, ok := PrefixMount(tc.root)
		got, gotOK := "", false
		if ok {
			got, gotOK = WindowsPath(m, tc.root)
		}
		if gotOK != (tc.want != "") || got != tc.want {
			t.Errorf("PrefixMount(%q) spelled %q, %v; want %q", tc.root, got, gotOK, tc.want)
		}
	}
}

func TestUnescapeMountinfo(t *testing.T) {
	for in, want := range map[string]string{
		`/mnt/a\040b`:    "/mnt/a b",
		`C:\134`:         `C:\`,
		`tab\011nl\012x`: "tab\tnl\nx",
		`not\9escape`:    `not\9escape`,
		`end\04`:         `end\04`,
		`plain`:          "plain",
	} {
		if got := unescapeMountinfo(in); got != want {
			t.Errorf("unescapeMountinfo(%q) = %q, want %q", in, got, want)
		}
	}
}
