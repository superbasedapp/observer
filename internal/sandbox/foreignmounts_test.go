package sandbox

import (
	"reflect"
	"strings"
	"testing"
)

// groundedMountinfo is /proc/self/mountinfo lines copied from a WSL2 host
// (kernel 6.18.58.1-microsoft-standard-WSL2, WSL 3.0.5.0, Ubuntu, live
// confinement check 2026-11-15): the root, the WSL tmpfs and driver mounts, a
// Linux ext4 mount nested under one, and the two Windows drives C: and D:.
const groundedMountinfo = `85 69 8:48 / / rw,relatime - ext4 /dev/sdd rw,discard,errors=remount-ro,data=ordered
81 85 0:34 / /mnt/wsl rw,relatime shared:1 - tmpfs none rw
82 85 0:36 / /usr/lib/wsl/drivers ro,nosuid,nodev,noatime - 9p drivers ro,aname=drivers;fmask=222;dmask=222,cache=0x5,access=client,msize=65536,trans=fd,rfd=8,wfd=8
86 85 0:40 / /mnt/wslg rw,relatime shared:2 - tmpfs none rw
87 86 8:48 / /mnt/wslg/distro ro,relatime shared:3 - ext4 /dev/sdd rw,discard,errors=remount-ro,data=ordered
135 85 0:70 / /mnt/c rw,noatime - 9p C:\134 rw,aname=drvfs;path=C:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=0x5,access=client,msize=65536,trans=fd,rfd=6,wfd=6
136 85 0:71 / /mnt/d rw,noatime - 9p D:\134 rw,aname=drvfs;path=D:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=0x5,access=client,msize=65536,trans=fd,rfd=6,wfd=6
`

// groundedMounts is the same host's /proc/mounts for the same mounts.
const groundedMounts = `/dev/sdd / ext4 rw,relatime,discard,errors=remount-ro,data=ordered 0 0
none /mnt/wsl tmpfs rw,relatime 0 0
drivers /usr/lib/wsl/drivers 9p ro,nosuid,nodev,noatime,aname=drivers;fmask=222;dmask=222,cache=0x5,access=client,msize=65536,trans=fd,rfd=8,wfd=8 0 0
C:\134 /mnt/c 9p rw,noatime,aname=drvfs;path=C:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=0x5,access=client,msize=65536,trans=fd,rfd=6,wfd=6 0 0
D:\134 /mnt/d 9p rw,noatime,aname=drvfs;path=D:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=0x5,access=client,msize=65536,trans=fd,rfd=6,wfd=6 0 0
`

// TestForeignDriveClassification is one row per mount-line shape: which
// foreign-drive rule (if any) names the mount, and where the mount is.
func TestForeignDriveClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		line      string
		wantPoint string
		wantRule  string // "" means not a foreign drive
	}{
		{"mountinfo 9p drvfs (grounded)", `135 85 0:70 / /mnt/c rw,noatime - 9p C:\134 rw,aname=drvfs;path=C:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=0x5,access=client,msize=65536,trans=fd,rfd=6,wfd=6`, "/mnt/c", "9p-aname-drvfs"},
		{"mounts 9p drvfs (grounded)", `D:\134 /mnt/d 9p rw,noatime,aname=drvfs;path=D:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=0x5,access=client,msize=65536,trans=fd,rfd=6,wfd=6 0 0`, "/mnt/d", "9p-aname-drvfs"},
		{"mounts fstype drvfs", `C:\134 /mnt/c drvfs rw,noatime,uid=1000,gid=1000 0 0`, "/mnt/c", "drvfs-fstype"},
		{"mountinfo fstype drvfs", `52 28 0:49 / /mnt/c rw,noatime - drvfs C:\134 rw,uid=1000`, "/mnt/c", "drvfs-fstype"},
		{"9p aname drvfs as the last option", `C:\134 /mnt/c 9p rw,aname=drvfs 0 0`, "/mnt/c", "9p-aname-drvfs"},
		{"custom automount root", `E:\134 /windir/e 9p rw,aname=drvfs;path=E:\ 0 0`, "/windir/e", "9p-aname-drvfs"},
		{"virtiofs with a drive source (not grounded)", `C:\134 /mnt/c virtiofs rw,noatime 0 0`, "/mnt/c", "windows-drive-source"},
		{"9p with a UNC source", `\134\134server\134share /mnt/z 9p rw,trans=fd 0 0`, "/mnt/z", "windows-drive-source"},
		{"9p driver store is not a user drive (grounded)", `drivers /usr/lib/wsl/drivers 9p ro,nosuid,nodev,noatime,aname=drivers;fmask=222;dmask=222,cache=0x5,access=client,msize=65536,trans=fd,rfd=8,wfd=8 0 0`, "/usr/lib/wsl/drivers", ""},
		{"mountinfo 9p driver store", `82 85 0:36 / /usr/lib/wsl/drivers ro,nosuid,nodev,noatime - 9p drivers ro,aname=drivers;fmask=222;dmask=222,cache=0x5`, "/usr/lib/wsl/drivers", ""},
		{"9p aname that only starts with drvfs", `x /mnt/x 9p rw,aname=drvfsx;path=X:\ 0 0`, "/mnt/x", ""},
		{"9p share with a plain tag", `hostshare /mnt/share 9p rw,trans=virtio 0 0`, "/mnt/share", ""},
		{"virtiofs share with a plain tag", `shared /srv/shared virtiofs rw,relatime 0 0`, "/srv/shared", ""},
		{"linux ext4 under /mnt (mounts)", `/dev/sdb1 /mnt/data ext4 rw,relatime 0 0`, "/mnt/data", ""},
		{"linux ext4 under /mnt (mountinfo)", `91 85 8:17 / /mnt/data rw,relatime shared:9 - ext4 /dev/sdb1 rw`, "/mnt/data", ""},
		{"wsl tmpfs (grounded)", `81 85 0:34 / /mnt/wsl rw,relatime shared:1 - tmpfs none rw`, "/mnt/wsl", ""},
		{"wslg tmpfs (grounded)", `86 85 0:40 / /mnt/wslg rw,relatime shared:2 - tmpfs none rw`, "/mnt/wslg", ""},
		{"overlay (grounded)", `113 85 0:42 / /usr/lib/wsl/lib rw,nosuid,nodev,noatime - overlay none rw,lowerdir=/gpu_lib_packaged:/gpu_lib_inbox`, "/usr/lib/wsl/lib", ""},
		{"octal-escaped space in the mount point", `D:\134 /mnt/my\040drive 9p rw,aname=drvfs;path=D:\ 0 0`, "/mnt/my drive", "9p-aname-drvfs"},
		{"octal-escaped space in a mountinfo mount point", `7 1 0:5 / /mnt/my\040drive rw - 9p D:\134 rw,aname=drvfs;path=D:\`, "/mnt/my drive", "9p-aname-drvfs"},
		{"several optional fields before the separator", `36 35 98:0 / /mnt/c rw,noatime master:1 shared:7 propagate_from:3 - 9p C:\134 rw,aname=drvfs`, "/mnt/c", "9p-aname-drvfs"},
		{"mountinfo with no super options", `36 35 98:0 / /mnt/c rw - drvfs C:\134`, "/mnt/c", "drvfs-fstype"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mounts, unparsed := ParseMountTable([]byte(tc.line + "\n"))
			if len(unparsed) != 0 || len(mounts) != 1 {
				t.Fatalf("parsed %d mounts, unparsed %q", len(mounts), unparsed)
			}
			if mounts[0].Point != tc.wantPoint {
				t.Errorf("mount point %q, want %q", mounts[0].Point, tc.wantPoint)
			}
			rule, ok := mounts[0].ForeignDrive()
			if ok != (tc.wantRule != "") || rule != tc.wantRule {
				t.Errorf("rule %q (foreign=%v), want %q", rule, ok, tc.wantRule)
			}
		})
	}
}

// TestParseMountTableDecodes pins the field decoding: the source's escaped
// backslash and the mount point's escaped space.
func TestParseMountTableDecodes(t *testing.T) {
	t.Parallel()
	mounts, _ := ParseMountTable([]byte(`135 85 0:70 / /mnt/a\040b rw - 9p C:\134 rw,aname=drvfs;path=C:\` + "\n"))
	if len(mounts) != 1 {
		t.Fatalf("mounts %v", mounts)
	}
	m := mounts[0]
	if m.Point != "/mnt/a b" || m.Source != `C:\` || m.FSType != "9p" || m.Options != `rw,rw,aname=drvfs;path=C:\` {
		t.Errorf("mount %+v", m)
	}
	// A backslash not followed by three octal digits is kept as written.
	for in, want := range map[string]string{
		`a\134b`: `a\b`, `a\040b`: "a b", `a\0b`: `a\0b`, `a\89b`: `a\89b`, `a\`: `a\`, `plain`: "plain", `\011`: "\t", `\377`: "\xff",
	} {
		if got := unescapeMountField(in); got != want {
			t.Errorf("unescape(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestForeignDriveRoots is the mask set a whole table yields.
func TestForeignDriveRoots(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		table   string
		extra   []string
		want    []string
		wantErr string
	}{
		{"grounded mountinfo", groundedMountinfo, nil, []string{"/mnt/c", "/mnt/d"}, ""},
		{"grounded mounts", groundedMounts, nil, []string{"/mnt/c", "/mnt/d"}, ""},
		{"CRLF line ends", strings.ReplaceAll(groundedMounts, "\n", "\r\n"), nil, []string{"/mnt/c", "/mnt/d"}, ""},
		{"no foreign drive: nothing to mask", "85 69 8:48 / / rw - ext4 /dev/sdd rw\n81 85 0:34 / /mnt/wsl rw - tmpfs none rw\n91 85 8:17 / /mnt/data rw - ext4 /dev/sdb1 rw\n", nil, nil, ""},
		{"a home-derived root is united and sorted", groundedMountinfo, []string{"/mnt/e", "/mnt/c"}, []string{"/mnt/c", "/mnt/d", "/mnt/e"}, ""},
		{"home-derived roots alone", "85 69 8:48 / / rw - ext4 /dev/sdd rw\n", []string{"/mnt/c"}, []string{"/mnt/c"}, ""},
		{"a mount inside another is dropped", "1 0 0:1 / /mnt/c rw - 9p C:\\134 rw,aname=drvfs\n2 1 0:2 / /mnt/c/Users/me/Win rw - 9p C:\\134 rw,aname=drvfs\n", nil, []string{"/mnt/c"}, ""},
		{"a sibling with a shared prefix is kept", "1 0 0:1 / /mnt/c rw - 9p C:\\134 rw,aname=drvfs\n2 1 0:2 / /mnt/cd rw - 9p D:\\134 rw,aname=drvfs\n", nil, []string{"/mnt/c", "/mnt/cd"}, ""},
		{"a drive outside /mnt", "1 0 0:1 / /windir/c rw - 9p C:\\134 rw,aname=drvfs\n", nil, []string{"/windir/c"}, ""},
		{"a bind of a drive subdirectory", "1 0 0:1 /Users/me /home/me/winhome rw - 9p C:\\134 rw,aname=drvfs\n", nil, []string{"/home/me/winhome"}, ""},
		{"an unparseable line that names no drive is skipped", groundedMounts + "this is not a mount line\n", nil, []string{"/mnt/c", "/mnt/d"}, ""},
		{"blank lines are skipped", "\n\n" + groundedMounts + "\n   \n", nil, []string{"/mnt/c", "/mnt/d"}, ""},
		{"empty table fails closed", "", nil, nil, "lists no mount"},
		{"only blank lines fails closed", "\n  \n", nil, nil, "lists no mount"},
		{"only garbage fails closed", "garbage\nmore garbage\n", nil, nil, "lists no mount"},
		{"an unreadable line that names drvfs fails closed", groundedMounts + "C:\\134 relative drvfs rw 0 0\n", nil, nil, "names drvfs but cannot be read"},
		{"a truncated drvfs line fails closed", groundedMounts + "broken drvfs line\n", nil, nil, "names drvfs but cannot be read"},
		{"a drive mounted at the root fails closed", "1 0 0:1 / / rw - 9p C:\\134 rw,aname=drvfs\n", nil, nil, "cannot be masked"},
		{"a drive whose mount point has a space fails closed", "1 0 0:1 / /mnt/my\\040drive rw - 9p D:\\134 rw,aname=drvfs\n", nil, nil, "cannot be masked"},
		{"a drive whose mount point has a newline fails closed", "1 0 0:1 / /mnt/a\\012b rw - 9p D:\\134 rw,aname=drvfs\n", nil, nil, "cannot be masked"},
		{"a drive whose mount point starts a path segment with a dash is fine", "1 0 0:1 / /mnt/-d rw - 9p D:\\134 rw,aname=drvfs\n", nil, []string{"/mnt/-d"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ForeignDriveRoots([]byte(tc.table), tc.extra)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %v, want one containing %q (roots %v)", err, tc.wantErr, got)
				}
				if got != nil {
					t.Errorf("an error came with roots %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("roots %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBuildMaskRoots pins the one place the mask set takes its order.
func TestBuildMaskRoots(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		lists [][]string
		want  []string
	}{
		{"none", nil, nil},
		{"sorted", [][]string{{"/mnt/d", "/mnt/c"}}, []string{"/mnt/c", "/mnt/d"}},
		{"deduplicated across lists", [][]string{{"/mnt/c"}, {"/mnt/c/", "/mnt/d"}}, []string{"/mnt/c", "/mnt/d"}},
		{"cleaned", [][]string{{"/mnt//c/./"}}, []string{"/mnt/c"}},
		{"relative and empty entries dropped", [][]string{{"", " ", "mnt/c", "./x"}}, nil},
		{"the root is never a mask", [][]string{{"/", "/mnt/c"}}, []string{"/mnt/c"}},
		{"nested dropped whichever comes first", [][]string{{"/mnt/c/Users", "/mnt/c"}}, []string{"/mnt/c"}},
		{"shared prefix is not nesting", [][]string{{"/mnt/c", "/mnt/cd", "/mnt/c-x"}}, []string{"/mnt/c", "/mnt/c-x", "/mnt/cd"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := BuildMaskRoots(tc.lists...); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("BuildMaskRoots = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestForeignDriveRulesAreNamed keeps every rule row addressable: a unique,
// non-empty id, so an error or a test row can name it.
func TestForeignDriveRulesAreNamed(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, r := range foreignDriveRules {
		if r.ID == "" || r.Match == nil || seen[r.ID] {
			t.Errorf("rule %+v has no id, no matcher or a duplicate id", r)
		}
		seen[r.ID] = true
	}
}
