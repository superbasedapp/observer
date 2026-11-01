package sandboxvm

import (
	"strings"
	"testing"
)

func TestDiskImageSize(t *testing.T) {
	for in, want := range map[int64]int64{0: diskHeadroom, 1: diskHeadroom + 1<<20, 100 << 20: 456 << 20} {
		got, err := DiskImageSize(in)
		if err != nil || got != want {
			t.Errorf("%d: %d %v, want %d", in, got, err, want)
		}
	}
	if _, err := DiskImageSize(DiskMax); err == nil {
		t.Fatal("an oversized workspace was accepted")
	}
}

func TestMkfsAndDumpArgv(t *testing.T) {
	a, err := MkfsArgv("/usr/sbin/mkfs.ext4", "/home/u/ws", "/s/r/ws.img", 256<<20, 1000, 1000)
	if err != nil || strings.Join(a, " ") != "/usr/sbin/mkfs.ext4 -q -F -t ext4 -d /home/u/ws -E root_owner=1000:1000 -L ws -m 0 /s/r/ws.img 256M" {
		t.Fatalf("%v %v", a, err)
	}
	if _, err := MkfsArgv("mkfs.ext4", "/a", "/b", 256<<20, 1, 1); err == nil {
		t.Fatal("a relative program was accepted")
	}
	d, err := DumpArgv("/usr/sbin/debugfs", "/s/r/ws.img", "/home/u/ws")
	if err != nil || strings.Join(d, "|") != "/usr/sbin/debugfs|-R|rdump / /home/u/ws|/s/r/ws.img" {
		t.Fatalf("%v %v", d, err)
	}
}

// TestMappingTable is one case per row.
func TestMappingTable(t *testing.T) {
	for _, r := range mappingTable {
		got := Mapping(r.Source, r.Delivery)
		if got != r || got.Why == "" {
			t.Errorf("%s/%s: %+v", r.Source, r.Delivery, got)
		}
	}
	if !Mapping(SourceCloneLocal, "").OK {
		t.Fatal("the default delivery is not virtiofs")
	}
	if Mapping("nfs", DeliveryVirtiofs).OK {
		t.Fatal("an unknown source mapped")
	}
}

// TestConfinedDumpArgv (SBX-BE-5): debugfs over a guest-written image runs
// inside bwrap with the host root read-only, every namespace unshared, a
// new session, death with its parent, and the fresh target the only
// writable bind.
func TestConfinedDumpArgv(t *testing.T) {
	a, err := ConfinedDumpArgv("/usr/bin/bwrap", "/usr/sbin/debugfs", "/s/r/ws.img", "/home/u/ws.vm-return")
	if err != nil {
		t.Fatal(err)
	}
	want := "/usr/bin/bwrap|--ro-bind|/|/|--dev|/dev|--proc|/proc|--bind|/home/u/ws.vm-return|/home/u/ws.vm-return|--unshare-all|--die-with-parent|--new-session|--|/usr/sbin/debugfs|-R|rdump / /home/u/ws.vm-return|/s/r/ws.img"
	if got := strings.Join(a, "|"); got != want {
		t.Fatalf("argv\n got %s\nwant %s", got, want)
	}
	binds := 0
	for i, s := range a {
		if s == "--bind" || s == "--bind-try" || s == "--dev-bind" {
			binds++
			if a[i+1] != "/home/u/ws.vm-return" {
				t.Fatalf("a writable bind other than the target: %v", a)
			}
		}
	}
	if binds != 1 {
		t.Fatalf("%d writable binds", binds)
	}
	for _, bad := range [][4]string{
		{"bwrap", "/usr/sbin/debugfs", "/s/ws.img", "/d"},
		{"/usr/bin/bwrap", "/usr/sbin/debugfs", "/d/ws.img", "/d"},
		{"/usr/bin/bwrap", "/usr/sbin/debugfs", "/s/ws.img", "/"},
	} {
		if _, err := ConfinedDumpArgv(bad[0], bad[1], bad[2], bad[3]); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
