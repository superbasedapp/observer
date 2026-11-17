//go:build !sbo_omit_isolation && !sbo_omit_terminals_sandbox && !sbo_omit_terminals

package main

import (
	"errors"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// foreign_mount_masks_test.go pins the foreign-OS drive masks every sandbox
// backend takes from the host mount table (ledger SBX-BE-24): the table is
// read through readHostMountTable, so each test feeds a recorded table
// instead of the real /proc.

// wslMountinfo is /proc/self/mountinfo lines of a WSL2 host with a C: and a D:
// drive (copied from the grounding host, 2026-11-15) and no AI-tool home on
// either: the shape the old home-derived mask set missed.
const wslMountinfo = `85 69 8:48 / / rw,relatime - ext4 /dev/sdd rw,discard,errors=remount-ro,data=ordered
81 85 0:34 / /mnt/wsl rw,relatime shared:1 - tmpfs none rw
82 85 0:36 / /usr/lib/wsl/drivers ro,nosuid,nodev,noatime - 9p drivers ro,aname=drivers;fmask=222;dmask=222,cache=0x5,access=client,msize=65536,trans=fd,rfd=8,wfd=8
135 85 0:70 / /mnt/c rw,noatime - 9p C:\134 rw,aname=drvfs;path=C:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=0x5,access=client,msize=65536,trans=fd,rfd=6,wfd=6
136 85 0:71 / /mnt/d rw,noatime - 9p D:\134 rw,aname=drvfs;path=D:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=0x5,access=client,msize=65536,trans=fd,rfd=6,wfd=6
`

// plainLinuxMountinfo has no Windows drive.
const plainLinuxMountinfo = `85 69 8:48 / / rw,relatime - ext4 /dev/sdd rw
91 85 8:17 / /mnt/data rw,relatime shared:9 - ext4 /dev/sdb1 rw
`

// withHostMountTable replaces the mount-table reader for one test. A test
// that uses it must not run in parallel.
func withHostMountTable(t *testing.T, table string, err error) {
	t.Helper()
	old := readHostMountTable
	readHostMountTable = func() ([]byte, error) { return []byte(table), err }
	t.Cleanup(func() { readHostMountTable = old })
}

// TestForeignMountRootsFromTheMountTable is the defect's regression: with a
// scratch HOME (so crossmount detects no foreign AI-tool home at all) every
// Windows drive in the mount table is still a mask root, including a data
// drive no tool lives on.
func TestForeignMountRootsFromTheMountTable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the mount table is read on Linux hosts only")
	}
	setTestHome(t, t.TempDir()) // crossmount detects nothing under a scratch HOME

	tests := []struct {
		name    string
		table   string
		err     error
		want    []string
		wantErr string
	}{
		{"both drives, no AI-tool home on either", wslMountinfo, nil, []string{"/mnt/c", "/mnt/d"}, ""},
		{"no Windows drive: no mask, argv unchanged", plainLinuxMountinfo, nil, nil, ""},
		{"the table cannot be read: fails closed", "", errors.New("open /proc/self/mountinfo: permission denied"), nil, "launch is refused"},
		{"an empty table: fails closed", "", nil, nil, "launch is refused"},
		{"a drvfs line it cannot read: fails closed", plainLinuxMountinfo + "C:\\134 nowhere drvfs rw 0 0\n", nil, nil, "launch is refused"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withHostMountTable(t, tc.table, tc.err)
			got, err := foreignMountRoots()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %v, want one containing %q (roots %v)", err, tc.wantErr, got)
				}
				if len(got) != 0 {
					t.Errorf("a failed read came with roots %v: it must not return a partial mask list", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("roots %v, want %v", got, tc.want)
			}
		})
	}
}

// TestForeignMountRootsOffLinuxReadsNoTable: a host that is not Linux has no
// /proc mount table and no bwrap box, so none is read and no error arises.
func TestForeignMountRootsOffLinuxReadsNoTable(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("a Linux host reads the table")
	}
	old := readHostMountTable
	t.Cleanup(func() { readHostMountTable = old })
	readHostMountTable = func() ([]byte, error) {
		t.Error("the mount table was read on a host that is not Linux")
		return nil, errors.New("not expected")
	}
	if _, err := foreignMountRoots(); err != nil {
		t.Fatalf("foreignMountRoots: %v", err)
	}
}

// TestMaskPathsUnionTheMountTableAndTheConfig: the runtime's mask set is the
// detected drives followed by the operator's mask_paths, de-duplicated, and a
// table that cannot be read fails the whole set.
func TestMaskPathsUnionTheMountTableAndTheConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the mount table is read on Linux hosts only")
	}
	setTestHome(t, t.TempDir())
	r := &sandboxRuntime{}
	r.cfg.MaskPaths = []string{"/srv/secrets", " ", "/mnt/c", "/srv/secrets"}

	withHostMountTable(t, wslMountinfo, nil)
	got, err := r.maskPaths()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/mnt/c", "/mnt/d", "/srv/secrets"}; !reflect.DeepEqual(got, want) {
		t.Errorf("maskPaths = %v, want %v", got, want)
	}

	withHostMountTable(t, "", errors.New("boom"))
	if got, err := r.maskPaths(); err == nil || got != nil {
		t.Errorf("an unreadable mount table gave %v, %v; want an error and no masks", got, err)
	}
}

// TestIsolationHostFactsFailsClosedOnAnUnreadableMountTable: the one-shot
// isolation path refuses the run (an error that is not ErrNoBwrap, so a
// consumer never falls back to an unisolated run) rather than carry no
// foreign-drive mask.
func TestIsolationHostFactsFailsClosedOnAnUnreadableMountTable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the mount table is read on Linux hosts only")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not on PATH")
	}
	setTestHome(t, t.TempDir())

	withHostMountTable(t, wslMountinfo, nil)
	host, err := isolationHostFacts(t.TempDir(), []string{"/srv/x"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/mnt/c", "/mnt/d", "/srv/x"}; !reflect.DeepEqual(host.MaskPaths, want) {
		t.Errorf("MaskPaths = %v, want %v", host.MaskPaths, want)
	}

	withHostMountTable(t, "", errors.New("boom"))
	_, err = isolationHostFacts(t.TempDir(), nil)
	if err == nil || isolationMissingOnHost(err) {
		t.Fatalf("error %v: want a refusal that is not 'no bwrap'", err)
	}
}
