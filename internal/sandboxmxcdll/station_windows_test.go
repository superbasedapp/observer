//go:build windows

package sandboxmxcdll

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
)

// envJobUIChild makes this test binary, started by a test below, report the
// UI limit class of its own job to the file it names and exit.
const envJobUIChild = "SBO_SANDBOXMXCDLL_JOBUI_CHILD"

// envJobUIGrand makes it report its own job's class only (the grandchild).
const envJobUIGrand = "SBO_SANDBOXMXCDLL_JOBUI_GRAND"

// envJobUIParent names the grandchild's parent (the process that entered the
// job): the grandchild tries to change the job through the parent's handles
// first, the way the WINFIX4 audit measured it (finding 1).
const envJobUIParent = "SBO_SANDBOXMXCDLL_JOBUI_PARENT"

func TestMain(m *testing.M) {
	if out := os.Getenv(envJobUIChild); out != "" {
		// The box's first process: enter the UI-limited job, then start a
		// grandchild, which must read the same limits on its own job.
		entered, _, eerr := EnterUIRestrictedJob(sandboxmxc.JobUIRestrictions)
		grand := ""
		if self, err := os.Executable(); err == nil {
			gout := out + ".grand"
			cmd := exec.Command(self, "-test.run=^$")
			cmd.Env = []string{"SYSTEMROOT=" + os.Getenv("SystemRoot"), envJobUIGrand + "=" + gout, envJobUIParent + "=" + strconv.Itoa(os.Getpid())}
			start := time.Now()
			if err := cmd.Run(); err != nil {
				grand = fmt.Sprintf("not run after %s: %v", time.Since(start).Round(time.Millisecond), err)
			} else {
				b, _ := os.ReadFile(gout)
				grand = string(b)
			}
		}
		class, in, err := OwnJobUIClass()
		_ = os.WriteFile(out, []byte(fmt.Sprintf("entered 0x%X err %v; in-job %v class 0x%X err %v; grandchild %s", entered, eerr, in, class, err, grand)), 0o600)
		os.Exit(0)
	}
	if out := os.Getenv(envJobUIGrand); out != "" {
		tamper := ""
		if pid, err := strconv.ParseUint(os.Getenv(envJobUIParent), 10, 32); err == nil {
			r := tamperProcessJob(uint32(pid))
			tamper = r.String() + "; "
			_ = os.WriteFile(out+".types", []byte(r.TypesText()), 0o600)
		}
		class, in, err := OwnJobUIClass()
		_ = os.WriteFile(out, []byte(fmt.Sprintf("%sin-job %v class 0x%X err %v", tamper, in, class, err)), 0o600)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func testDesktopName() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "observer-test-" + hex.EncodeToString(b)
}

func testStation(t *testing.T) *RunDesktop {
	t.Helper()
	d, err := CreateRunStation(testDesktopName())
	if err != nil {
		t.Fatalf("CreateRunStation: %v", err)
	}
	t.Cleanup(d.Close)
	return d
}

// TestRunStationIsNotTheUsersStation (RERUN2 D2): the run's desktop is on
// the logon session's alternate window station, never WinSta0; the station
// admits the box entry (ALL APPLICATION PACKAGES, StationBoxAccess); the
// desktop carries a protected DACL naming the user and the box entry only,
// narrowed to the box's SID alone; a second desktop of the same name on the
// station is refused; and a process started there runs and returns its exit
// code.
func TestRunStationIsNotTheUsersStation(t *testing.T) {
	name := testDesktopName()
	d, err := CreateRunStation(name)
	if err != nil {
		t.Fatalf("CreateRunStation: %v", err)
	}
	defer d.Close()
	if !strings.HasPrefix(d.Station, "Service-0x") || strings.EqualFold(d.Station, "WinSta0") || d.Path != d.Station+`\`+name {
		t.Fatalf("Station %q Path %q", d.Station, d.Path)
	}
	if _, err := CreateRunStation(name); err == nil {
		t.Fatal("a second desktop of the same name was created on the station")
	}
	if ok, err := d.StationAdmitsBoxes(); err != nil || !ok {
		ws, _ := d.StationSDDL()
		t.Fatalf("the station has no box entry: %s %v", ws, err)
	}
	ds, err := d.SDDL()
	if err != nil || !strings.HasPrefix(ds, "D:P") || strings.Count(ds, "(A;") != 2 || !strings.Contains(strings.ToUpper(ds), ";;;AC)") {
		t.Fatalf("desktop before the box SID: %s %v", ds, err)
	}
	const box = "S-1-15-2-1-2-3-4-5-6-7"
	if err := d.Narrow(box); err != nil {
		t.Fatalf("Narrow: %v", err)
	}
	if ds, _ = d.SDDL(); !strings.Contains(ds, box) || strings.Contains(strings.ToUpper(ds), ";;;AC)") || strings.Count(ds, "(A;") != 2 {
		t.Fatalf("desktop after Narrow: %s", ds)
	}
	cmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	p, err := StartOnDesktop(cmd, []string{"/d", "/c", "exit 3"}, os.TempDir(), []string{"SYSTEMROOT=" + os.Getenv("SystemRoot")}, d.Path, nil, nil, nil)
	if err != nil {
		t.Fatalf("StartOnDesktop on the run's station: %v", err)
	}
	if code, err := p.Wait(); err != nil || code != 3 {
		t.Fatalf("exit = %d, %v; want 3", code, err)
	}
}

// TestJobUILimitsReadBackInsideTheJob (RERUN2 D2, WINFIX3 finding 9): the
// kill-on-close job the helper holds carries every JOB_OBJECT_UILIMIT flag,
// read back by the helper and by a process inside the job. Before, the job
// had none (a box probe read class 0x0).
func TestJobUILimitsReadBackInsideTheJob(t *testing.T) {
	d := testStation(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "jobui.txt")
	env := []string{"SYSTEMROOT=" + os.Getenv("SystemRoot"), envJobUIChild + "=" + out}
	// The child starts in the helper's kill-on-close job (which carries no
	// UI limit: MXC cannot start a box under one), enters the nested
	// UI-limited job the way the box's first Observer process does, and
	// starts a grandchild, which reads the same limits.
	p, err := StartOnDesktop(self, []string{"-test.run=^$"}, t.TempDir(), env, d.Path, nil, nil, nil)
	if err != nil {
		t.Fatalf("StartOnDesktop: %v", err)
	}
	if code, err := p.Wait(); err != nil || code != 0 {
		t.Fatalf("the child: %d %v", code, err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	c := sandboxmxc.JobUIRestrictions
	if want := fmt.Sprintf("entered 0x%X err <nil>; in-job true class 0x%X err <nil>; grandchild tamper opened true, 0 job handle(s), 0 lowered; in-job true class 0x%X err <nil>", c, c, c); string(got) != want {
		t.Fatalf("inside the job: %q, want %q", got, want)
	}
	// What else the job's first process holds that a process of the box can
	// duplicate (finding 1, second part): logged, and no job handle among it.
	types, _ := os.ReadFile(filepath.Join(filepath.Dir(out), "jobui.txt.grand.types"))
	t.Logf("handles a grandchild duplicated from the job's first process, by type: %s", types)
	if strings.Contains(string(types), "Job=") {
		t.Fatalf("the job's first process holds a job handle: %s", types)
	}
}

// TestReleaseStationEntryRemovesOnlyWhatObserverAdded (WINFIX4 audit finding
// 3): when CreateRunStation added the box entry to the alternate station
// (it had none of its own), ReleaseStationEntry removes exactly that entry
// while no other run is live, and keeps it while one is. A station that
// already admitted boxes is never changed.
func TestReleaseStationEntryRemovesOnlyWhatObserverAdded(t *testing.T) {
	d := testStation(t)
	admits, err := d.StationAdmitsBoxes()
	if err != nil {
		t.Fatalf("StationAdmitsBoxes: %v", err)
	}
	if !admits {
		t.Fatal("the run's station does not admit boxes")
	}
	if !d.addedStationEntry {
		// Another program's sandbox already opened this logon session's
		// alternate station to AppContainers; Observer must never remove it.
		d.ReleaseStationEntry(func() bool { return false })
		if a, _ := d.StationAdmitsBoxes(); !a {
			t.Fatal("release removed an entry Observer did not add")
		}
		t.Skip("the alternate station already admitted boxes before this run; nothing for Observer to release")
	}
	// Another run is live: the entry stays.
	d.ReleaseStationEntry(func() bool { return true })
	if a, _ := d.StationAdmitsBoxes(); !a {
		t.Fatal("the box entry was removed while another run is live")
	}
	// No other run: the entry Observer added is removed.
	d.ReleaseStationEntry(func() bool { return false })
	if a, _ := d.StationAdmitsBoxes(); a {
		t.Fatal("the box entry Observer added was not removed at run end")
	}
	// Idempotent and a no-op once removed.
	d.ReleaseStationEntry(func() bool { return false })
}
