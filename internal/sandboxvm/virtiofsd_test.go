package sandboxvm

import (
	"strings"
	"testing"
)

func TestVirtiofsdArgv(t *testing.T) {
	a, err := VirtiofsdArgv("/usr/libexec/virtiofsd", "/s/fs.sock", "/home/u/ws")
	if err != nil || strings.Join(a, " ") != "/usr/libexec/virtiofsd --socket-path=/s/fs.sock --shared-dir=/home/u/ws --sandbox=none --cache=auto" {
		t.Fatalf("%v %v", a, err)
	}
}

// TestConfinedVirtiofsdArgv: only the two fixed programs; pins parents
// first, read-only paths after them; nothing outside the share.
func TestConfinedVirtiofsdArgv(t *testing.T) {
	c := ConfinedShare{
		Bwrap: ConfinedBwrap, Virtiofsd: ConfinedVirtiofsd, Socket: "/s/r/fs-ws.sock", Dir: "/home/u/ws",
		Pins: []string{"/home/u/ws/.git/info", "/home/u/ws/.git"}, ReadOnlyPaths: []string{"/home/u/ws/.git/info/attributes", "/home/u/ws/.git/config"},
	}
	a, err := ConfinedVirtiofsdArgv(c)
	if err != nil {
		t.Fatal(err)
	}
	j := strings.Join(a, " ")
	gitPin := strings.Index(j, "--bind /home/u/ws/.git /home/u/ws/.git")
	infoPin := strings.Index(j, "--bind /home/u/ws/.git/info ")
	roCfg := strings.Index(j, "--ro-bind /home/u/ws/.git/config")
	if gitPin < 0 || infoPin < gitPin || roCfg < infoPin || !strings.Contains(j, "--ro-bind / /") || !strings.Contains(j, "--unshare-user") {
		t.Fatalf("argv %s", j)
	}
	bad := c
	bad.Bwrap = "/tmp/bwrap"
	if _, err := ConfinedVirtiofsdArgv(bad); err == nil {
		t.Fatal("another bwrap was accepted")
	}
	bad = c
	bad.Pins = []string{"/etc"}
	if _, err := ConfinedVirtiofsdArgv(bad); err == nil {
		t.Fatal("a pin outside the share was accepted")
	}
}

// TestConfinedReadBack: a pin that is not a mount point or a read-only path
// that is writable refuses the live share.
func TestConfinedReadBack(t *testing.T) {
	c := ConfinedShare{Dir: "/home/u/ws", Pins: []string{"/home/u/ws/.git"}, ReadOnlyPaths: []string{"/home/u/ws/.git/config"}}
	m, ro := ConfinedExpectations(c)
	if len(m) != 3 || len(ro) != 1 {
		t.Fatalf("%v %v", m, ro)
	}
	if v := ConfinedReadBack(c, nil); !v.OK() {
		t.Fatal(v)
	}
	if v := ConfinedReadBack(c, []string{"/home/u/ws/.git is not mounted in the box"}); v.Code != VerdictSourceUnsupported || !strings.Contains(v.Reason, ".git is not mounted") {
		t.Fatalf("%+v", v)
	}
}

// TestConfinedReadBackAfterBoot: the same judge after boot ends the run
// with built_below_plan, never source_unsupported.
func TestConfinedReadBackAfterBoot(t *testing.T) {
	c := ConfinedShare{Dir: "/home/u/ws", Pins: []string{"/home/u/ws/.git"}, ReadOnlyPaths: []string{"/home/u/ws/.git/config"}}
	if v := ConfinedReadBackAfterBoot(c, nil); !v.OK() {
		t.Fatal(v)
	}
	v := ConfinedReadBackAfterBoot(c, []string{"/home/u/ws/.git/config is writable in the box, the plan made it read-only"})
	if v.Code != VerdictBuiltBelowPlan || !strings.Contains(v.Reason, "after boot") || !strings.Contains(v.Reason, ".git/config is writable") {
		t.Fatalf("%+v", v)
	}
}

// TestVirtiofsdCacheLetsTheGuestExec (live run 2026-10-24, D1): no share's
// virtiofsd runs --cache=never, under which the guest cannot execute a
// program from the share (EFAULT); the plain and the confined forms both run
// the proven mode, and the confined form keeps its read-only binds and pins.
func TestVirtiofsdCacheLetsTheGuestExec(t *testing.T) {
	plain, err := VirtiofsdArgv("/usr/libexec/virtiofsd", "/s/fs.sock", "/home/u/ws")
	if err != nil {
		t.Fatal(err)
	}
	confined, err := ConfinedVirtiofsdArgv(ConfinedShare{
		Bwrap: ConfinedBwrap, Virtiofsd: ConfinedVirtiofsd, Socket: "/s/r/fs-ws.sock", Dir: "/home/u/ws",
		Pins: []string{"/home/u/ws/.git"}, ReadOnlyPaths: []string{"/home/u/ws/.git/config"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, argv := range map[string][]string{"plain": plain, "confined": confined} {
		j := " " + strings.Join(argv, " ") + " "
		if strings.Contains(j, "--cache=never") || !strings.Contains(j, " --cache=auto ") || strings.Count(j, "--cache=") != 1 {
			t.Errorf("%s: %s", name, j)
		}
	}
	if j := strings.Join(confined, " "); !strings.Contains(j, "--ro-bind /home/u/ws/.git/config /home/u/ws/.git/config") || !strings.Contains(j, "--bind /home/u/ws/.git /home/u/ws/.git") {
		t.Fatalf("the confined form lost a bind: %s", j)
	}
}
