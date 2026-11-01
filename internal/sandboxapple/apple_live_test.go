package sandboxapple

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// apple_live_test.go pins the shapes Apple container 1.6.0 printed on a
// bare-metal Mac (macOS 26.7.1, 2026-10-23 and 2026-10-24; the *_live
// fixtures, anonymized): the image list and container snapshot shapes the
// probe and the read-back must read (D-A1, D-A2), the guest's own mount
// table that the in-guest check judges (D-A3), and the run options the
// probe's flag row looks for (D-A4 and the low items).

// liveRunHelp is `container run --help` of 1.6.0.
var liveRunHelp = func() string {
	b, err := os.ReadFile(filepath.Join("testdata", "run_help_live.txt"))
	if err != nil {
		panic(err)
	}
	return string(b)
}()

const liveImageDigest = "sha256:4ed900b414a0a1d63dbf1936dd6ae3cf5202547d1deba1f35acc658a75c4b66e"

// TestLiveImages160 (D-A1): the 1.6.0 image list keeps the name and digest
// under "configuration"; the probe finds the image by its digest, whatever
// registry prefix the CLI printed, and still reads the older shape.
func TestLiveImages160(t *testing.T) {
	b := readFixture(t, "images_live.json")
	for _, ref := range []string{
		"docker.io/example/agent@" + liveImageDigest,
		"example/agent@" + liveImageDigest,
		"docker.io/library/debian@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8",
	} {
		if ok, err := ImagePresent(b, ref); err != nil || !ok {
			t.Errorf("%s: present=%v err=%v", ref, ok, err)
		}
	}
	if ok, _ := ImagePresent(b, "docker.io/example/agent@sha256:"+strings.Repeat("c", 64)); ok {
		t.Error("an absent digest matched")
	}
	// The variant (per-platform) digest is not the image's own.
	if ok, _ := ImagePresent(b, "x@sha256:2f8ce93af88f1bd3f0560e997e4c306c22a43f9fc84153334ac023a72a9890a0"); ok {
		t.Error("a variant digest matched")
	}
	if ok, err := ImagePresent(readFixture(t, "images.json"), "ghcr.io/example/agent@sha256:"+testDigest); err != nil || !ok {
		t.Fatalf("the older shape: %v %v", ok, err)
	}
}

// TestLiveListAndSweep160 (D-A2): the 1.6.0 status is an object; the list
// parses, carries the labels and networks, and the sweep picks out the run
// that is gone (MAC-17: a SIGKILLed `--rm` CLI leaves its container
// running).
func TestLiveListAndSweep160(t *testing.T) {
	list, err := ParseList(readFixture(t, "ls_live.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("%d containers", len(list))
	}
	none, web := list[0], list[1]
	if none.Status != "running" || none.Labels[LabelInstall] != "a1b2c3d4e5f60718" || len(none.Networks) != 0 || none.CPUs != 4 || none.MemoryBytes != 4<<30 {
		t.Fatalf("the --network none container %+v", none)
	}
	if web.Status != "running" || !slices.Equal(web.Networks, []string{"default"}) {
		t.Fatalf("the default-network container %+v", web)
	}
	got := Orphans(list, "a1b2c3d4e5f60718", func(run string) bool { return run == "RunLive_0123456789abcd" })
	if !slices.Equal(got, []string{"observer-a1b2c3d4e5f60718-2222222222222222"}) {
		t.Fatalf("orphans %v", got)
	}
	// An object status of no known shape is refused, never guessed.
	for _, bad := range []string{
		`[{"status":{"phase":"up"},"configuration":{"id":"x"}}]`,
		`[{"status":7,"configuration":{"id":"x"}}]`,
	} {
		if _, err := ParseList([]byte(bad)); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
	if l, err := ParseList([]byte(`[{"configuration":{"id":"x"}}]`)); err != nil || l[0].Status != "" {
		t.Errorf("an absent status: %+v %v", l, err)
	}
}

// liveInspectPlan is the plan the live t1 container was run with (the
// driver's mount shape before the D-A3 fix, read back by inspect).
func liveInspectPlan() RunPlan {
	ws := "/Users/dev/src/app"
	return RunPlan{
		CLI: "/usr/local/bin/container", RunID: "RunLive_0123456789abcd", InstallID: "a1b2c3d4e5f60718",
		Name:  ContainerName("a1b2c3d4e5f60718", "RunLive_0123456789abcd"),
		Image: "example/agent@" + liveImageDigest, MemoryMiB: 4096, CPUs: 4, WorkDir: ws,
		Mounts: []Mount{
			{Source: ws, Target: ws},
			{Source: ws + "/.git", Target: ws + "/.git"},
			{Source: ws + "/.git/config", Target: ws + "/.git/config", ReadOnly: true},
			{Source: ws + "/.git/hooks", Target: ws + "/.git/hooks", ReadOnly: true},
			{Source: "/private/var/folders/xy/abc/T/obsbx/RunLive_0123456789abcd", Target: GuestSocketDir, ReadOnly: true},
		},
		Command: []string{GuestObserverPath, InitVerb},
	}
}

// TestLiveInspectReadBack160 (D-A2): the live inspect reads back and is
// judged on what it says (it no longer refuses for a shape it cannot
// parse); the image matches by digest across the printed registry prefix;
// the default-network container is refused for its network.
func TestLiveInspectReadBack160(t *testing.T) {
	plan := liveInspectPlan()
	clock := func() ReadBackClock {
		now := time.Unix(1_800_000_000, 0)
		return ReadBackClock{Now: func() time.Time { return now }, Sleep: func(d time.Duration) { now = now.Add(d) }}
	}
	good := readFixture(t, "inspect_live.json")
	if v := AwaitReadBack(func() ([]byte, error) { return good, nil }, plan, ReadBackWindow, clock()); !v.OK() {
		t.Fatalf("the live container as planned: %+v", v)
	}
	net := readFixture(t, "inspect_live_net.json")
	v := AwaitReadBack(func() ([]byte, error) { return net, nil }, plan, ReadBackWindow, clock())
	if v.Code != VerdictBuiltBelowPlan || !strings.Contains(v.Reason, "network default") || strings.Contains(v.Reason, "did not parse") {
		t.Fatalf("the default-network container: %+v", v)
	}
	// A read-only path or published socket the plan asked for and inspect
	// does not list is a refusal; one it lists but the plan did not ask for
	// is one too.
	asked := plan
	asked.ReadOnlyPaths = []string{"/Users/dev/src/app/.git/commondir"}
	asked.PublishSockets = []PublishSocket{{Host: "/private/var/folders/xy/abc/T/obsbx/r/mux.sock", Guest: GuestTunnelPath}}
	v = AwaitReadBack(func() ([]byte, error) { return good, nil }, asked, ReadBackWindow, clock())
	for _, want := range []string{"read-only path /Users/dev/src/app/.git/commondir is missing", "published socket " + GuestTunnelPath + " is missing"} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("reason lacks %q: %s", want, v.Reason)
		}
	}
	list, _ := ParseList(good)
	c := list[0]
	c.PublishedSockets = []PublishSocket{{Host: "/tmp/x.sock", Guest: "/run/y.sock"}}
	if v := ReadBack(c, plan); v.OK() || !strings.Contains(v.Reason, "publishes /run/y.sock") {
		t.Fatalf("an unplanned published socket: %+v", v)
	}
	// The two 1.6.0 configuration keys the fixes add (as inspect printed
	// them on 2026-10-24 for a run with --read-only-path and
	// --publish-socket).
	withKeys, err := ParseList([]byte(`[{"configuration":{"id":"x","readonlyPaths":["/proc/sys","/w/.git/config"],"publishedSockets":[{"containerPath":"/run/obsx/t.sock","hostPath":"/private/var/folders/xy/abc/T/s/t.sock"}]},"status":{"state":"running","networks":[]}}]`))
	if err != nil || !slices.Equal(withKeys[0].ReadOnlyPaths, []string{"/proc/sys", "/w/.git/config"}) ||
		len(withKeys[0].PublishedSockets) != 1 || withKeys[0].PublishedSockets[0].Guest != "/run/obsx/t.sock" {
		t.Fatalf("readonlyPaths and publishedSockets: %+v %v", withKeys, err)
	}
}

// TestGuestCheckLive (D-A3): the guest's own mount table under the fixed
// shape (the .git pin as a mount, the protected paths as --read-only-path)
// passes; the table 1.6.0 gave for the old shape (pin plus a file mount
// under it: the .git mount is gone) is refused, which inspect could not see.
func TestGuestCheckLive(t *testing.T) {
	ws := "/Users/dev/src/app"
	mounts := []string{ws, ws + "/.git"}
	ro := []string{ws + "/.git/config", ws + "/.git/hooks", ws + "/.git/commondir"}
	good, err := ParseMountInfo(readFixture(t, "mountinfo_live.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if v := CheckGuestMounts(good, mounts, ro); !v.OK() {
		t.Fatalf("the fixed shape: %+v", v)
	}
	dropped, err := ParseMountInfo(readFixture(t, "mountinfo_live_da3.txt"))
	if err != nil {
		t.Fatal(err)
	}
	v := CheckGuestMounts(dropped, mounts, []string{ws + "/.git/config"})
	if v.Code != VerdictBuiltBelowPlan || !strings.Contains(v.Reason, ws+"/.git is not mounted in the box") || !strings.Contains(v.Reason, "the agent was not started") {
		t.Fatalf("the dropped pin: %+v", v)
	}
	// A planned read-only path that is writable, one that is missing, and
	// one covered by a later mount on its parent are each refused.
	table := append(append([]MountEntry(nil), good...), MountEntry{Point: ws + "/.git/info/attributes"})
	if v := CheckGuestMounts(table, mounts, append(ro, ws+"/.git/info/attributes", ws+"/.git/objects/info/alternates")); !strings.Contains(v.Reason, "attributes is writable") || !strings.Contains(v.Reason, "alternates is not mounted") {
		t.Fatalf("writable and missing: %+v", v)
	}
	covered := append(append([]MountEntry(nil), good...), MountEntry{Point: ws + "/.git"})
	if v := CheckGuestMounts(covered, mounts, ro); !strings.Contains(v.Reason, "covered by a later mount on "+ws+"/.git") {
		t.Fatalf("covered: %+v", v)
	}
}

func TestParseMountInfo(t *testing.T) {
	tab, err := ParseMountInfo([]byte("36 35 98:0 / /a\\040b ro,relatime shared:1 - ext4 /dev/x rw\n\n37 36 0:1 / /c rw - tmpfs t rw\n"))
	if err != nil || len(tab) != 2 || tab[0].Point != "/a b" || !tab[0].ReadOnly || tab[1].ReadOnly {
		t.Fatalf("%+v %v", tab, err)
	}
	for _, bad := range []string{"not a line\n", "1 2 3 4 relative rw - x y z\n", "1 2 3 / /a\\04 rw - x y z\n"} {
		if _, err := ParseMountInfo([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// TestRunArgv160: the argv carries the 1.6.0 options the fixes use:
// --progress none, an explicit --entrypoint, the read-only paths and the
// published tunnel; a read-only path outside every mount, or a published
// guest socket under a mount, is refused.
func TestRunArgv160(t *testing.T) {
	p := testPlan()
	p.ReadOnlyPaths = []string{"/Users/dev/src/app/.git/config", "/Users/dev/src/app/.git/commondir"}
	p.PublishSockets = []PublishSocket{{Host: "/private/var/folders/xy/abc/T/obsbx/RunLive_0123456789abcd/mux.sock", Guest: GuestTunnelPath}}
	argv, err := RunArgv(p)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"--progress none", "--entrypoint " + GuestObserverPath,
		"--read-only-path /Users/dev/src/app/.git/config --read-only-path /Users/dev/src/app/.git/commondir",
		"--publish-socket /private/var/folders/xy/abc/T/obsbx/RunLive_0123456789abcd/mux.sock:" + GuestTunnelPath,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv lacks %q:\n%s", want, joined)
		}
	}
	img := slices.Index(argv, p.Image)
	if img < 0 || argv[img+1] != InitVerb || slices.Index(argv, "--entrypoint") > img {
		t.Fatalf("the entrypoint and its arguments around the image: %q", argv)
	}
	for name, mut := range map[string]func(*RunPlan){
		"ro outside the mounts": func(p *RunPlan) { p.ReadOnlyPaths = []string{"/etc/passwd"} },
		"ro twice":              func(p *RunPlan) { p.ReadOnlyPaths = []string{"/Users/dev/src/app/a", "/Users/dev/src/app/a"} },
		"ro on a mount target":  func(p *RunPlan) { p.ReadOnlyPaths = []string{"/Users/dev/src/app"} },
		"tunnel under a mount": func(p *RunPlan) {
			p.PublishSockets = []PublishSocket{{Host: "/tmp/h.sock", Guest: "/Users/dev/src/app/t.sock"}}
		},
		"relative tunnel":     func(p *RunPlan) { p.PublishSockets = []PublishSocket{{Host: "h.sock", Guest: GuestTunnelPath}} },
		"relative entrypoint": func(p *RunPlan) { p.Command = []string{"observer", "x"} },
	} {
		q := testPlan()
		mut(&q)
		if _, err := RunArgv(q); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	mounts, ro := ExpectedGuestMounts(p)
	if !slices.Equal(mounts, []string{"/Users/dev/src/app", "/Users/dev/.claude"}) || !slices.Equal(ro, []string{GuestSocketDir, "/Users/dev/src/app/.git/config", "/Users/dev/src/app/.git/commondir"}) {
		t.Fatalf("the in-guest check %q %q", mounts, ro)
	}
	if err := CheckArgv(RunHelpArgv("/usr/local/bin/container")); err != nil {
		t.Fatalf("run --help: %v", err)
	}
}

// TestProbeRunFlags: the 1.6.0 help passes row A6b; a CLI without
// --publish-socket (the relay's only transport) or --read-only-path is
// refused at the probe by name, never launched without capture.
func TestProbeRunFlags(t *testing.T) {
	if r := Probe(healthy()); !r.Verdict.OK() {
		t.Fatalf("1.6.0 help: %+v", r.Verdict)
	}
	for _, flag := range []string{"--publish-socket", "--read-only-path", "--entrypoint", "--progress"} {
		env := healthy()
		env.RunHelp = func(string) (string, error) {
			return strings.ReplaceAll(liveRunHelp, flag+" ", "--x-gone ") + "\n" + flag + "-other <x>\n", nil
		}
		r := Probe(env)
		if r.Verdict.Code != VerdictVersionUntested || r.Rule != "A6b run flags" || !strings.Contains(r.Verdict.Reason, flag) {
			t.Errorf("without %s: %s at %s (%s)", flag, r.Verdict.Code, r.Rule, r.Verdict.Reason)
		}
	}
	env := healthy()
	env.RunHelp = func(string) (string, error) { return "", errors.New("exit 64") }
	if r := Probe(env); r.Rule != "A6b run flags" || r.Verdict.OK() {
		t.Fatalf("help unreadable: %+v", r)
	}
}

func TestMergeEnv(t *testing.T) {
	got := MergeEnv([]string{"PATH=/usr/bin", "HOME=/root", RelaySecretEnv + "=s"}, []string{"HOME=/Users/dev", "ANTHROPIC_BASE_URL=http://127.0.0.1:8820", RelaySecretEnv + "=t"}, []string{RelaySecretEnv})
	if !slices.Equal(got, []string{"PATH=/usr/bin", "HOME=/Users/dev", "ANTHROPIC_BASE_URL=http://127.0.0.1:8820"}) {
		t.Fatalf("%q", got)
	}
}

// TestTestedWindow160 (item 6): the tested window is the release checked
// live through Observer on the Mac, 1.6.0 to 1.6.99; the 0.x releases the
// reconstructed reference described and anything past 1.6 run as beta.
func TestTestedWindow160(t *testing.T) {
	if DocLow != "1.6.0" || DocHigh != "1.6.99" {
		t.Fatalf("tested window %s to %s, want 1.6.0 to 1.6.99", DocLow, DocHigh)
	}
	for v, beta := range map[string]bool{"1.6.0": false, "1.6.3": false, "0.5.0": true, "0.6.1": true, "1.5.9": true, "1.7.0": true, "2.0.0": true} {
		env := healthy()
		env.Version = func(string) (string, error) { return "container CLI version " + v, nil }
		r := Probe(env)
		if !r.Verdict.OK() || r.Beta != beta {
			t.Errorf("%s: verdict %s beta %v, want available beta %v", v, r.Verdict.Code, r.Beta, beta)
		}
	}
}
