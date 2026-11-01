package sandboxwslc

import (
	"strings"
	"testing"
)

// syntheticHelp is a SYNTHETIC help text naming the required flags; no
// real wslc help is recorded yet (WIN-5).
const syntheticHelp = "Usage: wslc run [OPTIONS] IMAGE [COMMAND]\n  --name string\n  --network string\n  --volume list\n  --interactive\n  --tty\n"

const img = "docker.io/library/ubuntu@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func good() Facts {
	return Facts{Windows: true, Active: true, Build: 26200, WSL: true, Path: `C:\Program Files\WSL\wslc.exe`, Version: "1.0.0", Help: syntheticHelp, Image: img}
}

// TestProbeLadder: one case per row; with no recorded version every
// installed wslc is refused (probe-only).
func TestProbeLadder(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		edit func(*Facts)
		code string
	}{
		{"not windows", func(f *Facts) { f.Windows = false }, VerdictUnsupportedPlatform},
		{"inactive", func(f *Facts) { f.Active = false }, VerdictDisabledByConfig},
		{"old build", func(f *Facts) { f.Build = 22631 }, VerdictOSTooOld},
		{"no wsl", func(f *Facts) { f.WSL = false }, VerdictBackendMissing},
		{"no wslc", func(f *Facts) { f.Path = "" }, VerdictBackendMissing},
		{"no image", func(f *Facts) { f.Image = "ubuntu:latest" }, VerdictImageMissing},
		{"a needed flag missing", func(f *Facts) { f.Help = strings.ReplaceAll(syntheticHelp, "--network", "") }, VerdictVersionUntested},
		{"no recorded version", func(*Facts) {}, VerdictVersionUntested},
	}
	for _, c := range cases {
		f := good()
		c.edit(&f)
		if v := Probe(f); v.Code != c.code || v.Reason == "" {
			t.Errorf("%s: %+v, want %s", c.name, v, c.code)
		}
	}
	recordedVersions["1.0.0"] = true
	defer delete(recordedVersions, "1.0.0")
	if v := Probe(good()); !v.OK() {
		t.Fatalf("a recorded version: %+v", v)
	}
}

func TestRunArgv(t *testing.T) {
	t.Parallel()
	p := RunPlan{Path: "wslc", Name: "observer-sbx-run00001", Image: img, Mounts: []Mount{{Host: `C:\w`, Container: "/w"}, {Host: `C:\w\.git\config`, Container: "/w/.git/config", ReadOnly: true}}, Entrypoint: []string{"observer", "claude"}}
	argv, err := RunArgv(p, Flags(syntheticHelp))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(argv, " ")
	want := `wslc run --name observer-sbx-run00001 --network none --interactive --tty --volume C:\w:/w --volume C:\w\.git\config:/w/.git/config:ro ` + img + " observer claude"
	if got != want {
		t.Fatalf("argv\n%s\nwant\n%s", got, want)
	}
	if _, err := RunArgv(p, Flags("--name --volume")); err == nil || !strings.Contains(err.Error(), "--network") {
		t.Fatalf("a version without --network: %v", err)
	}
	bad := p
	bad.Name = "other"
	if _, err := RunArgv(bad, Flags(syntheticHelp)); err == nil {
		t.Fatal("a foreign name was planned")
	}
	if a, err := ExecRelayArgv("wslc", "observer-sbx-run00001", []string{"observer", "sandbox-guest"}); err != nil || a[1] != "exec" {
		t.Fatalf("exec argv %v %v", a, err)
	}
}

// TestTeardownListsBeforeAndAfter: the run's container and dead leftovers
// of this prefix are removed; a container that is still there after is a
// leftover; another tool's containers are never touched.
func TestTeardownListsBeforeAndAfter(t *testing.T) {
	t.Parallel()
	before, err := ParseList([]byte(`[{"Name":"observer-sbx-run00001"},{"name":"observer-sbx-dead0002"},{"Name":"observer-sbx-live0003"},{"Name":"someone-else"}]`))
	if err != nil {
		t.Fatal(err)
	}
	p := PlanTeardown(before, "observer-sbx-run00001", func(n string) bool { return n == "observer-sbx-live0003" })
	if strings.Join(p.Remove, ",") != "observer-sbx-dead0002,observer-sbx-run00001" {
		t.Fatalf("remove = %v", p.Remove)
	}
	if left := Leftovers([]string{"observer-sbx-live0003", "someone-else"}, p); len(left) != 0 {
		t.Fatalf("leftovers %v", left)
	}
	if left := Leftovers([]string{"observer-sbx-run00001"}, p); len(left) != 1 {
		t.Fatal("a container still listed after teardown is not reported")
	}
	if _, err := ParseList([]byte("not json")); err == nil {
		t.Fatal("garbage list accepted")
	}
	if strings.Join(ListArgv("wslc"), " ") != "wslc list --format json" || RemoveArgv("wslc", "x")[1] != "rm" {
		t.Fatal("list or remove argv")
	}
}
