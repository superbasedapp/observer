package workspace

import (
	"strings"
	"testing"
)

func testReturnReq() ReturnRequest {
	return ReturnRequest{SourceRepo: "/home/dev/src/app", CopyDir: "/home/dev/.observer/workspaces/RUN1/app", ManagedRoot: "/home/dev/.observer/workspaces", RunID: "RUN1"}
}

func TestPlanReturnSteps(t *testing.T) {
	p, err := PlanReturn(testReturnReq())
	if err != nil {
		t.Fatal(err)
	}
	if p.Ref != "refs/observer/sandbox/RUN1" {
		t.Fatalf("ref %q", p.Ref)
	}
	sha := strings.Repeat("a", 40)
	for name, st := range map[string]Step{
		"head": p.HeadOfCopy(), "exists": p.Exists(sha), "fetch": p.Fetch(sha), "paths": p.ListPaths(sha), "ref": p.CreateRef(sha), "verify": p.VerifyRef(),
	} {
		got := strings.Join(st.Argv, " ")
		// Every step runs in the SOURCE repository, never in the copy,
		// with hooks off and objects checked.
		if !strings.HasPrefix(got, "git -C /home/dev/src/app -c core.hooksPath=/dev/null") || !strings.Contains(got, "transfer.fsckObjects=true") {
			t.Errorf("%s: %s", name, got)
		}
	}
	fetch := strings.Join(p.WithGitVersion(GitVersion{Major: 2, Minor: 29, Known: true}).Fetch(sha).Argv, " ")
	for _, want := range []string{"--no-tags", "--no-recurse-submodules", "--no-write-fetch-head", "--no-auto-maintenance", "fetch.fsckObjects=true"} {
		if !strings.Contains(fetch, want) {
			t.Errorf("fetch lacks %s: %s", want, fetch)
		}
	}
	ref := p.CreateRef(sha).Argv
	if ref[len(ref)-1] != "" || ref[len(ref)-2] != sha || ref[len(ref)-3] != p.Ref {
		t.Fatalf("the ref is not written create-only (empty old value): %q", ref)
	}
}

func TestPlanReturnRefuses(t *testing.T) {
	for name, edit := range map[string]func(r *ReturnRequest){
		"copy outside the managed root": func(r *ReturnRequest) { r.CopyDir = "/home/dev/elsewhere" },
		"relative source":               func(r *ReturnRequest) { r.SourceRepo = "app" },
		"source is managed":             func(r *ReturnRequest) { r.SourceRepo = "/home/dev/.observer/workspaces/OTHER/app" },
		"bad run id":                    func(r *ReturnRequest) { r.RunID = "../x" },
		"ref injection":                 func(r *ReturnRequest) { r.RunID = "a b" },
	} {
		r := testReturnReq()
		edit(&r)
		if _, err := PlanReturn(r); err == nil {
			t.Errorf("%s: planned", name)
		}
	}
}

func TestParseHead(t *testing.T) {
	sha := strings.Repeat("b", 40)
	if got, err := ParseHead([]byte(sha + "\tHEAD\n" + strings.Repeat("d", 40) + "\trefs/remotes/origin/HEAD\n")); err != nil || got != sha {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"", "x\tHEAD", sha + "\trefs/heads/main", sha + "\tHEAD\n" + sha + "\tHEAD", "--upload-pack=x\tHEAD"} {
		if _, err := ParseHead([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if !ValidSHA(strings.Repeat("c", 64)) || ValidSHA("abc") {
		t.Fatal("sha shape")
	}
}

func TestCheckReturnedPaths(t *testing.T) {
	ok := "src/main.go\x00README.md\x00docs/a b.md\x00"
	if err := CheckReturnedPaths([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"/etc/passwd", "../x", "a/../b", "a/.git/hooks/pre-commit", ".GIT/config", "a/git~1/x", "a/.git./x", "bad\x01name", "a//b", strings.Repeat("x", maxReturnPathLen+1)} {
		if err := CheckReturnedPaths([]byte(bad)); err == nil {
			t.Errorf("%q passed", bad)
		}
	}
	if err := CheckReturnSize(MaxReturnBytes + 1); err == nil {
		t.Fatal("size cap")
	}
}

func TestDeliveryFor(t *testing.T) {
	oci := []Delivery{DeliveryBindSamePath}
	disk := []Delivery{DeliveryDiskImage}
	cases := []struct {
		src   Source
		modes []Delivery
		want  Delivery
		ok    bool
	}{
		{SourceLive, oci, DeliveryBindSamePath, true},
		{SourceLive, disk, "", false},
		{SourceLive, []Delivery{DeliveryVirtiofs}, DeliveryVirtiofs, true},
		{SourceCloneLocal, oci, DeliveryBindSamePath, true},
		{SourceCloneLocal, disk, DeliveryDiskImage, true},
		{SourceCloneRemote, []Delivery{DeliveryRemoteClone}, DeliveryRemoteClone, true},
		{SourceWorktree, disk, "", false},
		{SourceWorktree, oci, DeliveryBindSamePath, true},
		{SourceWorktree, []Delivery{DeliveryVirtiofs}, "", false},
		{"bogus", oci, "", false},
	}
	for _, c := range cases {
		got, err := DeliveryFor(c.src, c.modes)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("%s on %v: %q %v", c.src, c.modes, got, err)
		}
	}
	if ReturnsWork(SourceLive) || ReturnsWork(SourceWorktree) || !ReturnsWork(SourceCloneLocal) || !ReturnsWork(SourceCloneRemote) {
		t.Fatal("returns work")
	}
}

// TestCheckReturnedTree (SBX-P3A merge finding F10): every entry's path is
// checked, a gitlink is refused, symlinks are returned for their targets to
// be checked, and a malformed entry is refused.
func TestCheckReturnedTree(t *testing.T) {
	blob := strings.Repeat("a", 40)
	entry := func(mode, typ, obj, p string) string { return mode + " " + typ + " " + obj + "\t" + p + "\x00" }
	ok := entry("100644", "blob", blob, "a.txt") + entry("120000", "blob", blob, "dir/link") + entry("100755", "blob", blob, "run.sh")
	links, err := CheckReturnedTree([]byte(ok))
	if err != nil || len(links) != 1 || links[0].Path != "dir/link" || links[0].Object != blob {
		t.Fatalf("links %+v err %v", links, err)
	}
	for name, raw := range map[string]string{
		"gitlink":         ok + entry("160000", "commit", blob, "vendor/sub"),
		"bad path":        entry("100644", "blob", blob, "../x"),
		"git dir path":    entry("100644", "blob", blob, "a/.git/config"),
		"malformed":       "100644 blob\tnope\x00",
		"bad link object": entry("120000", "blob", "zz", "l"),
	} {
		if _, err := CheckReturnedTree([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestCheckSymlinkTarget: a target is accepted only when, resolved from the
// link's own directory, it stays inside the returned tree and out of .git.
func TestCheckSymlinkTarget(t *testing.T) {
	for _, c := range []struct {
		link, target string
		ok           bool
	}{
		{"a/link", "b.txt", true},
		{"a/link", "../b.txt", true},
		{"a/b/link", "../../c", true},
		{"link", "../x", false},
		{"a/link", "../../x", false},
		{"link", "/etc/passwd", false},
		{"link", "C:/Windows", false},
		{"link", "\\\\server\\share", false},
		{"link", "a/../../x", false},
		{"link", ".git/hooks/pre-commit", false},
		{"a/link", "../.GIT/config", false},
		{"link", "", false},
		{"link", "x\ny", false},
		{"link", strings.Repeat("a", 5000), false},
	} {
		err := CheckSymlinkTarget(c.link, []byte(c.target))
		if (err == nil) != c.ok {
			t.Errorf("%s -> %q: err %v, want ok=%v", c.link, c.target, err, c.ok)
		}
	}
}

// TestReturnFetchFollowsTheGitVersion: git older than 2.29 rejects
// --no-write-fetch-head and --no-auto-maintenance (exit 129), so the fetch
// passes them only from 2.29; an older or unknown git keeps every check
// (fsck, no hooks, gc.auto=0, maintenance.auto=false, no tags, no
// submodules, no destination ref) and leaves FETCH_HEAD to the cmd layer.
func TestReturnFetchFollowsTheGitVersion(t *testing.T) {
	p, err := PlanReturn(testReturnReq())
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 40)
	always := []string{"--no-tags", "--no-recurse-submodules", "transfer.fsckObjects=true", "fetch.fsckObjects=true", "gc.auto=0", "maintenance.auto=false", "core.hooksPath=/dev/null"}
	for _, c := range []struct {
		name      string
		out       string
		modern    bool
		fetchHead bool
		autoGC    bool
	}{
		{"2.25 (this project's WSL host)", "git version 2.25.1\n", false, true, true},
		{"2.28", "git version 2.28.0", false, true, true},
		{"2.29", "git version 2.29.0", true, false, true},
		{"windows build", "git version 2.39.2.windows.1", true, false, true},
		{"apple build", "git version 2.37.1 (Apple Git-137.1)", true, false, true},
		{"3.0", "git version 3.0.0", true, false, true},
		{"2.20", "git version 2.20.1", false, true, false},
		{"unparsed", "not git", false, true, false},
		{"empty", "", false, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			plan := p.WithGitVersion(ParseGitVersion([]byte(c.out)))
			argv := plan.Fetch(sha).Argv
			got := strings.Join(argv, " ")
			for _, want := range always {
				if !strings.Contains(got, want) {
					t.Errorf("fetch lacks %s: %s", want, got)
				}
			}
			for _, flag := range []string{"--no-write-fetch-head", "--no-auto-maintenance"} {
				if strings.Contains(got, flag) != c.modern {
					t.Errorf("%s present = %v, want %v: %s", flag, !c.modern, c.modern, got)
				}
			}
			if strings.Contains(got, "--no-auto-gc") != c.autoGC {
				t.Errorf("--no-auto-gc present = %v, want %v: %s", !c.autoGC, c.autoGC, got)
			}
			if plan.FetchWritesFetchHead() != c.fetchHead {
				t.Errorf("FetchWritesFetchHead = %v, want %v", plan.FetchWritesFetchHead(), c.fetchHead)
			}
			// The commit is fetched by name with no destination ref on every
			// git: the last two words are the copy and the sha.
			if argv[len(argv)-2] != testReturnReq().CopyDir || argv[len(argv)-1] != sha {
				t.Errorf("fetch names a destination: %q", argv)
			}
		})
	}
	if got := strings.Join(p.VersionStep().Argv, " "); !strings.HasSuffix(got, " version") || !strings.Contains(got, "core.hooksPath=/dev/null") {
		t.Errorf("version step %s", got)
	}
	if got := strings.Join(p.FetchHeadPath().Argv, " "); !strings.HasSuffix(got, " rev-parse --git-path FETCH_HEAD") {
		t.Errorf("FETCH_HEAD step %s", got)
	}
}

// TestCheckSymlinkChains is RB1 sweep finding S1: two links that each look
// inside on their own escape together, because the kernel resolves ".."
// after following the first link. A legitimate chain (latest -> v2,
// cur -> latest/bin) still passes.
func TestCheckSymlinkChains(t *testing.T) {
	deep := strings.Repeat("a/", 20) + "d"
	cases := []struct {
		name    string
		targets map[string]string
		bad     bool
	}{
		{"plain relative link", map[string]string{"docs/readme": "../README.md"}, false},
		{"chain inside", map[string]string{"latest": "v2", "cur": "latest/bin"}, false},
		{"chain through a dir link", map[string]string{"lib": "src/lib", "x/y": "../lib/z.go"}, false},
		{"escape through a deep link", map[string]string{
			deep:  strings.Repeat("../", 20),
			"esc": deep + "/" + strings.Repeat("../", 21) + "home/u/.ssh/id_rsa",
		}, true},
		{"into .git through a link", map[string]string{"g": ".", "x": "g/.git/config"}, true},
		{"loop", map[string]string{"a": "b", "b": "a"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for p, tg := range tc.targets {
				if err := CheckSymlinkTarget(p, []byte(tg)); err != nil && !tc.bad {
					t.Fatalf("CheckSymlinkTarget(%q, %q) = %v", p, tg, err)
				}
			}
			err := CheckSymlinkChains(tc.targets)
			if (err != nil) != tc.bad {
				t.Fatalf("CheckSymlinkChains = %v, want bad=%v", err, tc.bad)
			}
		})
	}
	// The escape case passes the per-link check: only the chain check sees it.
	if err := CheckSymlinkTarget(deep, []byte(strings.Repeat("../", 20))); err != nil {
		t.Fatalf("per-link check refused the first link: %v", err)
	}
	if err := CheckSymlinkTarget("esc", []byte(deep+"/"+strings.Repeat("../", 21)+"home/u/.ssh/id_rsa")); err != nil {
		t.Fatalf("per-link check refused the second link: %v", err)
	}
}
