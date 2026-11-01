package sandboxsbpl

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// resolve_test.go covers F1, F3 and F8 of the SBX-P5 merge: every path the
// profile names is resolved (Seatbelt matches resolved paths), Build refuses
// one that is not, a protected path that resolves elsewhere is denied at its
// target too, the shared temp roots are hidden, and POSIX shared memory is
// narrowed. The resolver here is a table of links (cmd/observer tests the
// same with real symlinks).

// linkResolver resolves p through links (written prefix -> target), the
// longest prefix first, repeatedly.
func linkResolver(links map[string]string) func(string) string {
	return func(p string) string {
		p = filepath.Clean(p)
		for i := 0; i < 40; i++ {
			best := ""
			for from := range links {
				if (p == from || strings.HasPrefix(p, from+"/")) && len(from) > len(best) {
					best = from
				}
			}
			if best == "" {
				return p
			}
			p = filepath.Join(links[best], strings.TrimPrefix(p, best))
		}
		return ""
	}
}

// TestBuildRefusesUnresolvedPaths: a spelling Seatbelt never matches is a
// named refusal, for a grant and for a protected path whose target is not
// protected.
func TestBuildRefusesUnresolvedPaths(t *testing.T) {
	res := linkResolver(map[string]string{"/tmp": "/private/tmp", "/Users/dev/src/app/.git": "/Users/dev/src/app/realgit"})
	cases := []struct {
		name string
		mut  func(*Request)
	}{
		{"workspace under /tmp", func(r *Request) { r.WorkspaceRoot = "/tmp/x" }},
		{"extra bind under /tmp", func(r *Request) { r.ExtraRO = []string{"/tmp/x"} }},
		{"temp root /tmp", func(r *Request) { r.TempRoots = []string{"/tmp"} }},
		{"protected path through a linked .git", func(r *Request) {}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := baseRequest(sandbox.EgressInternet)
			r.Resolve = res
			c.mut(&r)
			_, err := Build(r)
			var ue *UnresolvedPathError
			if err == nil || !errors.As(err, &ue) || !strings.Contains(err.Error(), ReasonUnresolvedPath) {
				t.Fatalf("Build = %v, want the %s refusal", err, ReasonUnresolvedPath)
			}
		})
	}
}

// TestCanonicalizeTmpIsPrivateTmp: /tmp/x becomes /private/tmp/x and the
// profile grants the resolved path, so the box can write where it runs.
func TestCanonicalizeTmpIsPrivateTmp(t *testing.T) {
	res := linkResolver(map[string]string{"/tmp": "/private/tmp"})
	r := baseRequest(sandbox.EgressInternet)
	r.WorkspaceRoot = "/tmp/x"
	r.Overlays = nil
	r.TempRoots = []string{"/private/var/folders/xy/abc/T", "/tmp"}
	got, err := Canonicalize(r, res)
	if err != nil {
		t.Fatal(err)
	}
	if got.WorkspaceRoot != "/private/tmp/x" || got.TempRoots[1] != "/private/tmp" {
		t.Fatalf("canonical %q %q", got.WorkspaceRoot, got.TempRoots)
	}
	rules, params := built(t, got)
	runMatrix(t, rules, params, []access{
		{"the resolved workspace writes", file("file-write-data", "/private/tmp/x/a.txt"), true},
		{"the rest of /private/tmp stays hidden", file("file-read-data", "/private/tmp/other/a.txt"), false},
	})
}

// TestCanonicalizeLinkedGitKeepsHooksReadOnly: a workspace .git that links
// to a directory inside the workspace keeps .git/hooks and .git/config
// unwritable at their target, the link cannot be replaced, and the target
// directory cannot be renamed away.
func TestCanonicalizeLinkedGitKeepsHooksReadOnly(t *testing.T) {
	res := linkResolver(map[string]string{"/Users/dev/src/app/.git": "/Users/dev/src/app/realgit"})
	got, err := Canonicalize(baseRequest(sandbox.EgressInternet), res)
	if err != nil {
		t.Fatal(err)
	}
	rules, params := built(t, got)
	runMatrix(t, rules, params, []access{
		{"hooks target cannot be planted", file("file-write-create", "/Users/dev/src/app/realgit/hooks/pre-commit"), false},
		{"config target does not write", file("file-write-data", "/Users/dev/src/app/realgit/config"), false},
		{"the link cannot be replaced", file("file-write-unlink", "/Users/dev/src/app/.git"), false},
		{"the git dir cannot be renamed", file("file-write-unlink", "/Users/dev/src/app/realgit"), false},
		{"git objects still write", file("file-write-data", "/Users/dev/src/app/realgit/objects/ab/cd"), true},
		{"the workspace still writes", file("file-write-data", "/Users/dev/src/app/main.go"), true},
	})
}

// TestCanonicalizeSymlinkedWorkspaceAndState: a workspace reached through a
// link is granted at its target; a tool state dir that links out of the
// home becomes an absolute bind of the same access; the observer binary is
// granted at its file and its link spelling stays readable.
func TestCanonicalizeSymlinkedWorkspaceAndState(t *testing.T) {
	res := linkResolver(map[string]string{
		"/Users/dev/src/app":         "/Volumes/work/app",
		"/Users/dev/.claude":         "/Volumes/dotfiles/claude",
		"/opt/homebrew/bin/observer": "/opt/homebrew/Cellar/observer/1.40.0/bin/observer",
	})
	r := baseRequest(sandbox.EgressInternet)
	r.Overlays = []sandbox.Overlay{{Path: "/Users/dev/src/app/.git/config", Kind: sandbox.OverlayReadOnly}}
	got, err := Canonicalize(r, res)
	if err != nil {
		t.Fatal(err)
	}
	if got.WorkspaceRoot != "/Volumes/work/app" || got.ObserverBin != "/opt/homebrew/Cellar/observer/1.40.0/bin/observer" || got.ObserverBinLink != "/opt/homebrew/bin/observer" {
		t.Fatalf("canonical %+v", got)
	}
	if len(got.StateRW) != 1 || got.StateRW[0] != ".claude.json" || !strings.Contains(strings.Join(got.ExtraRW, ","), "/Volumes/dotfiles/claude") {
		t.Fatalf("state %q extra rw %q", got.StateRW, got.ExtraRW)
	}
	rules, params := built(t, got)
	runMatrix(t, rules, params, []access{
		{"workspace target writes", file("file-write-data", "/Volumes/work/app/main.go"), true},
		{"workspace git config at its target does not write", file("file-write-data", "/Volumes/work/app/.git/config"), false},
		{"state target writes", file("file-write-data", "/Volumes/dotfiles/claude/settings.json"), true},
		{"observer binary file reads", file("file-read-data", "/opt/homebrew/Cellar/observer/1.40.0/bin/observer"), true},
		{"observer link reads", file("file-read-data", "/opt/homebrew/bin/observer"), true},
	})
	// The unresolved request is refused, not silently weakened.
	r.Resolve = res
	if _, err := Build(r); err == nil {
		t.Fatal("Build accepted the unresolved request")
	}
}

// TestOracleSharedTemp (F3): another run's TMPDIR, the rest of $TMPDIR and
// /private/tmp are neither readable nor writable; the run's own TMPDIR and
// launch record are, and their ancestors keep their metadata.
func TestOracleSharedTemp(t *testing.T) {
	rules, params := built(t, baseRequest(sandbox.EgressInternet))
	T := "/private/var/folders/xy/abc/T"
	runMatrix(t, rules, params, []access{
		{"another run's temp is unreadable", file("file-read-data", T+"/obsbx-tmp/run2/x"), false},
		{"an env file left in temp is unreadable", file("file-read-data", T+"/obsbx-tmp/run2/env"), false},
		{"the rest of $TMPDIR is unreadable", file("file-read-data", T+"/com.apple.foo/state"), false},
		{"/private/tmp is unreadable", file("file-read-data", "/private/tmp/notes.txt"), false},
		{"/private/tmp does not write", file("file-write-data", "/private/tmp/notes.txt"), false},
		{"own temp reads", file("file-read-data", T+"/obsbx-tmp/run1/x"), true},
		{"own temp writes", file("file-write-data", T+"/obsbx-tmp/run1/x"), true},
		{"own launch record reads", file("file-read-data", T+"/obsbx/run1/launch.json"), true},
		{"$TMPDIR keeps its metadata", file("file-read-metadata", T), true},
		{"$TMPDIR cannot be listed", file("file-read-data", T), false},
		{"the temp parent keeps its metadata", file("file-read-metadata", T+"/obsbx-tmp"), true},
		{"the temp parent cannot be listed", file("file-read-data", T+"/obsbx-tmp"), false},
		{"/private/var/tmp still reads (ledger SBX-MAC-2)", file("file-read-data", "/private/var/tmp/x"), true},
	})
}

// TestOracleSharedMemoryNarrowed (F8): only notify(3)'s segment reads;
// nothing is created, written or unlinked.
func TestOracleSharedMemoryNarrowed(t *testing.T) {
	rules, params := built(t, baseRequest(sandbox.EgressNone))
	shm := func(op, name string) Query { return Query{Op: op, IPCName: name} }
	runMatrix(t, rules, params, []access{
		{"notify segment reads", shm("ipc-posix-shm-read-data", NotifyShmName), true},
		{"notify segment metadata", shm("ipc-posix-shm-read-metadata", NotifyShmName), true},
		{"notify segment does not write", shm("ipc-posix-shm-write-data", NotifyShmName), false},
		{"a new segment is not created", shm("ipc-posix-shm-write-create", "psm_123"), false},
		{"another segment does not read", shm("ipc-posix-shm-read-data", "org.chromium.x"), false},
		{"a segment is not unlinked", shm("ipc-posix-shm-write-unlink", NotifyShmName), false},
	})
}
