package aider

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

func writeTranscript(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, historyFileName)
	if err := os.WriteFile(p, []byte("# aider chat started at 2026-10-20 10:00:00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func withKnownRoots(t *testing.T, roots func() []string) {
	t.Helper()
	SetProjectRootSource(roots)
	t.Cleanup(func() { SetProjectRootSource(nil) })
}

func withNoHomes(t *testing.T) {
	t.Helper()
	orig := allHomesFunc
	allHomesFunc = func() []crossmount.HomeRoot { return nil }
	t.Cleanup(func() { allHomesFunc = orig })
}

// TestDiscoverRootsProbesKnownProjectRoots pins T-924: a repo outside the
// home folder (C:\programsx\regulation on the operator's laptop) is never
// reached by the home walk, but its transcript is found through the
// project roots Observer already knows. A known root without a
// transcript, and one whose transcript is a symlink, add nothing.
func TestDiscoverRootsProbesKnownProjectRoots(t *testing.T) {
	t.Setenv("AIDER_CHAT_HISTORY_FILE", "")
	withNoHomes(t)
	outside := t.TempDir()
	repo := filepath.Join(outside, "programsx", "regulation")
	want := writeTranscript(t, repo)
	bare := filepath.Join(outside, "programsx", "no-aider")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(outside, "programsx", "linked")
	if err := os.MkdirAll(linked, 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkOK := runtime.GOOS != "windows"
	if symlinkOK {
		if err := os.Symlink(want, filepath.Join(linked, historyFileName)); err != nil {
			symlinkOK = false
		}
	}
	withKnownRoots(t, func() []string { return []string{repo, bare, linked, "", repo} })

	got := discoverRoots()
	if !slices.Equal(got, []string{want}) {
		t.Fatalf("discoverRoots = %v, want [%s] (symlink checked: %v)", got, want, symlinkOK)
	}
	a := &Adapter{scrubber: scrub.New(), disc: &discovery{
		walk: discoverRoots, now: time.Now, spawn: func(func()) {}, interval: time.Hour,
	}}
	if !a.IsSessionFile(want) {
		t.Error("transcript under a known project root is not a session file")
	}
}

// TestKnownRootProbeIsBounded: a pass stats at most MaxKnownRoots roots,
// so a large project table never turns discovery into a crawl.
func TestKnownRootProbeIsBounded(t *testing.T) {
	t.Setenv("AIDER_CHAT_HISTORY_FILE", "")
	withNoHomes(t)
	base := t.TempDir()
	roots := make([]string, 0, MaxKnownRoots+3)
	for i := 0; i < MaxKnownRoots+3; i++ {
		roots = append(roots, filepath.Join(base, fmt.Sprintf("r%03d", i)))
	}
	late := writeTranscript(t, roots[MaxKnownRoots+1])
	first := writeTranscript(t, roots[0])
	withKnownRoots(t, func() []string { return roots })

	got := discoverRoots()
	if !slices.Contains(got, first) {
		t.Errorf("transcript at the first known root missing: %v", got)
	}
	if slices.Contains(got, late) {
		t.Errorf("root beyond MaxKnownRoots was probed: %v", got)
	}
}

// TestKnownRootsJoinBackgroundRediscovery: a project root that gains its
// first aider transcript after start is picked up by the next refresh,
// with the source consulted on every pass, not cached once.
func TestKnownRootsJoinBackgroundRediscovery(t *testing.T) {
	t.Setenv("AIDER_CHAT_HISTORY_FILE", "")
	withNoHomes(t)
	repo := filepath.Join(t.TempDir(), "elsewhere", "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	calls := 0
	withKnownRoots(t, func() []string { calls++; return []string{repo} })

	clock := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	var pending []func()
	d := &discovery{
		walk:     discoverRoots,
		now:      func() time.Time { return clock },
		spawn:    func(f func()) { pending = append(pending, f) },
		interval: rediscoverInterval,
	}
	a := &Adapter{scrubber: scrub.New(), disc: d}
	if got := a.WatchPaths(); len(got) != 0 {
		t.Fatalf("startup roots = %v, want none", got)
	}
	want := writeTranscript(t, repo)
	clock = clock.Add(rediscoverInterval)
	_ = a.WatchPaths()
	if len(pending) != 1 {
		t.Fatalf("background walks = %d, want 1", len(pending))
	}
	pending[0]()
	if got := a.WatchPaths(); !slices.Equal(got, []string{want}) {
		t.Fatalf("after refresh roots = %v, want [%s]", got, want)
	}
	if calls != 2 {
		t.Errorf("project-root source consulted %d times, want once per pass (2)", calls)
	}
}

// TestKnownRootsInForeignSpelling: a root stored in the other OS's
// spelling is translated before the probe (a WSL daemon sees a Windows
// project as C:\..., which it must stat as /mnt/c/...). The translation
// itself is crossmount's; this pins that discovery applies it.
func TestKnownRootsInForeignSpelling(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the WSL spelling of a Windows path is exercised on the Linux side")
	}
	t.Setenv("AIDER_CHAT_HISTORY_FILE", "")
	withNoHomes(t)
	repo := t.TempDir()
	want := writeTranscript(t, repo)
	// A file:// URI is one of the foreign spellings TranslateForeignPath
	// normalizes on every host, so it stands in for C:\... here without
	// needing a real /mnt/c.
	withKnownRoots(t, func() []string { return []string{"file://" + repo} })
	if got := discoverRoots(); !slices.Equal(got, []string{want}) {
		t.Fatalf("discoverRoots = %v, want [%s]", got, want)
	}
}
