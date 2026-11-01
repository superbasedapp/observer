package aider

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// withOptions installs process-wide discovery options for one test.
func withOptions(t *testing.T, o DiscoveryOptions) {
	t.Helper()
	optsMu.Lock()
	prev := opts
	opts = o
	optsMu.Unlock()
	t.Cleanup(func() {
		optsMu.Lock()
		opts = prev
		optsMu.Unlock()
	})
}

func plantTranscript(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func withHome(t *testing.T, home string) {
	t.Helper()
	orig := allHomesFunc
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{{Path: home, OS: crossmount.OSLinux, Origin: "native"}}
	}
	t.Cleanup(func() { allHomesFunc = orig })
}

// TestBackgroundDiscoveryDoesNotBlockTheCaller pins D-MU1: in background
// mode (the daemon) the first WatchPaths call returns at once even while the
// walk is blocked (a home folder waiting on a macOS privacy prompt), and the
// walk's result is served once it finishes.
func TestBackgroundDiscoveryDoesNotBlockTheCaller(t *testing.T) {
	release := make(chan struct{})
	walked := make(chan struct{})
	d := &discovery{
		walk: func() []string {
			<-release
			defer close(walked)
			return []string{"/repo/" + historyFileName}
		},
		now:        time.Now,
		spawn:      func(f func()) { go f() },
		interval:   time.Hour,
		background: true,
	}
	a := &Adapter{scrubber: scrub.New(), disc: d}

	done := make(chan []string, 1)
	go func() { done <- a.WatchPaths() }()
	select {
	case got := <-done:
		if len(got) != 0 {
			t.Fatalf("first call = %v, want empty while the walk runs", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WatchPaths waited on a blocked walk")
	}
	// A second call while the walk is still blocked starts no second walk
	// and still does not wait.
	if got := a.WatchPaths(); len(got) != 0 {
		t.Fatalf("second call = %v", got)
	}
	close(release)
	<-walked
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := a.WatchPaths(); slices.Equal(got, []string{"/repo/" + historyFileName}) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("walk result never served: %v", a.WatchPaths())
}

// TestConfigureDiscoveryBackgroundOnShared pins that ConfigureDiscovery is
// what switches the shared discovery into background mode.
func TestConfigureDiscoveryBackgroundOnShared(t *testing.T) {
	prev := discoveryOptions()
	t.Cleanup(func() { ConfigureDiscovery(prev) })
	ConfigureDiscovery(DiscoveryOptions{Background: true, HomeWalk: true, Active: true})
	sharedDiscovery.mu.Lock()
	on := sharedDiscovery.background
	sharedDiscovery.mu.Unlock()
	if !on {
		t.Fatal("ConfigureDiscovery(Background) did not reach the shared discovery")
	}
}

// TestDarwinWalkSkipsProtectedHomeFolders pins the D-MU1 skip table: on
// darwin the walk never opens Desktop/Documents/Downloads (and the other
// guarded folders) unless a known project root lives in one.
func TestDarwinWalkSkipsProtectedHomeFolders(t *testing.T) {
	home := t.TempDir()
	plain := filepath.Join(home, "code", "repo", historyFileName)
	desk := filepath.Join(home, "Desktop", "repo", historyFileName)
	docs := filepath.Join(home, "Documents", "proj", historyFileName)
	for _, p := range []string{plain, desk, docs} {
		plantTranscript(t, p)
	}
	withHome(t, home)
	orig := goosFunc
	goosFunc = func() string { return "darwin" }
	t.Cleanup(func() { goosFunc = orig })

	withOptions(t, DiscoveryOptions{HomeWalk: true, Active: true})
	SetProjectRootSource(nil)
	got := discoverRoots()
	if !slices.Equal(got, []string{plain}) {
		t.Fatalf("darwin roots = %v, want only %s", got, plain)
	}

	// A known project root under Documents makes Documents walkable (and
	// is probed directly); Desktop stays skipped.
	SetProjectRootSource(func() []string { return []string{filepath.Join(home, "Documents", "other")} })
	t.Cleanup(func() { SetProjectRootSource(nil) })
	got = discoverRoots()
	if !slices.Contains(got, docs) || slices.Contains(got, desk) {
		t.Fatalf("with a known root under Documents roots = %v, want %s and not %s", got, docs, desk)
	}

	// Linux has no guarded folders: everything is walked.
	goosFunc = func() string { return "linux" }
	SetProjectRootSource(nil)
	got = discoverRoots()
	for _, want := range []string{plain, desk, docs} {
		if !slices.Contains(got, want) {
			t.Errorf("linux roots = %v, missing %s", got, want)
		}
	}
}

// TestDiscoveryOffSwitches pins the home-walk off switch and the inactive
// adapter: neither walks the home, and an inactive adapter does not even
// probe known roots.
func TestDiscoveryOffSwitches(t *testing.T) {
	home := t.TempDir()
	walked := filepath.Join(home, "code", "repo", historyFileName)
	knownRepo := filepath.Join(home, "known")
	known := filepath.Join(knownRepo, historyFileName)
	plantTranscript(t, walked)
	plantTranscript(t, known)
	withHome(t, home)
	calls := 0
	SetProjectRootSource(func() []string { calls++; return []string{knownRepo} })
	t.Cleanup(func() { SetProjectRootSource(nil) })
	t.Setenv("AIDER_CHAT_HISTORY_FILE", "")

	withOptions(t, DiscoveryOptions{HomeWalk: false, Active: true})
	if got := discoverRoots(); !slices.Equal(got, []string{known}) {
		t.Fatalf("home_walk=false roots = %v, want only the known root %s", got, known)
	}
	withOptions(t, DiscoveryOptions{HomeWalk: true, Active: false})
	calls = 0
	if got := discoverRoots(); len(got) != 0 {
		t.Fatalf("inactive adapter roots = %v, want none", got)
	}
	if calls != 0 {
		t.Errorf("inactive adapter read the known-root source %d times", calls)
	}
}

// TestWalkStopsOnCancel pins the shutdown cancel: a cancelled context ends
// the walk before it opens anything.
func TestWalkStopsOnCancel(t *testing.T) {
	home := t.TempDir()
	plantTranscript(t, filepath.Join(home, "repo", historyFileName))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	found, visited := walkHome(ctx, home, 1000, nil)
	if len(found) != 0 || visited != 0 {
		t.Fatalf("cancelled walk found %v after %d dirs", found, visited)
	}
}
