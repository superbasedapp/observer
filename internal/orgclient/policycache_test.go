package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// plantLockedDirectory replaces the cache file at path with a read-only
// directory holding one file (D-704, the live test's shape 3).
func plantLockedDirectory(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "keep.txt"), []byte("developer content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o700) })
}

// TestVerifyCachedPolicyBundle_UnreadablePathReadsMissing pins D-704 fix 1,
// one row per shape: a path the node cannot read as the bundle file reads
// "missing" (an error here made the reporter skip every snapshot while the
// path stayed blocked).
func TestVerifyCachedPolicyBundle_UnreadablePathReadsMissing(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, path string)
		skip   func() string
	}{
		{"a read-only directory planted at the path", plantLockedDirectory, nil},
		{"a bundle file this user may not read", func(t *testing.T, path string) {
			if err := os.Chmod(path, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		}, func() string {
			if runtime.GOOS == "windows" || os.Geteuid() == 0 {
				return "file modes do not deny the owner here"
			}
			return ""
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != nil {
				if why := tc.skip(); why != "" {
					t.Skip(why)
				}
			}
			ps := newPolicyBundleServer(t)
			b := signedTestBundle(t, priv, pub, 3, escalatingTOML)
			ps.bundle = &b
			c, _, cachePath := enrolledClient(t, ps.srv.URL)
			if res, err := c.FetchPolicyBundle(context.Background(), cachePath); err != nil || res.Status != PolicyApplied {
				t.Fatalf("seed fetch = %+v, %v", res, err)
			}
			tc.mutate(t, cachePath)
			got, err := c.VerifyCachedPolicyBundle(context.Background(), cachePath)
			if err != nil {
				t.Fatalf("VerifyCachedPolicyBundle: %v (an unreadable path must be a verdict, not an error)", err)
			}
			if got.Integrity != orgcontract.BundleIntegrityMissing {
				t.Fatalf("check = %+v, want missing", got)
			}
		})
	}
}

// TestFetchPolicyBundle_PlantedDirectoryIsMovedAside pins the D-704 repair:
// the fetch moves a directory planted at the cache path aside (its content
// intact, nothing deleted), writes the organization's bundle, and the path
// verifies again.
func TestFetchPolicyBundle_PlantedDirectoryIsMovedAside(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyBundleServer(t)
	b := signedTestBundle(t, priv, pub, 3, escalatingTOML)
	ps.bundle = &b
	c, _, cachePath := enrolledClient(t, ps.srv.URL)
	if _, err := c.FetchPolicyBundle(context.Background(), cachePath); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}
	plantLockedDirectory(t, cachePath)

	res, err := c.FetchPolicyBundle(context.Background(), cachePath)
	if err != nil || res.Status != PolicyApplied || res.DisplacedTo == "" {
		t.Fatalf("fetch over a planted directory = %+v, %v, want the bundle re-applied and the move reported", res, err)
	}
	if got := ps.seen[len(ps.seen)-1]; got != "" {
		t.Fatalf("If-None-Match = %q with no bundle file, want none", got)
	}
	check, err := c.VerifyCachedPolicyBundle(context.Background(), cachePath)
	if err != nil || check.Integrity != orgcontract.BundleIntegrityVerified {
		t.Fatalf("after the repair: %+v, %v, want verified", check, err)
	}
	moved, _ := filepath.Glob(cachePath + ".displaced-*")
	if len(moved) != 1 {
		t.Fatalf("moved-aside entries = %v, want exactly one", moved)
	}
	t.Cleanup(func() { _ = os.Chmod(moved[0], 0o700) })
	kept, err := os.ReadFile(filepath.Join(moved[0], "keep.txt"))
	if err != nil || string(kept) != "developer content" {
		t.Fatalf("the planted directory's content = %q, %v, want it kept intact", kept, err)
	}
}

// TestDisplaceForeignCacheEntry pins the repair's reach, one row per entry
// at the path: only a non-regular entry is moved, nothing is ever deleted.
func TestDisplaceForeignCacheEntry(t *testing.T) {
	now := time.Date(2026, 10, 17, 0, 1, 34, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		plant     func(t *testing.T, path string)
		wantMoved bool
	}{
		{"nothing at the path", func(*testing.T, string) {}, false},
		{"a regular file (the atomic replace handles it)", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"a directory", func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "org-policy-bundle.json")
			tc.plant(t, path)
			aside, err := displaceForeignCacheEntry(path, now)
			if err != nil {
				t.Fatalf("displaceForeignCacheEntry: %v", err)
			}
			if (aside != "") != tc.wantMoved {
				t.Fatalf("moved to %q, want moved=%v", aside, tc.wantMoved)
			}
			if aside != "" {
				if _, err := os.Stat(aside); err != nil {
					t.Fatalf("the moved entry is gone: %v", err)
				}
				if !strings.HasPrefix(filepath.Base(aside), "org-policy-bundle.json.displaced-") {
					t.Fatalf("moved to %q, want a sibling of the cache path", aside)
				}
			}
		})
	}
}

// TestRetryFailureMessageFor pins the WARN table: a local failure never
// tells the operator to unenrol (D-704).
func TestRetryFailureMessageFor(t *testing.T) {
	local := fmt.Errorf("orgclient.FetchPolicyBundle: read cache baseline: %w: %w", errPolicyLocalPreResponse, errors.New("read x: is a directory"))
	if msg := retryFailureMessageFor(local); strings.Contains(msg, "unenroll") || !strings.Contains(msg, "local") {
		t.Fatalf("local failure message = %q, want a local-error message with no unenrol advice", msg)
	}
	if msg := retryFailureMessageFor(errors.New("dial tcp: connection refused")); !strings.Contains(msg, "org server stays unreachable") {
		t.Fatalf("transport failure message = %q, want the org-server message", msg)
	}
}

// TestRunLoopKickHoldsKicksDuringBackoff pins D-704's loop bound: after a
// failed cycle, kicks wait out the backoff instead of running a cycle each.
// Without it the policy-state reporter (which kicks the poll on a missing
// bundle) and the poll's outcome sink (which pokes the reporter) ran a
// tight fetch loop against the org server.
func TestRunLoopKickHoldsKicksDuringBackoff(t *testing.T) {
	c, _, _ := enrolledClient(t, "http://127.0.0.1:1")
	kick := make(chan struct{}, 1)
	var cycles atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.runLoopKick(ctx, time.Hour, kick, func(context.Context) error {
			cycles.Add(1)
			return fmt.Errorf("orgclient.FetchPolicyBundle: read cache baseline: %w", errPolicyLocalPreResponse)
		})
	}()
	// Kick continuously for well under the first (jittered) backoff.
	window := time.Duration(float64(initialBackoff) * (1 - jitterFraction) * 0.6)
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		select {
		case kick <- struct{}{}:
		default:
		}
		time.Sleep(time.Millisecond)
	}
	got := cycles.Load()
	cancel()
	<-done
	if got != 1 {
		t.Fatalf("cycles inside the first backoff = %d, want 1 (the first kick only)", got)
	}
}
