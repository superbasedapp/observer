package arena

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestAdmissionSeesTheLaunchTarget: the admission callback's context names
// the directory the process starts in and the run's source repository, and
// the environment entries it adds reach the process.
func TestAdmissionSeesTheLaunchTarget(t *testing.T) {
	out := filepath.Join(t.TempDir(), "env.txt")
	bin := fakeBin(t, t.TempDir(), "target-fake", `echo "$ARENA_TEST_MARK" > "`+out+`"`)
	ic, _ := integration.For("claude-code")
	wt, src := t.TempDir(), t.TempDir()
	var seen LaunchTarget
	_, err := executeDrive(context.Background(), bin, ic.Headless, driveRequest{
		Tool: "claude-code", Prompt: "p", WorktreePath: wt, SourceRoot: src, Timeout: 30 * time.Second,
		Admission: func(ctx context.Context, _, _ string) error {
			target, ok := LaunchTargetFrom(ctx)
			if !ok {
				t.Fatal("no launch target on the admission context")
			}
			seen = *target
			target.ChildEnv = append(target.ChildEnv, "ARENA_TEST_MARK=from-admission")
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen.Dir != wt || seen.SourceRoot != src {
		t.Fatalf("target %+v, want dir %s source %s", seen, wt, src)
	}
	got, err := os.ReadFile(out)
	if err != nil || strings.TrimSpace(string(got)) != "from-admission" {
		t.Fatalf("process env mark %q (%v), want from-admission", got, err)
	}
	if _, ok := LaunchTargetFrom(context.Background()); ok {
		t.Fatal("a bare context carries a target")
	}
}
