//go:build linux

package intervention

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRefreshInstallManifestRetainsOnlyLiveNativeLifetimes(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	launcher := filepath.Join(dir, "goose")
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, data, 0o700); err != nil {
		t.Fatal(err)
	}
	candidates := []InstalledCandidate{{Tool: "goose", LauncherPath: launcher}}
	opts := ScanOptions{TargetUID: os.Getuid(), ControllerPID: os.Getpid()}
	previous, err := BuildInstallManifest(ctx, candidates)
	if err != nil {
		t.Fatal(err)
	}
	allowCLIInvocationArgument(&previous, "goose/cli", "60")
	child := exec.Command(launcher, "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	id, err := Inspect(ctx, child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "new")
	if err := os.WriteFile(replacement, data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, launcher); err != nil {
		t.Fatal(err)
	}
	current, err := RefreshInstallManifest(ctx, previous, candidates, opts)
	if err != nil {
		t.Fatal(err)
	}
	allowCLIInvocationArgument(&current, "goose/cli", "60")
	row := requireSurface(t, current, "goose/cli")
	if len(row.Targets) != 2 {
		t.Fatalf("lost running old executable after vendor replacement: %+v", row)
	}
	if _, err := RevalidateBinding(ctx, current, id, "goose/cli", opts); err != nil {
		t.Fatalf("old process lost binding: %v", err)
	}
	// A reused PID or another process of the old inode must not inherit a
	// retired install's authority. Only this exact lifetime is retained.
	for _, field := range []string{"pid", "start", "boot", "uid"} {
		t.Run(field, func(t *testing.T) {
			other := id
			switch field {
			case "pid":
				other.PID++
			case "start":
				other.StartTicks++
			case "boot":
				other.BootID += "-next"
			case "uid":
				other.UID++
			}
			got := MatchInstalledProcess(current, ProcessEvidence{Identity: other}, MatchOptions{TargetUID: other.UID})
			if got.State != MatchNone {
				t.Fatalf("retained binding matched another lifetime: %+v", got)
			}
		})
	}
	if err := os.Remove(launcher); err != nil {
		t.Fatal(err)
	}
	current, err = RefreshInstallManifest(ctx, current, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	allowCLIInvocationArgument(&current, "goose/cli", "60")
	if _, err := RevalidateBinding(ctx, current, id, "goose/cli", opts); err != nil {
		t.Fatalf("running process lost binding after uninstall: %v", err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	current, err = RefreshInstallManifest(ctx, current, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if row := requireSurface(t, current, "goose/cli"); len(row.Targets) != 0 {
		t.Fatalf("exited native lifetime retained: %+v", row)
	}
}
