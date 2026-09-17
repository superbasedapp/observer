//go:build linux

package intervention

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

func TestBuildInstallManifestNativeAndRefresh(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	launcher := filepath.Join(dir, "goose")
	copyOwnExecutable(t, launcher)

	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{Tool: "goose", LauncherPath: launcher}})
	if err != nil {
		t.Fatal(err)
	}
	surface := requireSurface(t, manifest, "goose/cli")
	if surface.State != BindingReady || len(surface.Targets) != 1 || surface.Targets[0].Kind != TargetNativeExecutable {
		t.Fatalf("native surface = %+v", surface)
	}
	oldIdentity := surface.Targets[0].Executable.Identity

	replacement := filepath.Join(dir, "replacement")
	copyOwnExecutable(t, replacement)
	if err := os.Rename(replacement, launcher); err != nil {
		t.Fatal(err)
	}
	refreshed, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{Tool: "goose", LauncherPath: launcher}})
	if err != nil {
		t.Fatal(err)
	}
	newIdentity := requireSurface(t, refreshed, "goose/cli").Targets[0].Executable.Identity
	if newIdentity == oldIdentity {
		t.Fatal("replaced executable retained its old device/inode identity")
	}

	id := Identity{BootID: "boot", PID: 9001, StartTicks: 1, UID: os.Getuid(), Executable: newIdentity}
	if got := MatchInstalledProcess(manifest, ProcessEvidence{Identity: id}, MatchOptions{TargetUID: os.Getuid()}); got.State != MatchNone {
		t.Fatalf("stale manifest matched replacement: %+v", got)
	}
}

func TestCodexInvocationSeparatesCLIFromSameExecutableService(t *testing.T) {
	dir := t.TempDir()
	launcher := filepath.Join(dir, "codex")
	raw, err := os.ReadFile("/usr/bin/yes")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{Tool: "codex", LauncherPath: launcher}})
	if err != nil {
		t.Fatal(err)
	}

	start := func(argument string) *exec.Cmd {
		t.Helper()
		cmd := exec.Command(launcher, argument)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
		return cmd
	}
	cli := start("exec")
	service := start("app-server")
	serviceID, err := Inspect(context.Background(), service.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	knownScan, err := ScanInstalledProcesses(ctx, manifest, ScanOptions{TargetUID: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	if len(knownScan.Matches) != 1 || knownScan.Matches[0].Identity.PID != cli.Process.Pid || knownScan.Matches[0].SurfaceID != "codex/cli" ||
		!identityListContainsPID(knownScan.Refused, service.Process.Pid) {
		t.Fatalf("known same-inode codex modes scan = %+v", knownScan)
	}

	// An undeclared leading argument is the product's ordinary CLI: the
	// executable identity already matched exactly, so the invocation is
	// governed rather than abstained on, and the scan stays complete.
	unknown := start("future-mode")
	if _, err := Inspect(context.Background(), unknown.Process.Pid); err != nil {
		t.Fatal(err)
	}
	scan, err := ScanInstalledProcesses(ctx, manifest, ScanOptions{TargetUID: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Matches) != 2 ||
		!matchListContainsPID(scan.Matches, cli.Process.Pid) || !matchListContainsPID(scan.Matches, unknown.Process.Pid) {
		t.Fatalf("same-inode codex scan with undeclared mode = %+v", scan)
	}
	for _, match := range scan.Matches {
		if match.SurfaceID != "codex/cli" {
			t.Fatalf("unexpected surface in codex scan: %+v", match)
		}
	}
	if !identityListContainsPID(scan.Refused, service.Process.Pid) {
		t.Fatalf("declared service invocation absent from refusals: %+v", scan.Refused)
	}
	if identityListContainsPID(scan.Refused, unknown.Process.Pid) {
		t.Fatalf("undeclared codex mode escaped governance: %+v", scan.Refused)
	}
	if len(scan.UnclassifiedSurfaces) != 0 {
		t.Fatalf("declared non-billable mode degraded the scan: %+v", scan)
	}
	// Complete reports whether the WHOLE process table was reconciled, not just
	// this test's own two launched processes. On a shared/sandboxed host the
	// scan legitimately meets root-owned or foreign-UID processes it cannot
	// read /proc entries for (ScanFailureInspectionUnavailable) — that is the
	// honest answer (docs/security.md ledger row INT-1), not a defect. What
	// this test actually needs is that its own launched processes were never
	// among the casualties: cli/unknown must still classify as matches (already
	// asserted above) and service must still classify as refused, none of them
	// dropped as an inspection failure.
	if !scan.Complete {
		for _, pid := range []int{cli.Process.Pid, service.Process.Pid, unknown.Process.Pid} {
			if failureListContainsPID(scan.Failures, pid) {
				t.Fatalf("scan incompleteness implicates a process this test launched (pid=%d): failures=%+v", pid, scan.Failures)
			}
			if identityListContainsPID(scan.Ambiguous, pid) {
				t.Fatalf("scan incompleteness implicates a process this test launched via ambiguity (pid=%d): ambiguous=%+v", pid, scan.Ambiguous)
			}
		}
	}
	if _, err := RevalidateBinding(ctx, manifest, serviceID, "codex/cli", ScanOptions{TargetUID: os.Getuid()}); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("same-inode app-server revalidation error = %v, want binding mismatch", err)
	}

	governed, ok := matchForPID(scan.Matches, cli.Process.Pid)
	if !ok {
		t.Fatalf("declared codex CLI absent from matches: %+v", scan.Matches)
	}
	handle, err := Acquire(ctx, governed.Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handle.Close() }()
	result, err := handle.Terminate(ctx)
	if err != nil || !result.Observed || result.AlreadyExited {
		t.Fatalf("terminate disposable codex CLI = %+v, %v", result, err)
	}
	_ = cli.Wait()
	if current, err := Inspect(ctx, service.Process.Pid); err != nil || current != serviceID {
		t.Fatalf("same-inode app-server changed after CLI cutoff: current=%+v err=%v", current, err)
	}
}

func TestInterpretedInvocationSeparatesCLIFromSameScriptService(t *testing.T) {
	dir := t.TempDir()
	interpreter := filepath.Join(dir, "node")
	raw, err := os.ReadFile("/usr/bin/yes")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(interpreter, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(dir, "commandcode")
	writeExecutable(t, launcher, []byte("#!"+interpreter+"\n"))
	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{Tool: "command-code", LauncherPath: launcher}})
	if err != nil {
		t.Fatal(err)
	}
	allowCLIInvocationArgument(&manifest, "command-code/cli", "cli")
	allowNonCLIInvocationArgument(&manifest, "command-code/cli", "serve")

	start := func(argument string) *exec.Cmd {
		t.Helper()
		cmd := exec.Command(launcher, argument)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
		return cmd
	}
	cli := start("cli")
	service := start("serve")
	serviceID, err := Inspect(context.Background(), service.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	scan, err := ScanInstalledProcesses(ctx, manifest, ScanOptions{TargetUID: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Matches) != 1 || scan.Matches[0].Identity.PID != cli.Process.Pid || scan.Matches[0].Target.Kind != TargetInterpretedEntrypoint ||
		!identityListContainsPID(scan.Refused, service.Process.Pid) {
		t.Fatalf("same-script CLI/service scan = %+v", scan)
	}
	if _, err := RevalidateBinding(ctx, manifest, serviceID, "command-code/cli", ScanOptions{TargetUID: os.Getuid()}); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("same-script service revalidation error = %v, want binding mismatch", err)
	}

	handle, err := Acquire(ctx, scan.Matches[0].Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handle.Close() }()
	result, err := handle.Terminate(ctx)
	if err != nil || !result.Observed || result.AlreadyExited {
		t.Fatalf("terminate disposable interpreted CLI = %+v, %v", result, err)
	}
	_ = cli.Wait()
	if current, err := Inspect(ctx, service.Process.Pid); err != nil || current != serviceID {
		t.Fatalf("same-script service changed after CLI cutoff: current=%+v err=%v", current, err)
	}
}

func TestReadInvocationArgumentsIsBoundedAndDistinguishesAbsentFields(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		raw     []byte
		want    [2]transientArgument
		wantErr bool
	}{
		{name: "no arguments", raw: []byte("tool\x00")},
		{name: "one argument", raw: []byte("tool\x00exec\x00"), want: [2]transientArgument{{value: "exec", present: true}}},
		{name: "two arguments", raw: []byte("tool\x00script\x00serve\x00"), want: [2]transientArgument{{value: "script", present: true}, {value: "serve", present: true}}},
		{name: "unterminated field", raw: []byte("tool\x00exec"), wantErr: true},
		{name: "oversized field", raw: append(append([]byte("tool\x00"), bytes.Repeat([]byte{'x'}, invocationFieldBytes)...), 0), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cmdline")
			if err := os.WriteFile(path, tc.raw, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := readInvocationArguments(context.Background(), path)
			if (err != nil) != tc.wantErr || (!tc.wantErr && got != tc.want) {
				t.Fatalf("readInvocationArguments() = (%+v, %v), want (%+v, error=%v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestBuildInstallManifestInterpretedEntrypoint(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	interpreter := filepath.Join(dir, "node")
	copyOwnExecutable(t, interpreter)
	launcher := filepath.Join(dir, "commandcode")
	writeExecutable(t, launcher, []byte("#!/usr/bin/env node\nconsole.log('fixture')\n"))

	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{
		Tool:         "command-code",
		LauncherPath: launcher,
		Interpreters: []InstalledInterpreter{{Kind: "node", Path: interpreter}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	surface := requireSurface(t, manifest, "command-code/cli")
	if surface.State != BindingReady || len(surface.Targets) != 1 || surface.Targets[0].Kind != TargetInterpretedEntrypoint {
		t.Fatalf("interpreted surface = %+v", surface)
	}
	if surface.Targets[0].Entrypoint == nil || surface.Targets[0].Entrypoint.Path != launcher {
		t.Fatalf("entrypoint = %+v, want %q", surface.Targets[0].Entrypoint, launcher)
	}
}

func TestBuildInstallManifestPinsEverySuppliedInterpreter(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	python3 := filepath.Join(dir, "python3")
	python := filepath.Join(dir, "python")
	copyOwnExecutable(t, python3)
	copyOwnExecutable(t, python)
	launcher := filepath.Join(dir, "aider")
	writeExecutable(t, launcher, []byte("#!/usr/bin/env python\n# fixture\n"))

	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{
		Tool:         "aider",
		LauncherPath: launcher,
		Interpreters: []InstalledInterpreter{
			{Kind: "python", Path: python3},
			{Kind: "python", Path: python},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	surface := requireSurface(t, manifest, "aider/cli")
	if surface.State != BindingReady || len(surface.Targets) != 2 {
		t.Fatalf("multi-interpreter surface = %+v", surface)
	}
	for _, target := range surface.Targets {
		if target.Kind != TargetInterpretedEntrypoint || target.Entrypoint == nil || target.Entrypoint.Path != launcher {
			t.Errorf("multi-interpreter target = %+v", target)
		}
	}
}

func TestBuildInstallManifestRejectsShellWithoutDeclaredWorker(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	launcher := filepath.Join(dir, "hermes")
	writeExecutable(t, launcher, []byte("#!/bin/sh\nexit 0\n"))
	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{Tool: "hermes", LauncherPath: launcher}})
	if err != nil {
		t.Fatal(err)
	}
	surface := requireSurface(t, manifest, "hermes/cli")
	if surface.State != BindingUnsupported || len(surface.Targets) != 0 || !slices.Contains(surface.Reasons, ReasonShellLauncher) {
		t.Fatalf("shell surface = %+v", surface)
	}
}

func TestBuildInstallManifestDiscoversAllMuseNativeWorkers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	launcher := filepath.Join(dir, "muse")
	writeExecutable(t, launcher, []byte("#!/bin/sh\nexec \"$0-bin-version\" \"$@\"\n"))
	copyOwnExecutable(t, filepath.Join(dir, "muse-bin-0.1.0"))
	copyOwnExecutable(t, filepath.Join(dir, "muse-bin-0.2.0"))
	copyOwnExecutable(t, filepath.Join(dir, "ordinary-helper"))

	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{Tool: "muse", LauncherPath: launcher}})
	if err != nil {
		t.Fatal(err)
	}
	surface := requireSurface(t, manifest, "muse/cli")
	if surface.State != BindingReady || len(surface.Targets) != 2 {
		t.Fatalf("muse surface = %+v", surface)
	}
	for _, target := range surface.Targets {
		if target.Kind != TargetNativeExecutable || filepath.Base(target.Executable.Path) == "muse" {
			t.Errorf("unsafe muse target = %+v", target)
		}
	}
}

func TestBuildInstallManifestDiscoversCodexPackageWorker(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	packageBin := filepath.Join(dir, "lib", "node_modules", "@openai", "codex", "bin")
	if err := os.MkdirAll(packageBin, 0o755); err != nil {
		t.Fatal(err)
	}
	launcherReal := filepath.Join(packageBin, "codex.js")
	writeExecutable(t, launcherReal, []byte("#!/usr/bin/env node\n// fixture package launcher\n"))
	worker := filepath.Join(filepath.Dir(packageBin), "vendor", "x86_64-unknown-linux-musl", "bin", "codex")
	if err := os.MkdirAll(filepath.Dir(worker), 0o755); err != nil {
		t.Fatal(err)
	}
	copyOwnExecutable(t, worker)
	visibleDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(visibleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	visible := filepath.Join(visibleDir, "codex")
	if err := os.Symlink(launcherReal, visible); err != nil {
		t.Fatal(err)
	}

	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{Tool: "codex", LauncherPath: visible}})
	if err != nil {
		t.Fatal(err)
	}
	surface := requireSurface(t, manifest, "codex/cli")
	if surface.State != BindingReady || len(surface.Targets) != 1 || surface.Targets[0].Executable.Path != worker {
		t.Fatalf("codex surface = %+v", surface)
	}
}

func TestBuildInstallManifestRejectsCodexWorkerSymlinkOutsideDeclaredLayout(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	packageBin := filepath.Join(dir, "lib", "node_modules", "@openai", "codex", "bin")
	if err := os.MkdirAll(packageBin, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(packageBin, "codex.js")
	writeExecutable(t, launcher, []byte("#!/usr/bin/env node\n// fixture package launcher\n"))
	visibleDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(visibleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	visible := filepath.Join(visibleDir, "codex")
	if err := os.Symlink(launcher, visible); err != nil {
		t.Fatal(err)
	}
	declaredWorker := filepath.Join(filepath.Dir(packageBin), "vendor", "x86_64-unknown-linux-musl", "bin", "codex")
	if err := os.MkdirAll(filepath.Dir(declaredWorker), 0o755); err != nil {
		t.Fatal(err)
	}
	outsideWorker := filepath.Join(dir, "unrelated", "codex")
	copyOwnExecutable(t, outsideWorker)
	if err := os.Symlink(outsideWorker, declaredWorker); err != nil {
		t.Fatal(err)
	}

	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{Tool: "codex", LauncherPath: visible}})
	if err != nil {
		t.Fatal(err)
	}
	surface := requireSurface(t, manifest, "codex/cli")
	if surface.State != BindingUnsupported || len(surface.Targets) != 0 || !slices.Contains(surface.Reasons, ReasonGenericProcessHost) {
		t.Fatalf("external codex worker symlink surface = %+v", surface)
	}
}

func TestBuildInstallManifestRefusesWrongLauncherName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	launcher := filepath.Join(dir, "not-goose")
	copyOwnExecutable(t, launcher)
	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{Tool: "goose", LauncherPath: launcher}})
	if err != nil {
		t.Fatal(err)
	}
	surface := requireSurface(t, manifest, "goose/cli")
	if surface.State != BindingUnsupported || !slices.Contains(surface.Reasons, ReasonCandidatePathInvalid) {
		t.Fatalf("wrong-name surface = %+v", surface)
	}
}

func TestBuildInstallManifestRefusesGenericNativeSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	launcher := filepath.Join(dir, "goose")
	if err := os.Symlink("/bin/sleep", launcher); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{Tool: "goose", LauncherPath: launcher}})
	if err != nil {
		t.Fatal(err)
	}
	surface := requireSurface(t, manifest, "goose/cli")
	if surface.State != BindingUnsupported || len(surface.Targets) != 0 || !slices.Contains(surface.Reasons, ReasonGenericProcessHost) {
		t.Fatalf("generic-host surface = %+v", surface)
	}
}

func TestBuildInstallManifestRefusesGenericMuseWorkerSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	launcher := filepath.Join(dir, "muse")
	writeExecutable(t, launcher, []byte("#!/bin/sh\nexit 0\n"))
	if err := os.Symlink("/bin/sh", filepath.Join(dir, "muse-bin-1.0.0")); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{Tool: "muse", LauncherPath: launcher}})
	if err != nil {
		t.Fatal(err)
	}
	surface := requireSurface(t, manifest, "muse/cli")
	if surface.State != BindingUnsupported || len(surface.Targets) != 0 || !slices.Contains(surface.Reasons, ReasonGenericProcessHost) {
		t.Fatalf("generic muse worker surface = %+v", surface)
	}
}

func TestBuildInstallManifestRejectsFIFOWithoutOpeningIt(t *testing.T) {
	t.Parallel()

	launcher := filepath.Join(t.TempDir(), "goose")
	if err := syscall.Mkfifo(launcher, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	manifest, err := BuildInstallManifest(ctx, []InstalledCandidate{{Tool: "goose", LauncherPath: launcher}})
	if err != nil {
		t.Fatal(err)
	}
	if surface := requireSurface(t, manifest, "goose/cli"); surface.State != BindingUnsupported || !slices.Contains(surface.Reasons, ReasonCandidateNotExecutable) {
		t.Fatalf("FIFO surface = %+v", surface)
	}
}

func TestBuildInstallManifestRetainsUnresolvedCandidateEvidence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	wrong := filepath.Join(dir, "not-goose")
	launcher := filepath.Join(dir, "goose")
	copyOwnExecutable(t, wrong)
	copyOwnExecutable(t, launcher)
	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{
		{Tool: "goose", LauncherPath: wrong},
		{Tool: "goose", LauncherPath: launcher},
	})
	if err != nil {
		t.Fatal(err)
	}
	surface := requireSurface(t, manifest, "goose/cli")
	if surface.State != BindingPartial || len(surface.Targets) != 1 || !slices.Contains(surface.Reasons, ReasonCandidatePathInvalid) {
		t.Fatalf("multi-candidate surface = %+v", surface)
	}
}

func TestScanAndRevalidateDisposableNativeProcess(t *testing.T) {
	if os.Getenv("INTERVENTION_BINDING_HELPER") == "1" {
		fmt.Println("ready")
		time.Sleep(30 * time.Second)
		return
	}

	dir := t.TempDir()
	launcher := filepath.Join(dir, "goose")
	copyOwnExecutable(t, launcher)
	manifest, err := BuildInstallManifest(context.Background(), []InstalledCandidate{{Tool: "goose", LauncherPath: launcher}})
	if err != nil {
		t.Fatal(err)
	}
	allowCLIInvocationArgument(&manifest, "goose/cli", "-test.run=^TestScanAndRevalidateDisposableNativeProcess$")

	cmd := exec.Command(launcher, "-test.run=^TestScanAndRevalidateDisposableNativeProcess$")
	cmd.Env = append(os.Environ(), "INTERVENTION_BINDING_HELPER=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
			return
		}
		ready <- ""
	}()
	select {
	case line := <-ready:
		if line != "ready" {
			t.Fatalf("helper readiness = %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not become ready")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := ScanInstalledProcesses(ctx, manifest, ScanOptions{TargetUID: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	var found *ProcessMatch
	for i := range result.Matches {
		if result.Matches[i].Identity.PID == cmd.Process.Pid {
			found = &result.Matches[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("disposable helper PID %d absent from matches; result=%+v", cmd.Process.Pid, result)
	}
	match, err := RevalidateBinding(ctx, manifest, found.Identity, "goose/cli", ScanOptions{TargetUID: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	if match.Identity != found.Identity {
		t.Fatalf("revalidated identity = %+v, want %+v", match.Identity, found.Identity)
	}
}

func TestScanInstalledProcessesSkipsOwnedZombie(t *testing.T) {
	if os.Getenv("INTERVENTION_ZOMBIE_HELPER") == "1" {
		return
	}

	helper := filepath.Join(t.TempDir(), "zombie-helper")
	copyOwnExecutable(t, helper)
	cmd := exec.Command(helper, "-test.run=^TestScanInstalledProcessesSkipsOwnedZombie$")
	cmd.Env = append(os.Environ(), "INTERVENTION_ZOMBIE_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Wait()
		}
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		_, _, state, err := readStatusIdentityState(cmd.Process.Pid)
		if err == nil && state == 'Z' {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("copied helper PID %d did not become a zombie: state=%q err=%v", cmd.Process.Pid, state, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	result, err := ScanInstalledProcesses(context.Background(), InstallManifest{}, ScanOptions{TargetUID: os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range result.Failures {
		if failure.PID == cmd.Process.Pid {
			t.Fatalf("zombie PID %d recorded as an inspection failure: %+v", cmd.Process.Pid, failure)
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	waited = true
}

func TestAncestorPIDsIncludesSelf(t *testing.T) {
	t.Parallel()

	got, err := AncestorPIDs(context.Background(), os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[0] != os.Getpid() {
		t.Fatalf("ancestors = %v", got)
	}
}

func requireSurface(t *testing.T, manifest InstallManifest, id string) SurfaceManifest {
	t.Helper()
	surface, ok := manifest.Surface(id)
	if !ok {
		t.Fatalf("manifest missing %q", id)
	}
	return surface
}

func allowCLIInvocationArgument(manifest *InstallManifest, surfaceID, argument string) {
	if manifest == nil {
		return
	}
	for i := range manifest.Surfaces {
		if manifest.Surfaces[i].Spec.ID == surfaceID {
			manifest.Surfaces[i].Spec.Binding.Invocation.CLILeadingArguments = append(
				manifest.Surfaces[i].Spec.Binding.Invocation.CLILeadingArguments, argument,
			)
			return
		}
	}
}

func allowNonCLIInvocationArgument(manifest *InstallManifest, surfaceID, argument string) {
	if manifest == nil {
		return
	}
	for i := range manifest.Surfaces {
		if manifest.Surfaces[i].Spec.ID == surfaceID {
			manifest.Surfaces[i].Spec.Binding.Invocation.NonCLILeadingArguments = append(
				manifest.Surfaces[i].Spec.Binding.Invocation.NonCLILeadingArguments, argument,
			)
			return
		}
	}
}

func matchForPID(matches []ProcessMatch, pid int) (ProcessMatch, bool) {
	for _, match := range matches {
		if match.Identity.PID == pid {
			return match, true
		}
	}
	return ProcessMatch{}, false
}

func matchListContainsPID(matches []ProcessMatch, pid int) bool {
	_, ok := matchForPID(matches, pid)
	return ok
}

func identityListContainsPID(identities []Identity, pid int) bool {
	for _, identity := range identities {
		if identity.PID == pid {
			return true
		}
	}
	return false
}

func failureListContainsPID(failures []ProcessScanFailure, pid int) bool {
	for _, failure := range failures {
		if failure.PID == pid {
			return true
		}
	}
	return false
}

func copyOwnExecutable(t *testing.T, path string) {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, path, raw)
}

func writeExecutable(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o755); err != nil {
		t.Fatal(err)
	}
}
