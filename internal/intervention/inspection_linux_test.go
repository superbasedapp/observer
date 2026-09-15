//go:build linux

package intervention

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/processobs/poll"
)

func TestProtectedInventoryIdentityIsNotControlAuthority(t *testing.T) {
	child := startOwnedChild(t, "protected")
	pid := child.cmd.Process.Pid
	ctx := context.Background()
	_, err := Inspect(ctx, pid)
	if err == nil {
		t.Skip("host grants inspection of a nondumpable child; permission fallback cannot be exercised")
	}
	if !errors.Is(err, ErrPermission) {
		t.Fatalf("protected child inspection: %v", err)
	}
	parent, err := Inspect(ctx, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	birth, ok := poll.ReadProcInfo(pid)
	if !ok || !birth.HasStart {
		t.Fatal("owned child's birth unavailable")
	}
	expected := parent
	expected.PID, expected.StartTicks = pid, birth.StartTicks
	called := 0
	opts := ScanOptions{TargetUID: os.Getuid(), InspectProtected: func(_ context.Context, gotPID int, start int64, boot string) (Identity, error) {
		called++
		if gotPID != pid || start != expected.StartTicks || boot != expected.BootID {
			t.Fatal("supplement request lost the original process birth")
		}
		return expected, nil
	}}
	got, err := inspectScanProcess(ctx, pid, opts)
	if err != nil || got != expected || called != 1 {
		t.Fatalf("supplement: identity=%+v calls=%d err=%v", got, called, err)
	}
	// A supplemented inventory identity cannot open a privileged control path.
	if _, err := Acquire(ctx, got); !errors.Is(err, ErrPermission) {
		t.Fatalf("supplement bypassed ordinary control inspection: %v", err)
	}
	if _, err := ReadProcessEvidence(ctx, InstallManifest{}, pid); !errors.Is(err, ErrPermission) {
		t.Fatalf("supplement bypassed ordinary binding inspection: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Identity)
	}{
		{"pid", func(id *Identity) { id.PID++ }},
		{"birth", func(id *Identity) { id.StartTicks++ }},
		{"uid", func(id *Identity) { id.UID++ }},
		{"boot", func(id *Identity) { id.BootID = "different-boot" }},
		{"missing-executable", func(id *Identity) { id.Executable = ExecutableIdentity{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := expected
			tc.mutate(&bad)
			opts.InspectProtected = func(context.Context, int, int64, string) (Identity, error) { return bad, nil }
			if _, err := inspectScanProcess(ctx, pid, opts); !errors.Is(err, ErrIdentityMismatch) {
				t.Fatalf("accepted wrong protected identity: %v", err)
			}
		})
	}
	opts.InspectProtected = func(context.Context, int, int64, string) (Identity, error) {
		return Identity{}, errors.New("private backend transport contents")
	}
	if _, err := inspectScanProcess(ctx, pid, opts); !errors.Is(err, ErrInspectionUnavailable) || strings.Contains(err.Error(), "private") {
		t.Fatalf("supplement failure was not closed: %v", err)
	}
}

func TestReadableInventoryDoesNotUsePrivilegedSupplement(t *testing.T) {
	child := startOwnedChild(t, "wait")
	ctx := context.Background()
	want := inspectOwned(t, child)
	opts := ScanOptions{TargetUID: os.Getuid(), InspectProtected: func(context.Context, int, int64, string) (Identity, error) {
		t.Fatal("readable process used privileged supplement")
		return Identity{}, nil
	}}
	got, err := inspectScanProcess(ctx, child.cmd.Process.Pid, opts)
	if err != nil || got != want {
		t.Fatalf("ordinary inspection changed: %+v %v", got, err)
	}
}

func TestMinimalProcessStartParserIgnoresCommandContents(t *testing.T) {
	fields := append([]string{"S"}, make([]string, 18)...)
	for index := 1; index < len(fields); index++ {
		fields[index] = "0"
	}
	fields = append(fields, "456")
	valid := "123 (name with ) and ( delimiters) " + strings.Join(fields, " ")
	for _, tc := range []struct {
		name string
		raw  string
		pid  int
		want bool
	}{
		{"embedded-delimiters", valid, 123, true},
		{"wrong-pid", valid, 124, false},
		{"truncated", "123 (name) S 0", 123, false},
		{"zero-start", strings.TrimSuffix(valid, "456") + "0", 123, false},
		{"invalid-start", strings.TrimSuffix(valid, "456") + "invalid", 123, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start, ok := parseProcessStart(tc.raw, tc.pid)
			if ok != tc.want || (ok && start != 456) {
				t.Fatalf("start=%d ok=%v", start, ok)
			}
		})
	}
}
