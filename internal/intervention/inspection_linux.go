//go:build linux

package intervention

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/processobs/poll"
)

// inspectScanProcess supplements only an otherwise permission-denied inventory
// read. The broker cannot substitute for ReadProcessEvidence, Acquire or the
// supervisor's independent signal-time checks.
func inspectScanProcess(ctx context.Context, pid int, opts ScanOptions) (Identity, error) {
	if opts.InspectProtected == nil {
		return Inspect(ctx, pid)
	}
	before, birthErr := readProcessStart(pid)
	identity, err := Inspect(ctx, pid)
	if err == nil || !errors.Is(err, ErrPermission) {
		return identity, err
	}
	if birthErr != nil {
		return Identity{}, err
	}
	bootID := poll.PlatformBootID()
	uid, uidErr := readUniformUID(pid)
	if uidErr != nil || uid != opts.TargetUID || bootID == "" {
		return Identity{}, fmt.Errorf("intervention: protected inventory principal: %w", ErrIdentityMismatch)
	}
	identity, err = opts.InspectProtected(ctx, pid, before, bootID)
	if err != nil {
		// Supplemental transports must not contribute raw socket paths,
		// protocol contents or privileged backend errors to scan diagnostics.
		return Identity{}, fmt.Errorf("intervention: protected inventory: %w", ErrInspectionUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	after, afterErr := readProcessStart(pid)
	uid, uidErr = readUniformUID(pid)
	if !validIdentity(identity) || identity.PID != pid || identity.UID != opts.TargetUID ||
		identity.BootID != bootID || identity.StartTicks != before ||
		afterErr != nil || after != before ||
		uidErr != nil || uid != opts.TargetUID {
		return Identity{}, fmt.Errorf("intervention: protected inventory continuity: %w", ErrIdentityMismatch)
	}
	return identity, nil
}

// readProcessStart intentionally reads only the kernel stat record. General
// observation readers also collect argv, cwd and IO data and must not be used
// by the privileged identity service.
func readProcessStart(pid int) (int64, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return 0, ErrPermission
		}
		return 0, classifyUnreadableProcess(pid)
	}
	start, ok := parseProcessStart(string(raw), pid)
	if !ok {
		return 0, ErrInspectionUnavailable
	}
	return start, nil
}

func parseProcessStart(raw string, pid int) (int64, bool) {
	open, close := strings.IndexByte(raw, '('), strings.LastIndexByte(raw, ')')
	if open < 1 || close <= open {
		return 0, false
	}
	gotPID, err := strconv.Atoi(strings.TrimSpace(raw[:open]))
	if err != nil || gotPID != pid {
		return 0, false
	}
	fields := strings.Fields(raw[close+1:])
	if len(fields) < 20 || len(fields[0]) != 1 {
		return 0, false
	}
	start, err := strconv.ParseInt(fields[19], 10, 64)
	return start, err == nil && start > 0
}
