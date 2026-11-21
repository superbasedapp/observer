//go:build !linux

package pidbridge

import (
	"context"
	"time"
)

// ProcResolver on non-Linux is a stub. Resolve always reports a clean
// miss so the proxy falls back to a NULL session_id on api_turns.
type ProcResolver struct {
	store *Store
}

// NewProcResolver returns a stub resolver on non-Linux builds. procDir
// and cacheTTL are accepted for API parity but ignored.
func NewProcResolver(store *Store, _ string, _ time.Duration) *ProcResolver {
	return &ProcResolver{store: store}
}

// SetClock is a no-op on non-Linux.
func (r *ProcResolver) SetClock(func() time.Time) {}

// Resolve always reports a clean miss.
func (r *ProcResolver) Resolve(context.Context, string) (string, bool, error) {
	return "", false, nil
}

// ResolveTool always reports a clean miss on non-Linux — per-tool
// profile assignment (R2) degrades to per-provider resolution.
func (r *ProcResolver) ResolveTool(context.Context, string) (string, bool, error) {
	return "", false, nil
}

// ResolveCWD always reports a clean miss on non-Linux — per-project
// overrides (R3) degrade to the global assignment table.
func (r *ProcResolver) ResolveCWD(context.Context, string) (string, bool, error) {
	return "", false, nil
}

// ResolveOwnTool always reports a clean miss on non-Linux: the process
// table is not introspected, so no process is known to be a tool's own.
func (r *ProcResolver) ResolveOwnTool(context.Context, string) (string, bool, error) {
	return "", false, nil
}

// SetToolBinaries is a no-op on non-Linux: there is no own-process check.
func (r *ProcResolver) SetToolBinaries(func(tool string) []string) {}
