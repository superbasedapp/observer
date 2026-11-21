package customagent

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// Adapter is the proxy-only custom-agent adapter. It has no watch roots.
type Adapter struct{}

// New returns the custom-agent adapter.
func New() *Adapter { return &Adapter{} }

// Name returns the stable tool identifier.
func (a *Adapter) Name() string { return models.ToolCustomAgent }

// WatchPaths returns nil: capture arrives through the proxy, never the file
// watcher.
func (a *Adapter) WatchPaths() []string { return nil }

// IsSessionFile always returns false: an own agent writes no session file
// Observer reads.
func (a *Adapter) IsSessionFile(string) bool { return false }

// ParseSessionFile is a no-op the watcher never calls (no watch roots); the
// Adapter interface requires it.
func (a *Adapter) ParseSessionFile(_ context.Context, _ string, fromOffset int64) (adapter.ParseResult, error) {
	return adapter.ParseResult{NewOffset: fromOffset}, nil
}
