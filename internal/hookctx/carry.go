package hookctx

import (
	"context"
	"sync"
)

type ctxKey struct{}

// WithContext attaches c to ctx, so the handlers below the receiver read
// the same filled context the entry point built.
func WithContext(ctx context.Context, c *Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, ctxKey{}, c)
}

// Attached returns the context WithContext attached to ctx.
func Attached(ctx context.Context) (*Context, bool) {
	if ctx == nil {
		return nil, false
	}
	c, ok := ctx.Value(ctxKey{}).(*Context)
	return c, ok && c != nil
}

// From returns the context attached to ctx, or a host-path context with
// no providers when none is attached. The fallback is what every hook
// handler read before the seam (the hook process's own operating system),
// so a handler reached without an attached context behaves as it always
// did; the daemon path always attaches its own.
func From(ctx context.Context) *Context {
	if c, ok := Attached(ctx); ok {
		return c
	}
	return HostDefault()
}

// process is the hook process's own filled context (SetProcess), read by
// the pure event builders that take no context.Context.
var (
	processMu  sync.Mutex
	processCtx *Context
)

// SetProcess records c as this process's hook context. An `observer hook`
// process serves exactly one invocation, so one slot is enough: the entry
// point sets it, and the builders below the receiver that cannot carry a
// context.Context read it through Process. On the relay path this is what
// makes those builders read the run's channel instead of the host (sandbox
// plan section 5.2: the agy transcript reader, the ancestry start, the
// sandbox marker, the worktree-root default). nil clears it.
func SetProcess(c *Context) {
	processMu.Lock()
	processCtx = c
	processMu.Unlock()
}

// Process returns the context SetProcess recorded, or HostDefault when none
// was (a test calling a builder directly, or any non-hook process).
func Process() *Context {
	processMu.Lock()
	c := processCtx
	processMu.Unlock()
	if c != nil {
		return c
	}
	return HostDefault()
}

// HostDefault is a host-path context with HostSource and no providers.
// Building it does no I/O.
func HostDefault() *Context {
	return &Context{path: PathHost, src: HostSource()}
}
