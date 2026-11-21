package attachsock

import "context"

// callerPIDKey carries the connecting process's pid through a handler's
// context.
type callerPIDKey struct{}

// WithCallerPID returns ctx carrying the attach connection's peer process
// id (lane cli-2). The server sets it from the endpoint's peer credentials
// (localipc.PeerPID) before it calls the Host or the Controller.
func WithCallerPID(ctx context.Context, pid int) context.Context {
	if pid <= 0 {
		return ctx
	}
	return context.WithValue(ctx, callerPIDKey{}, pid)
}

// CallerPID returns the attach connection's peer process id, false when
// the platform has no lookup or it failed (the caller is not identified).
func CallerPID(ctx context.Context) (int, bool) {
	pid, ok := ctx.Value(callerPIDKey{}).(int)
	return pid, ok && pid > 0
}

// callerStartKey carries the token naming the start of the connecting
// process, read when its connection was accepted.
type callerStartKey struct{}

// WithCallerStart returns ctx carrying the connecting process's start
// token (peerproc.StartToken) as the server read it at accept (lane cli-2
// fixes-3, audit M1). An empty token is not recorded.
func WithCallerStart(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return context.WithValue(ctx, callerStartKey{}, token)
}

// CallerStart returns the start token of the connecting process as read at
// accept, false when it was not read. A Controller compares it with the
// token the pid holds when it judges a request: a caller that exited, or a
// pid that now names another process, is no longer the caller that
// connected (agentlaunch.CallerPresent).
func CallerStart(ctx context.Context) (string, bool) {
	tok, ok := ctx.Value(callerStartKey{}).(string)
	return tok, ok && tok != ""
}

// CallerSnapshotter is an OPTIONAL Host capability (lane cli-2 fixes-3,
// audit M1): the server calls it once per accepted connection, before the
// connection's first frame is read, with the connecting process's pid; the
// context it returns carries whatever the host reads about that process
// then (its ancestry, its environment marker) to every later judgment of
// the request, so facts that a process could shed by exiting are read
// while it still runs. A Host without it judges the caller when the
// request arrives.
type CallerSnapshotter interface {
	SnapshotCaller(ctx context.Context, pid int) context.Context
}

// CallerHint is the agent-session hint a control client reported about
// itself: it found an agent session's environment marker. It can only make
// the caller an agent's, never a human's.
type CallerHint struct {
	AgentEnv bool
	Session  string
}

type callerHintKey struct{}

// WithCallerHint returns ctx carrying a control request's hint.
func WithCallerHint(ctx context.Context, h CallerHint) context.Context {
	return context.WithValue(ctx, callerHintKey{}, h)
}

// CallerHintOf returns the hint a control request carried (the zero value
// when none).
func CallerHintOf(ctx context.Context) CallerHint {
	h, _ := ctx.Value(callerHintKey{}).(CallerHint)
	return h
}
