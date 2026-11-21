package proxy

import (
	"context"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// runfold.go is the proxy's one seam for folding a stamped local run's
// model turn onto the tool's native session (tracker row F-003, finding
// F-N3-1, ledger row OSH-R-150). It is an optional extension of the
// process-wide CredentialInjector (only a run with an injection record is
// stamped by a local host helper), so with no injector, or one that does
// not fold, every stamped request lands on RelaySessionID exactly as
// before. The fold decision itself is the injector's (cmd/observer, over
// internal/sandboxcred's table); the proxy only asks.

// RunSessionRequest is what the proxy hands the folder for one stamped
// request: the run header, the relay token header and the session id the
// request names (the proxy's own extraction).
type RunSessionRequest struct {
	RunID, Token, Session string
}

// RunSessionFolder is the optional CredentialInjector extension that may
// fold a stamped request's turn onto the session it names. ok false keeps
// the turn in the run's namespace.
type RunSessionFolder interface {
	FoldRunSession(ctx context.Context, in RunSessionRequest) (session string, ok bool)
}

// foldRunSession returns the session a stamped request of run lands on when
// the installed injector folds it, "" otherwise. sid is the id the request
// names before any run namespace.
func foldRunSession(r *http.Request, run, sid string) string {
	if sid == "" || !sandboxvocab.ValidRelayRunID(run) {
		return ""
	}
	b := credInjector.Load()
	if b == nil {
		return ""
	}
	f, ok := b.i.(RunSessionFolder)
	if !ok {
		return ""
	}
	s, ok := f.FoldRunSession(r.Context(), RunSessionRequest{RunID: run, Token: r.Header.Get(SandboxCredTokenHeader), Session: sid})
	if !ok || s != sid {
		return ""
	}
	return s
}
