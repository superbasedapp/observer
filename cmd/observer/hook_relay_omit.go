//go:build sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import (
	"context"
	"io"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
)

// hook_relay_omit.go stands in for hook_relay.go in a build without the
// sandbox module: no box ever runs this binary's hooks (a build without the
// module never plans a sandboxed launch), and no daemon of this build
// relays, so both ends answer "not mine".

func boxHookRelay([]string, io.Reader, io.Writer, io.Writer) (int, bool) { return 0, false }

func relayChildHookContext(context.Context, hookctx.Request, string) (*hookctx.Context, bool) {
	return nil, false
}

func boxLaunchGate(string, budgetLaunchEvidence) (error, bool) { return nil, false } //nolint:revive // mirrors the full build

func inRelayBox() bool { return false }

var errNoDatabaseInBox error
