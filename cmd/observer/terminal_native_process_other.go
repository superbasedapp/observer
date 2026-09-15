//go:build !linux

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// Native writer/PID metadata needs a host process backend. Other platforms
// retain known-ID resume and existing discovery when this backend is absent.
func terminalNativeSession(context.Context, int, string, adapter.Adapter, adapter.TerminalSessionResolver, terminalProcessBinding) (terminalNativeIdentity, error) {
	return terminalNativeIdentity{}, nil
}

func terminalNativeDiscoveryAvailable(adapter.Adapter) bool { return false }
