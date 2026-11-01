//go:build sbo_omit_security

package main

import (
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/statusline"
)

// statuslineSecurityProvider shows nothing: the module is not in this build.
func statuslineSecurityProvider(config.Config) func(statusline.Input) *string { return nil }

// withSecuritySegment is never reached without a provider.
func withSecuritySegment(segs []string) []string { return segs }
