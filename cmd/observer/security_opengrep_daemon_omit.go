//go:build !sbo_omit_security && sbo_omit_security_scan_opengrep

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
)

// startOpengrepDaemon starts nothing in a build without the code rules.
func startOpengrepDaemon(context.Context, *gatedGroup, string, componentstate.Snapshot) {}
