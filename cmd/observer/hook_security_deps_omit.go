//go:build !sbo_omit_security && sbo_omit_security_deps

package main

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// hook_security_deps_omit.go stands in for the install gate without the
// security.deps component: no install provider and no install check.

const hookInstallLimit time.Duration = 0

func securityInstallChecker(string) hookctx.InstallChecker { return nil }

func securityDepsEnrich(context.Context, *hookctx.Context, *policy.Event, string) {}
