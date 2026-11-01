//go:build sbo_omit_security

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_managedpull_omit.go: a build without the security module applies
// no managed pull; the component resolver gets nothing from it.

func securityManagedGranted(context.Context, config.Config, *store.Store, orgclient.ManagedPullConsent) []string {
	return nil
}

func loadSecurityManagedAtStart(context.Context, config.Config, *store.Store) {}

// bindSecurityBaselineOrg binds nothing without the security module.
func bindSecurityBaselineOrg(*store.Store) {}
