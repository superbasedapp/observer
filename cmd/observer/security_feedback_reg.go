package main

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
)

// security_feedback_reg.go hands the hook registration writers the one
// optional-module rule (lane sec-h): hook.Options.Selected answers whether
// a binding's RegisterWhen component is selected (securitySelected: active,
// and for an opt-in child such as security.feedback, named by a
// [components] block). It is compiled into every build: with
// sbo_omit_security the security tree is not compiled, so nothing is
// selected and no opt-in event is ever written.

// registrationSelected returns hook.Options.Selected for configPath (with
// home standing in for an empty configPath, as `observer init --home`
// resolves it).
func registrationSelected(configPath, home string) func(component string) bool {
	if configPath == "" && home != "" {
		configPath = filepath.Join(home, ".observer", "config.toml")
	}
	return registrationSelectedFor(componentSnapshotFor(configPath))
}

// registrationSelectedFor is registrationSelected over a snapshot.
func registrationSelectedFor(snap componentstate.Snapshot) func(component string) bool {
	return func(component string) bool { return securitySelected(snap, component) }
}
