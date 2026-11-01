//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// sandbox_cred_seam.go holds the call-site seams of credential injection
// for sandboxed runs (lane GATES-SBX, gap G24): nil unless the credentials
// files are compiled (sandbox_cred*.go set them from init), and each
// returns at once while terminals.sandbox.credentials is not selected, so
// the hosted driver and its host helper behave as before.

// hostedCredReady reports whether injection can serve a hosted run's
// home_relay custody on this node (newHostedDriver's homeRelayOK).
var hostedCredReady func(full config.Config) bool

// hostedCredReadyFor applies hostedCredReady (false when unset).
func hostedCredReadyFor(full config.Config) bool {
	return hostedCredReady != nil && hostedCredReady(full)
}

// hostedCredConsentLine is credential injection's text for the consent
// screen's credential line while its component is selected (ok false, or
// nil: the screen's own line stands).
var hostedCredConsentLine func(ctx context.Context, custody, vendor, capture string) (string, bool)

// hostedApplyCredConsent names home_relay injection on the consent screen
// when it is on (audit F8): the credential line becomes injection's own
// disclosure (sandboxcred.Disclosure). The consent record's facts are
// unchanged.
func hostedApplyCredConsent(ctx context.Context, scr *sandboxremote.ConsentScreen, vendor, capture string) {
	if hostedCredConsentLine == nil {
		return
	}
	line, ok := hostedCredConsentLine(ctx, scr.Facts.Custody, vendor, capture)
	if !ok {
		return
	}
	for i := range scr.Lines {
		if scr.Lines[i].Label == "Model credential" {
			scr.Lines[i].Value = line
			return
		}
	}
	scr.Lines = append(scr.Lines, sandboxremote.ConsentLine{Label: "Model credential", Value: line})
}

// hostedCredNotReady names why credential injection cannot serve home_relay
// on this node although its component is selected ("" when it can, or is
// off; nil unless the credentials files are compiled).
var hostedCredNotReady func(full config.Config) string

// hostedCredNotReadyFor applies hostedCredNotReady ("" when unset).
func hostedCredNotReadyFor(full config.Config) string {
	if hostedCredNotReady == nil {
		return ""
	}
	return hostedCredNotReady(full)
}
