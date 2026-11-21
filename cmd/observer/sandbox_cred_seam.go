//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxkey"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_cred_seam.go holds the call-site seams of credential injection
// for sandboxed runs (lane GATES-SBX, gap G24): nil unless the credentials
// files are compiled (sandbox_cred*.go set them from init), and each
// returns at once while terminals.sandbox.credentials is not selected, so
// the hosted driver and its host helper behave as before.

// hostedCredConsentLine is credential injection's text for the consent
// screen's credential line while its component is selected (ok false, or
// nil: the screen's own line stands).
var hostedCredConsentLine func(ctx context.Context, custody, vendor, capture string) (string, bool)

// hostedCredInBoxStored are the providers whose stored key an in-box
// custody may put in a box where the daemon's environment has none (nil
// without the credentials files, or while the component is off).
var hostedCredInBoxStored func(ctx context.Context) []string

// hostedApplyCredConsent names home_relay injection on the consent screen
// when it is on (audit F8): the credential line becomes injection's own
// disclosure (sandboxkey.Disclosure), naming each key a run may bind. For
// an in-box API key the line names, by provider, where each key the box
// would get comes from (gap H3): this machine's environment, or a key the
// person stored. The consent record's facts are unchanged.
func hostedApplyCredConsent(ctx context.Context, scr *sandboxremote.ConsentScreen, vendor, capture string) {
	line, ok := "", false
	// The custody fact is the node's value, then any per-tool values
	// ("auto; droid=in_box_api_key", hostedConsentCustody).
	node, perTool, _ := strings.Cut(scr.Facts.Custody, "; ")
	var stored []string
	if hostedCredInBoxStored != nil {
		stored = hostedCredInBoxStored(ctx)
	}
	switch {
	case vocab.KeyCustody(node) == vocab.CustodyInBoxAPIKey:
		line, ok = sandboxkey.InBoxDisclosure(hostedInBoxEnvProviders(), stored), true
	case vocab.KeyCustody(node) == vocab.CustodyAuto:
		// Decision SBXD-1: the rule once, then where an in-box key would
		// come from (decision SBXD-3: the stored keys that can enter the
		// box are bound in the consent's facts).
		line, ok = sandboxkey.Disclosure(node, vendor, capture, stored...)+" When the key is put in the box: "+sandboxkey.InBoxDisclosure(hostedInBoxEnvProviders(), stored)+".", true
	case hostedCredConsentLine != nil:
		line, ok = hostedCredConsentLine(ctx, node, vendor, capture)
	}
	if extra := hostedConsentPerToolLine(perTool) + hostedConsentOptInLine(scr.Facts); extra != "" {
		if !ok {
			line, ok = scr.Facts.Custody, true
			for _, l := range scr.Lines {
				if l.Label == "Model credential" {
					line = l.Value
				}
			}
		}
		line += extra
	}
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

// hostedConsentPerToolLine says, in plain words, the per-tool custody
// values the consent binds (perTool is "droid=in_box_api_key,...").
func hostedConsentPerToolLine(perTool string) string {
	if perTool == "" {
		return ""
	}
	words := map[string]string{
		string(vocab.CustodyAuto):        "chosen per launch by the rule above",
		string(vocab.CustodyHomeRelay):   "the key always stays on this machine",
		string(vocab.CustodyInBoxAPIKey): "the API key is always put in the box",
	}
	var parts []string
	for _, kv := range strings.Split(perTool, ",") {
		tool, c, _ := strings.Cut(kv, "=")
		w, ok := words[c]
		if !ok {
			w = c
		}
		parts = append(parts, integration.DisplayName(tool)+": "+w)
	}
	return " Set for these agents in your settings: " + strings.Join(parts, "; ") + "."
}

// hostedConsentOptInLine names the opted-in in-box key sources the consent
// binds (decision SBXD-4), by tool name.
func hostedConsentOptInLine(f sandboxremote.ConsentFacts) string {
	names := func(ids string) []string {
		if ids == "" {
			return nil
		}
		var out []string
		for _, t := range strings.Split(ids, ",") {
			out = append(out, integration.DisplayName(t))
		}
		return out
	}
	if s := sandboxkey.OptInDisclosure(names(f.ToolKeys), names(f.LoginSeed)); s != "" {
		return " " + s
	}
	return ""
}

// hostedConsentKeyFactsNow is hostedConsentKeyFacts for a consent screen
// built outside a driver: the stored provider ids through the credentials
// seam (nil while the component is off, as the host helper reads them).
func hostedConsentKeyFactsNow(ctx context.Context, hc config.TerminalSandboxHostedConfig, inBoxRefused bool) (inBoxKeys, toolKeys, loginSeed string) {
	var stored []string
	if hostedCredInBoxStored != nil {
		stored = hostedCredInBoxStored(ctx)
	}
	return hostedConsentKeyFacts(hc, len(stored) > 0, stored, inBoxRefused)
}

// hostedCredFacts reads, without opening a key, what credential injection
// offers on this node: whether its component is selected, whether this
// build has the proxy that swaps the sentinel, and which providers have a
// stored key (ids only). Nil unless the credentials files are compiled.
var hostedCredFacts func(full config.Config) (selected, built bool, providers []string)
