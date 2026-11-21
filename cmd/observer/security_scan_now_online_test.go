//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

// The dashboard's online dependency check (decision P-1 of
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md): the scan dialog's
// option state, the matching a manual run builds (one owner for the CLI's
// --online and the dashboard's "Also check online"), and the word the deps
// step's result carries, so a run is never shown as checked online when the
// gate kept it local.

// onlineTestCfg is a config with online checks on or off whose lookup mode
// is local, so the SuperBased lookup's gate is closed and reads nothing.
func onlineTestCfg(on bool) config.Config {
	c := onlineCfg(on)
	c.Security.Deps.Match = lookupLocal
	return c
}

func shownDisclosure() secfeed.Disclosure {
	return secfeed.Disclosure{Version: secfeed.DisclosureVersion, ShownAt: time.Now(), Surface: "dashboard", Verified: true}
}

// TestScanNowOnlineState is the dialog's option, row by row: the online
// gate's own reasons first, then the linked driver; a managed node is
// labelled relay.
func TestScanNowOnlineState(t *testing.T) {
	shown := shownDisclosure()
	cases := []struct {
		name    string
		env     *depsScanEnv
		scalibr bool
		want    dashapi.SecurityScanOnline
	}{
		{
			"online checks off", &depsScanEnv{cfg: onlineTestCfg(false), disclose: shown}, true,
			dashapi.SecurityScanOnline{Step: scanNowDepsID, Reason: "online_checks_off"},
		},
		{
			"disclosure not accepted", &depsScanEnv{cfg: onlineTestCfg(true)}, true,
			dashapi.SecurityScanOnline{Step: scanNowDepsID, Reason: "disclosure_not_shown"},
		},
		{
			"the gate wins over the driver", &depsScanEnv{cfg: onlineTestCfg(false)}, false,
			dashapi.SecurityScanOnline{Step: scanNowDepsID, Reason: "online_checks_off"},
		},
		{
			"open, but only osv-scanner runs", &depsScanEnv{cfg: onlineTestCfg(true), disclose: shown}, false,
			dashapi.SecurityScanOnline{Step: scanNowDepsID, Reason: dashapi.SecurityScanOnlineNeedsSCALIBR},
		},
		{
			"open", &depsScanEnv{cfg: onlineTestCfg(true), disclose: shown}, true,
			dashapi.SecurityScanOnline{Step: scanNowDepsID, Open: true},
		},
		{
			"open on a managed node: the relay", &depsScanEnv{cfg: onlineTestCfg(true), disclose: shown, managed: true}, true,
			dashapi.SecurityScanOnline{Step: scanNowDepsID, Open: true, Relay: true},
		},
	}
	for _, c := range cases {
		if got := scanNowOnlineState(c.env, c.scalibr); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

// TestDepsRunMatchers: online not asked attaches nothing online; asked with
// the gate closed attaches nothing and names the reason (the CLI refuses on
// it, the dashboard says so); asked with the gate open attaches the online
// matcher and, on an individual node only, the git submodule check.
func TestDepsRunMatchers(t *testing.T) {
	shown := shownDisclosure()
	root := t.TempDir()
	cases := []struct {
		name       string
		env        *depsScanEnv
		online     bool
		blocked    string
		direct     bool
		submodules bool
	}{
		{"not asked", &depsScanEnv{cfg: onlineTestCfg(true), disclose: shown}, false, "", false, false},
		{"asked, online checks off", &depsScanEnv{cfg: onlineTestCfg(false), disclose: shown}, true, "online_checks_off", false, false},
		{"asked, disclosure not accepted", &depsScanEnv{cfg: onlineTestCfg(true)}, true, "disclosure_not_shown", false, false},
		{"asked, open", &depsScanEnv{cfg: onlineTestCfg(true), disclose: shown}, true, "", true, true},
		{"asked, open, managed: relay only", &depsScanEnv{cfg: onlineTestCfg(true), disclose: shown, managed: true}, true, "", true, false},
	}
	for _, c := range cases {
		run := c.env.depsRunMatchers(root, c.online)
		if run.blocked != c.blocked || run.direct != c.direct || (run.matcher != nil) != c.direct || (c.env.submodules != nil) != c.submodules {
			t.Errorf("%s: blocked %q direct %v matcher %v submodules %v; want %q %v %v",
				c.name, run.blocked, run.direct, run.matcher != nil, c.env.submodules != nil, c.blocked, c.direct, c.submodules)
		}
	}
}

// TestScanNowOnlineNote is the deps step result's online word, row by row.
func TestScanNowOnlineNote(t *testing.T) {
	cases := []struct {
		name    string
		asked   bool
		run     depsRunOnline
		scalibr bool
		want    string
	}{
		{"not asked", false, depsRunOnline{direct: true}, true, ""},
		{"not asked, gate closed", false, depsRunOnline{blocked: "online_checks_off"}, true, ""},
		{"the project forbids it", true, depsRunOnline{blocked: "online_checks_off"}, true, "online_checks_off"},
		{"disclosure", true, depsRunOnline{blocked: "disclosure_not_shown"}, false, "disclosure_not_shown"},
		{"only osv-scanner ran", true, depsRunOnline{direct: true}, false, dashapi.SecurityScanOnlineNeedsSCALIBR},
		{"no matcher built", true, depsRunOnline{}, true, dashapi.SecurityScanOnlineUnavailable},
		{"checked", true, depsRunOnline{direct: true}, true, dashapi.SecurityScanOnlineChecked},
	}
	for _, c := range cases {
		if got := scanNowOnlineNote(c.asked, c.run, c.scalibr); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
