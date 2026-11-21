package policy

import (
	"testing"
	"time"
)

// TestSelfApprovalSandboxSetupRoutes (lane sbxinstall-guard, PT-89, plan
// sandbox-installation-lifecycle section 8, ledger SBXSETUP-1): the sandbox
// setup routes install, turn on and probe sandbox backends on the person's
// click, and the hosted connect route stores a provider key (ruling R5). An
// agent's write to any of them is denied by R-165 under enforce and flagged
// under observe, from curl, wget, httpie and PowerShell alike; the GET forms
// (the summary, a backend's plan, an op's progress) are reads.
func TestSelfApprovalSandboxSetupRoutes(t *testing.T) {
	t.Parallel()
	const base = "http://127.0.0.1:8821"
	cases := []coreRuleCase{
		// The run route, every client.
		sh("curl POST run", `curl -X POST -H 'X-Observer-Confirm: t' -H 'Content-Type: application/json' -d '{"step":"bwrap.package","action":"run","fingerprint":"f"}' `+base+`/api/terminal/sandbox/setup/bwrap/run`, "R-165", DecisionDeny),
		sh("curl -d implies POST on run", `curl -d '{"step":"bwrap.package","action":"undo"}' `+base+`/api/terminal/sandbox/setup/bwrap/run`, "R-165", DecisionDeny),
		sh("curl POST run on localhost", `curl -X POST -d '{}' http://localhost:8821/api/terminal/sandbox/setup/cloud-hypervisor/run`, "R-165", DecisionDeny),
		sh("wget --post-data run", `wget --post-data='{"step":"chv.download","action":"run"}' `+base+`/api/terminal/sandbox/setup/cloud-hypervisor/run`, "R-165", DecisionDeny),
		sh("wget --method POST run", `wget --method=POST --body-data='{"action":"repair"}' `+base+`/api/terminal/sandbox/setup/bwrap/run`, "R-165", DecisionDeny),
		sh("httpie POST run", `http POST 127.0.0.1:8821/api/terminal/sandbox/setup/bwrap/run step=bwrap.package action=update`, "R-165", DecisionDeny),
		ps("Invoke-WebRequest POST run", `Invoke-WebRequest -Method Post -Uri `+base+`/api/terminal/sandbox/setup/docker/run -Body '{"action":"run"}'`, "R-165", DecisionDeny),
		ps("Invoke-RestMethod POST run", `Invoke-RestMethod -Method Post -Uri `+base+`/api/terminal/sandbox/setup/bwrap/run -Body '{"action":"run"}'`, "R-165", DecisionDeny),
		// The check route (an active probe on the person's click, ruling R1).
		sh("curl POST check", `curl -X POST -H 'X-Observer-Confirm: t' -d '{}' `+base+`/api/terminal/sandbox/setup/bwrap/check`, "R-165", DecisionDeny),
		sh("wget --post-data check", `wget --post-data='{}' `+base+`/api/terminal/sandbox/setup/bwrap/check`, "R-165", DecisionDeny),
		sh("httpie POST check", `http POST 127.0.0.1:8821/api/terminal/sandbox/setup/gvisor/check`, "R-165", DecisionDeny),
		ps("Invoke-WebRequest POST check", `Invoke-WebRequest -Method Post -Uri `+base+`/api/terminal/sandbox/setup/bwrap/check -Body '{}'`, "R-165", DecisionDeny),
		// A write to the collection or an op is matched too (deny-biased).
		sh("curl POST the summary path", `curl -X POST -d '{}' `+base+`/api/terminal/sandbox/setup`, "R-165", DecisionDeny),
		// The hosted connect route (ruling R5).
		sh("curl POST hosted connect", `curl -X POST -H 'X-Observer-Confirm: t' -d '{"provider":"e2b","key":"k"}' `+base+`/api/terminal/sandbox/hosted/connect`, "R-165", DecisionDeny),
		sh("wget --post-data hosted connect", `wget --post-data='{"provider":"modal"}' `+base+`/api/terminal/sandbox/hosted/connect`, "R-165", DecisionDeny),
		sh("httpie POST hosted connect", `http POST 127.0.0.1:8821/api/terminal/sandbox/hosted/connect provider=e2b key=k`, "R-165", DecisionDeny),
		ps("Invoke-WebRequest POST hosted connect", `Invoke-WebRequest -Method Post -Uri `+base+`/api/terminal/sandbox/hosted/connect -Body '{"provider":"e2b"}'`, "R-165", DecisionDeny),
		// The reads.
		sh("GET the summary is a read", `curl `+base+`/api/terminal/sandbox/setup`, "", 0),
		sh("GET a backend's plan is a read", `curl -s `+base+`/api/terminal/sandbox/setup/bwrap`, "", 0),
		sh("GET an op is a read", `curl `+base+`/api/terminal/sandbox/setup/op/op0001`, "", 0),
		sh("wget GET a plan is a read", `wget -qO- `+base+`/api/terminal/sandbox/setup/bwrap`, "", 0),
		sh("httpie GET an op is a read", `http GET 127.0.0.1:8821/api/terminal/sandbox/setup/op/op0001`, "", 0),
		ps("Invoke-WebRequest GET the summary is a read", `Invoke-WebRequest -Uri `+base+`/api/terminal/sandbox/setup`, "", 0),
		sh("GET the hosted state is a read", `curl `+base+`/api/terminal/sandbox/hosted`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}

// TestSelfApprovalToolInstallRoutes (ruling R2, PT-89, ledger
// TOOLINSTALL-GUARD-1): the guided install, uninstall and record-forget
// routes of AI tools had no guard row, and their double-submit confirm pair
// can be minted by a local process. An agent's write is now denied by R-165
// under enforce and flagged under observe; the GET list of records is a
// read.
func TestSelfApprovalToolInstallRoutes(t *testing.T) {
	t.Parallel()
	const base = "http://127.0.0.1:8821"
	cases := []coreRuleCase{
		sh("curl POST install", `curl -X POST -H 'X-Observer-Confirm: t' -d '{"tool":"codex"}' `+base+`/api/terminal/install`, "R-165", DecisionDeny),
		sh("wget --post-data install", `wget --post-data='{"tool":"codex"}' `+base+`/api/terminal/install`, "R-165", DecisionDeny),
		sh("httpie POST install", `http POST 127.0.0.1:8821/api/terminal/install tool=codex`, "R-165", DecisionDeny),
		ps("Invoke-WebRequest POST install", `Invoke-WebRequest -Method Post -Uri `+base+`/api/terminal/install -Body '{"tool":"codex"}'`, "R-165", DecisionDeny),
		sh("curl POST uninstall", `curl -X POST -d '{"tool":"codex"}' `+base+`/api/terminal/uninstall`, "R-165", DecisionDeny),
		sh("wget --post-data uninstall", `wget --post-data='{"tool":"codex"}' `+base+`/api/terminal/uninstall`, "R-165", DecisionDeny),
		sh("httpie POST uninstall", `http POST localhost:8821/api/terminal/uninstall tool=codex`, "R-165", DecisionDeny),
		ps("Invoke-RestMethod POST uninstall", `Invoke-RestMethod -Method Post -Uri `+base+`/api/terminal/uninstall -Body '{"tool":"codex"}'`, "R-165", DecisionDeny),
		sh("curl POST forget", `curl -X POST -d '{"id":7}' `+base+`/api/terminal/installs/forget`, "R-165", DecisionDeny),
		sh("wget --post-data forget", `wget --post-data='{"id":7}' `+base+`/api/terminal/installs/forget`, "R-165", DecisionDeny),
		sh("httpie POST forget", `http POST 127.0.0.1:8821/api/terminal/installs/forget id:=7`, "R-165", DecisionDeny),
		ps("Invoke-WebRequest POST forget", `Invoke-WebRequest -Method Post -Uri `+base+`/api/terminal/installs/forget -Body '{"id":7}'`, "R-165", DecisionDeny),
		sh("GET the records is a read", `curl `+base+`/api/terminal/installs`, "", 0),
		ps("Invoke-WebRequest GET the records is a read", `Invoke-WebRequest -Uri `+base+`/api/terminal/installs`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}

// TestSelfApprovalSandboxSetupVerbs (lane sbxinstall-guard, PT-89, ledger
// SBXSETUP-1): `observer sandbox setup run|undo|update|repair` and `sandbox
// hosted connect` are the person's; an agent's run is denied by R-165 under
// enforce and flagged under observe, typed directly, through npx, pipx or
// uvx, from PowerShell, and with flags before or between the subcommand
// words. `status` and `records` only print.
func TestSelfApprovalSandboxSetupVerbs(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		sh("setup run", `observer sandbox setup run bwrap`, "R-165", DecisionDeny),
		sh("setup run --step --yes", `observer sandbox setup run bwrap --step bwrap.package --yes`, "R-165", DecisionDeny),
		sh("setup run --from-file", `observer sandbox setup run cloud-hypervisor --step chv.download --from-file /tmp/cloud-hypervisor-static`, "R-165", DecisionDeny),
		sh("setup run --from-file=", `observer sandbox setup run cloud-hypervisor --from-file=/tmp/chv --yes`, "R-165", DecisionDeny),
		sh("setup undo", `observer sandbox setup undo bwrap --step bwrap.enable --yes`, "R-165", DecisionDeny),
		sh("setup update", `observer sandbox setup update cloud-hypervisor --step chv.download`, "R-165", DecisionDeny),
		sh("setup repair", `observer sandbox setup repair bwrap --step bwrap.package`, "R-165", DecisionDeny),
		sh("hosted connect", `observer sandbox hosted connect e2b`, "R-165", DecisionDeny),
		sh("hosted connect piped", `echo k | observer sandbox hosted connect modal`, "R-165", DecisionDeny),
		sh("setup run via npx", `npx @superbased/observer sandbox setup run bwrap --yes`, "R-165", DecisionDeny),
		sh("setup run via npx -y, versioned", `npx -y @superbased/observer@1.40.0 sandbox setup run bwrap`, "R-165", DecisionDeny),
		sh("setup undo via npm exec", `npm exec @superbased/observer sandbox setup undo bwrap --step bwrap.enable`, "R-165", DecisionDeny),
		sh("setup update via pipx", `pipx run superbased-observer sandbox setup update cloud-hypervisor --step chv.download`, "R-165", DecisionDeny),
		sh("setup repair via uvx", `uvx superbased-observer sandbox setup repair bwrap --step bwrap.package`, "R-165", DecisionDeny),
		sh("hosted connect via pipx", `pipx run superbased-observer sandbox hosted connect e2b`, "R-165", DecisionDeny),
		sh("binary by path", `/opt/observer/bin/observer sandbox setup run bwrap`, "R-165", DecisionDeny),
		sh("config flag first", `observer --config /tmp/c.toml sandbox setup run bwrap`, "R-165", DecisionDeny),
		sh("flags before: setup run (OSH-141)", `observer sandbox setup --step bwrap.package run bwrap`, "R-165", DecisionDeny),
		sh("flags between groups: setup run", `observer sandbox --x y setup run bwrap`, "R-165", DecisionDeny),
		sh("flags before: hosted connect", `observer sandbox hosted --config c.toml connect e2b`, "R-165", DecisionDeny),
		ps("PowerShell setup run", `observer sandbox setup run bwrap --yes`, "R-165", DecisionDeny),
		ps("PowerShell call operator setup run", `& 'C:\Program Files\observer\observer.exe' sandbox setup run hcs --step hcs.features`, "R-165", DecisionDeny),
		ps("PowerShell npx setup repair", `npx @superbased/observer sandbox setup repair mxc --step mxc.content`, "R-165", DecisionDeny),
		// The reads.
		sh("setup status is a read", `observer sandbox setup status`, "", 0),
		sh("setup status of a backend is a read", `observer sandbox setup status bwrap --json`, "", 0),
		sh("setup records is a read", `observer sandbox setup records --json`, "", 0),
		sh("setup alone is help", `observer sandbox setup`, "", 0),
		sh("setup status via npx is a read", `npx @superbased/observer sandbox setup status`, "", 0),
		sh("setup records via pipx is a read", `pipx run superbased-observer sandbox setup records`, "", 0),
		sh("hosted status is a read", `observer sandbox hosted status`, "", 0),
		sh("hosted disconnect only removes the key", `observer sandbox hosted disconnect e2b`, "", 0),
		sh("npx of another package", `npx other-tool sandbox setup run bwrap`, "", 0),
		sh("a word in a message is not a run", `echo "observer sandbox setup run bwrap"`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}

// TestSelfApprovalSandboxSetupCheckAsks (ruling R1, PT-89, ledger
// SBXSETUP-3): `observer sandbox setup check` runs a sandbox driver's probe
// on this machine, which only the person's word allows, so an agent's run is
// asked about by R-165 in BOTH modes (the consentAskVerbs shape), typed
// directly or through a package runner, with or without --json; `status`
// and `records` are not.
func TestSelfApprovalSandboxSetupCheckAsks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, line string
		hit        bool
	}{
		{name: "check", line: `observer sandbox setup check bwrap`, hit: true},
		{name: "check --json", line: `observer sandbox setup check bwrap --json`, hit: true},
		{name: "check via npx", line: `npx @superbased/observer sandbox setup check cloud-hypervisor`, hit: true},
		{name: "check via pipx", line: `pipx run superbased-observer sandbox setup check gvisor`, hit: true},
		{name: "check via uvx", line: `uvx superbased-observer sandbox setup check docker --json`, hit: true},
		{name: "check, config flag first", line: `observer --config /tmp/c.toml sandbox setup check bwrap`, hit: true},
		{name: "flags before: check (OSH-141)", line: `observer sandbox setup --x y check bwrap`, hit: true},
		{name: "status is a read", line: `observer sandbox setup status bwrap`},
		{name: "records is a read", line: `observer sandbox setup records`},
		{name: "npx of another package", line: `npx other-tool sandbox setup check bwrap`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const home, root = "/home/u", "/home/u/proj"
			ev := Event{
				Kind: KindShellExec, Target: tc.line,
				Cwd: root, ProjectRoot: root, SessionID: "s1",
				Now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC),
			}
			for _, mode := range []Mode{ModeObserve, ModeEnforce} {
				e, err := New(Config{Mode: mode, Home: home})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				v := e.Evaluate(ev)
				switch {
				case tc.hit && (v.RuleID != "R-165" || v.Decision != DecisionAsk):
					t.Fatalf("%s: want R-165 ask, got %q %s (%q)", mode, v.RuleID, v.Decision, v.Reason)
				case !tc.hit && v.RuleID == "R-165":
					t.Fatalf("%s: want no R-165 hit, got %s (%q)", mode, v.Decision, v.Reason)
				}
			}
		})
	}
}
