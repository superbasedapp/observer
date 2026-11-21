package policy

import "testing"

// TestSelfApprovalGuardRecipes pins the guard recipe rows of R-165 (plan
// docs/plans/profile-guard-recipes-repo-grouping-plan-2026-11-07.md section
// 3): applying, removing, saving and deleting a recipe are the person's
// actions, through the CLI and through the dashboard routes. The catalog,
// show, preview and an explicit dry run stay allowed.
func TestSelfApprovalGuardRecipes(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		// The CLI verbs.
		sh("recipe apply", `observer guard recipe apply --level strict --pack networking --yes`, "R-165", DecisionDeny),
		sh("recipe apply to a project", `observer guard recipe apply --pack frontend --project . --yes`, "R-165", DecisionDeny),
		sh("recipe apply without --yes still matches", `observer guard recipe apply --level none`, "R-165", DecisionDeny),
		sh("recipe apply --dry-run=false matches", `observer guard recipe apply --level none --dry-run=false`, "R-165", DecisionDeny),
		sh("recipe apply through npx", `npx -y @superbased/observer guard recipe apply --level loose --yes`, "R-165", DecisionDeny),
		sh("recipe remove", `observer guard recipe remove --yes`, "R-165", DecisionDeny),
		sh("recipe remove in a project", `observer guard recipe remove --project /work/app --yes`, "R-165", DecisionDeny),
		sh("recipe save", `observer guard recipe save my-strict --file my-strict.toml`, "R-165", DecisionDeny),
		sh("recipe delete", `observer guard recipe delete my-strict`, "R-165", DecisionDeny),
		sh("recipe apply --dry-run is a read", `observer guard recipe apply --level lockdown --dry-run`, "", 0),
		sh("recipe remove --dry-run is a read", `observer guard recipe remove --dry-run`, "", 0),
		sh("recipe list is a read", `observer guard recipe list --json`, "", 0),
		sh("recipe show is a read", `observer guard recipe show strict --toml`, "", 0),
		// The dashboard routes: every write matches, the GETs are reads.
		sh("POST a recipe apply", `curl -X POST -H 'X-Observer-Confirm: t' -H 'Content-Type: application/json' http://127.0.0.1:8821/api/guard/recipes/apply -d '{"level":"none","scope":"global"}'`, "R-165", DecisionDeny),
		sh("POST a recipe remove", `curl -X POST http://127.0.0.1:8821/api/guard/recipes/remove -d '{"scope":"global"}'`, "R-165", DecisionDeny),
		sh("POST a user recipe", `curl -X POST http://localhost:8821/api/guard/recipes/user -d '{"name":"mine","toml":"name = \"mine\""}'`, "R-165", DecisionDeny),
		sh("POST a user recipe delete", `curl -X POST http://localhost:8821/api/guard/recipes/user/delete -d '{"name":"mine"}'`, "R-165", DecisionDeny),
		sh("GET the recipe catalog is a read", `curl http://127.0.0.1:8821/api/guard/recipes`, "", 0),
		sh("GET a recipe preview is a read", `curl 'http://127.0.0.1:8821/api/guard/recipes/preview?level=strict&scope=global'`, "", 0),
		sh("GET a recipe replay is a read", `curl 'http://127.0.0.1:8821/api/guard/simulate?hours=168&recipe=1&level=strict'`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}

// TestSelfApprovalLoopbackHostSpellings (sweep finding UI-1): the dashboard
// answers a request whose host is any spelling of this machine (an
// IPv4-mapped IPv6 literal, an inet_aton number, a name under .localhost),
// so R-165 must read every such spelling as loopback. A numeric host that
// is not a plain dotted quad fails closed, and a loopback Host header,
// --resolve or --connect-to makes any URL a loopback target.
func TestSelfApprovalLoopbackHostSpellings(t *testing.T) {
	t.Parallel()
	const post = `curl -X POST -H 'X-Observer-Confirm: a' -b 'sb_remote_confirm=a' -H 'Content-Type: application/json' -d '{"level":"none","scope":"global"}' `
	cases := []coreRuleCase{
		sh("IPv4-mapped IPv6, dotted", post+`'http://[::ffff:127.0.0.1]:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("IPv4-mapped IPv6, hex", post+`'http://[::ffff:7f00:1]:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("IPv4-mapped IPv6, long form", post+`'http://[0:0:0:0:0:ffff:7f00:1]:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("IPv6 unspecified", post+`'http://[::]:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("IPv6 loopback with a zone", post+`'http://[::1%25lo]:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("decimal integer host", post+`'http://2130706433:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("decimal integer host with a Host header", post+`-H 'Host: 127.0.0.1:8820' 'http://2130706433:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("hex integer host", post+`'http://0x7f000001:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("octal dotted host", post+`'http://0177.0.0.1:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("short dotted host", post+`'http://127.1:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("0.0.0.0 short form", post+`'http://0:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("numeric host that is not a plain quad fails closed", post+`'http://3232235777:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("five-part numeric host fails closed", post+`'http://1.2.3.4.5:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("a name under .localhost", post+`'http://observer.localhost:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("localhost with a trailing dot", post+`'http://localhost.:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("loopback quad with a trailing dot", post+`'http://127.0.0.1.:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("userinfo with two at signs", post+`'http://a@b@127.0.0.1:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("percent-encoded host", post+`'http://%31%32%37.0.0.1:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("full-width host", post+"'http://\uff4c\uff4f\uff43\uff41\uff4c\uff48\uff4f\uff53\uff54:8820/api/guard/recipes/apply'", "R-165", DecisionDeny),
		sh("a remote name with a loopback Host header", post+`-H 'Host: localhost:8820' 'http://sbo.example.test:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("a remote name with an attached Host header", post+`'-HHost: 127.0.0.1' 'http://sbo.example.test:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("--resolve onto loopback", post+`--resolve sbo.example.test:8820:127.0.0.1 'http://sbo.example.test:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("--resolve onto IPv6 loopback", post+`--resolve 'sbo.example.test:8820:[::1]' 'http://sbo.example.test:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("--connect-to onto loopback", post+`--connect-to sbo.example.test:8820:127.0.0.1:8820 'http://sbo.example.test:8820/api/guard/recipes/apply'`, "R-165", DecisionDeny),
		sh("wget with a loopback Host header", `wget --post-data '{}' --header='Host: 127.0.0.1' http://sbo.example.test:8820/api/guard/recipes/apply`, "R-165", DecisionDeny),
		// The same gap on the other R-165 route rows.
		sh("policy editor through a mapped host", `curl -X PUT -d '{}' 'http://[::ffff:127.0.0.1]:8820/api/guard/policy'`, "R-165", DecisionDeny),
		sh("launch policy through an integer host", `curl -X PUT -d '{"allow_fresh_agent":true}' http://2130706433:8820/api/terminal/policy`, "R-165", DecisionDeny),
		// Still not loopback.
		sh("a plain public quad is remote", post+`'http://93.184.216.34:8820/api/guard/recipes/apply'`, "", 0),
		sh("a private plain quad is remote", post+`'http://192.168.1.10:8820/api/guard/recipes/apply'`, "", 0),
		sh("a remote name is remote", post+`'https://sbo.example.test/api/guard/recipes/apply'`, "", 0),
		sh("a remote Host header on a remote name", post+`-H 'Host: sbo.example.test' 'https://sbo.example.test/api/guard/recipes/apply'`, "", 0),
		sh("--resolve onto a remote address", post+`--resolve sbo.example.test:443:93.184.216.34 'https://sbo.example.test/api/guard/recipes/apply'`, "", 0),
		sh("a mapped host GET is a read", `curl 'http://[::ffff:127.0.0.1]:8820/api/guard/recipes'`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}

// TestLoopbackHostRows is one case per loopbackHostRows row (and the
// fall-through), with each row's reason named.
func TestLoopbackHostRows(t *testing.T) {
	t.Parallel()
	for _, row := range loopbackHostRows {
		if row.why == "" {
			t.Errorf("a loopback host row has no reason")
		}
	}
	cases := []struct {
		host string
		want bool
	}{
		{"", false},                       // no host
		{"ｌｏｃａｌｈｏｓｔ", true},               // non-ASCII fails closed
		{"localhost", true},               // localhost
		{"api.localhost:8820", true},      // *.localhost
		{"localhost.", true},              // trailing dot removed first
		{"127.0.0.1", true},               // IP literal, loopback
		{"127.9.9.9:80", true},            // any 127/8
		{"[::1]", true},                   // IPv6 loopback
		{"[::ffff:127.0.0.1]:8820", true}, // mapped, dotted
		{"[::ffff:7f00:1]", true},         // mapped, hex
		{"0.0.0.0", true},                 // unspecified
		{"[::]", true},                    // IPv6 unspecified
		{"2130706433", true},              // inet_aton integer
		{"0x7f.1", true},                  // inet_aton hex short form
		{"[fe80::1", true},                // an unclosed bracket fails closed
		{"[not-an-ip]", true},             // a bracketed literal that does not parse
		{"3232235777", true},              // numeric, not a plain quad: fails closed
		{"0300.0250.1.1", true},           // octal quad: fails closed
		{"192.168.1.1", false},            // plain private quad
		{"93.184.216.34:443", false},      // plain public quad
		{"[2001:db8::1]", false},          // a public IPv6 literal
		{"example.com", false},            // a name
		{"localhost.example.com", false},  // a name that only starts with localhost
		{"1e100.net", false},              // a name with a numeric-looking label
	}
	for _, tc := range cases {
		if got := loopbackHost(tc.host); got != tc.want {
			t.Errorf("loopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestIntegrityFollowersAreIntegrityRules pins the CFG-1 table: every row
// is an integrity rule and says why it follows.
func TestIntegrityFollowersAreIntegrityRules(t *testing.T) {
	t.Parallel()
	for _, f := range integrityFollowers {
		if !IsIntegrityRuleID(f.id) || f.why == "" {
			t.Errorf("integrity follower %q (%q): not an integrity rule, or no reason", f.id, f.why)
		}
	}
}

// TestSelfApprovalInlineHTTP (sweep finding SA-4): an interpreter one-liner
// or inline script that names a loopback URL of a guard route (the route
// table R-165's HTTP row uses) is judged as that request: program text does
// not show the method, so naming the route is judged as writing to it.
func TestSelfApprovalInlineHTTP(t *testing.T) {
	t.Parallel()
	ps := func(name, line string) coreRuleCase {
		return coreRuleCase{name: name, kind: KindShellExec, target: line, dialect: DialectPowerShell, wantRule: "R-165", wantEnforce: DecisionDeny}
	}
	heredoc := "python3 - <<'PY'\nimport requests\nrequests.post('http://127.0.0.1:8820/api/guard/recipes/remove', json={'scope':'global'})\nPY"
	cases := []coreRuleCase{
		sh("python urllib", `python3 -c "import urllib.request as u; u.urlopen(u.Request('http://127.0.0.1:8820/api/guard/recipes/apply', data=b'{}', method='POST'))"`, "R-165", DecisionDeny),
		sh("node fetch", `node -e "fetch('http://127.0.0.1:8820/api/guard/recipes/apply',{method:'POST'})"`, "R-165", DecisionDeny),
		sh("ruby net/http", `ruby -e "require 'net/http'; Net::HTTP.post(URI('http://localhost:8820/api/guard/policy'), '{}')"`, "R-165", DecisionDeny),
		sh("perl LWP", `perl -MLWP::UserAgent -e 'LWP::UserAgent->new->post("http://127.0.0.1:8820/api/guard/approvals", Content => "{}")'`, "R-165", DecisionDeny),
		sh("python heredoc", heredoc, "R-165", DecisionDeny),
		sh("piped into node", `echo "fetch('http://127.0.0.1:8820/api/guard/recipes/apply',{method:'POST'})" | node`, "R-165", DecisionDeny),
		sh("host and path in separate literals", `python3 -c "import http.client as h; c=h.HTTPConnection('127.0.0.1', 8820); c.request('POST', '/api/guard/recipes/apply', '{}')"`, "R-165", DecisionDeny),
		sh("base URL and path concatenated", `node -e "const b='http://localhost:8820'; fetch(b + '/api/guard/policy', {method:'PUT'})"`, "R-165", DecisionDeny),
		sh("a mapped IPv6 host in program text", `python3 -c "import urllib.request as u; u.urlopen(u.Request('http://[::ffff:127.0.0.1]:8820/api/guard/recipes/apply', data=b'{}'))"`, "R-165", DecisionDeny),
		ps("PowerShell WebClient", `[System.Net.WebClient]::new().UploadString('http://127.0.0.1:8820/api/guard/recipes/apply', '{}')`),
		ps("pwsh -Command with HttpClient", `pwsh -Command "[System.Net.Http.HttpClient]::new().PostAsync('http://127.0.0.1:8820/api/guard/policy', $null)"`),
		// Not a guard route, or not loopback.
		sh("python to another loopback route", `python3 -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8820/api/sessions')"`, "", 0),
		sh("python to a remote host", `python3 -c "import urllib.request as u; u.urlopen(u.Request('https://example.com/api/guard/policy', data=b'{}'))"`, "", 0),
		sh("a route path with no loopback host named", `python3 -c "print('/api/guard/policy')"`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}

// TestSelfApprovalRecipeValueFlags (sweep finding CFG-10): the recipe
// verbs' value flags take the next word, so a --dry-run after one of them is
// its value, not the preview.
func TestSelfApprovalRecipeValueFlags(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		sh("--pack takes --dry-run as its value", `observer guard recipe apply --level none --pack --dry-run`, "R-165", DecisionDeny),
		sh("--level takes --dry-run as its value", `observer guard recipe apply --level --dry-run --yes`, "R-165", DecisionDeny),
		sh("--replay takes --dry-run as its value", `observer guard recipe apply --level none --replay --dry-run`, "R-165", DecisionDeny),
		sh("--file takes --dry-run as its value", `observer guard recipe remove --file --dry-run`, "R-165", DecisionDeny),
		sh("--project takes --dry-run as its value", `observer guard recipe remove --project --dry-run --yes`, "R-165", DecisionDeny),
		sh("a real dry run after the values is a read", `observer guard recipe apply --level none --pack networking --replay 168h --dry-run`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}

// TestSelfApprovalHookRemoval (sweep finding SA-2): removing the gate hooks
// from the AI tools switches every rule off for them, so the uninstall
// verbs, a component change or teardown naming integration.hooks or an
// adapter, the setup wizard's hooks undo and the [observer.hooks] keys are
// R-165's. An explicit dry run stays a read.
func TestSelfApprovalHookRemoval(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		sh("uninstall one tool", `observer uninstall --claude-code`, "R-165", DecisionDeny),
		sh("uninstall all", `observer uninstall --all`, "R-165", DecisionDeny),
		sh("uninstall through npx", `npx -y @superbased/observer uninstall --all --purge`, "R-165", DecisionDeny),
		sh("uninstall --dry-run=false", `observer uninstall --all --dry-run=false`, "R-165", DecisionDeny),
		sh("setup uninstall", `observer setup uninstall --stop-daemon`, "R-165", DecisionDeny),
		sh("components remove integration.hooks", `observer components remove integration.hooks --yes`, "R-165", DecisionDeny),
		sh("components remove an adapter", `observer components remove adapter.claude-code --yes`, "R-165", DecisionDeny),
		sh("components teardown integration.hooks", `observer components teardown integration.hooks`, "R-165", DecisionDeny),
		sh("components teardown an adapter", `observer components teardown adapter.codex`, "R-165", DecisionDeny),
		sh("POST setup hooks undo", `curl -X POST -H 'X-Observer-Confirm: t' http://127.0.0.1:8820/api/setup/hooks -d '{"tool":"claude-code","undo":true}'`, "R-165", DecisionDeny),
		sh("POST setup hooks undo from a file", `curl -X POST http://127.0.0.1:8820/api/setup/hooks -d @undo.json`, "R-165", DecisionDeny),
		sh("POST components apply removing hooks", `curl -X POST http://127.0.0.1:8820/api/components/apply -d '{"change":{"remove":["integration.hooks"]}}'`, "R-165", DecisionDeny),
		sh("POST components apply removing an adapter", `curl -X POST http://127.0.0.1:8820/api/components/apply -d '{"change":{"remove":["adapter.cursor"]}}'`, "R-165", DecisionDeny),
		sh("POST components teardown of hooks", `curl -X POST http://127.0.0.1:8820/api/components/teardown -d '{"ids":["integration.hooks"]}'`, "R-165", DecisionDeny),
		sh("config set auto_register", `observer config set observer.hooks.auto_register false`, "R-165", DecisionDeny),
		sh("config set periodic_register", `observer config set observer.hooks.periodic_register off`, "R-165", DecisionDeny),
		sh("PUT config keys auto_register", `curl -X PUT http://127.0.0.1:8820/api/config/keys -d '{"patches":[{"key":"observer.hooks.auto_register","value":false}]}'`, "R-165", DecisionDeny),
		sh("PUT the observer section's hooks", `curl -X PUT http://127.0.0.1:8820/api/config/section/observer -d '{"Hooks":{"AutoRegister":false}}'`, "R-165", DecisionDeny),
		sh("PUT the observer.hooks section", `curl -X PUT http://127.0.0.1:8820/api/config/section/observer.hooks -d '{}'`, "R-165", DecisionDeny),
		// Reads and previews.
		sh("uninstall --dry-run is a read", `observer uninstall --all --dry-run`, "", 0),
		sh("components remove without --yes previews", `observer components remove integration.hooks`, "", 0),
		sh("components teardown --dry-run is a read", `observer components teardown integration.hooks --dry-run`, "", 0),
		sh("components remove of another component", `observer components remove integration.mcp-server --yes`, "", 0),
		sh("POST setup hooks register", `curl -X POST http://127.0.0.1:8820/api/setup/hooks -d '{"tool":"claude-code"}'`, "", 0),
		sh("POST setup hooks undo dry run", `curl -X POST http://127.0.0.1:8820/api/setup/hooks -d '{"tool":"claude-code","undo":true,"dry_run":true}'`, "", 0),
		sh("POST teardown of hooks dry run", `curl -X POST http://127.0.0.1:8820/api/components/teardown -d '{"ids":["integration.hooks"],"dry_run":true}'`, "", 0),
		sh("PUT the observer section without hooks", `curl -X PUT http://127.0.0.1:8820/api/config/section/observer -d '{"LogLevel":"debug"}'`, "", 0),
		sh("config get auto_register is a read", `observer config get observer.hooks.auto_register`, "", 0),
		sh("service uninstall is not a hooks removal", `observer service uninstall`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}

// TestSelfApprovalGuardEnvPersist (sweep finding SA-9): OBSERVER_GUARD_*
// environment overrides apply to [guard] in every hook load, so an agent
// persisting one for later processes (setx, the .NET and registry setters,
// launchctl, a shell startup file) is lowering its own guard.
func TestSelfApprovalGuardEnvPersist(t *testing.T) {
	t.Parallel()
	ps := func(name, line string) coreRuleCase {
		return coreRuleCase{name: name, kind: KindShellExec, target: line, dialect: DialectPowerShell, wantRule: "R-165", wantEnforce: DecisionDeny}
	}
	edit := func(name, target, text string) coreRuleCase {
		return coreRuleCase{
			name: name, kind: KindFileAccess, actionType: "edit_file", target: target,
			edits: []ProposedEdit{{Kind: EditReplace, New: text}}, wantRule: "R-165", wantEnforce: DecisionDeny,
		}
	}
	cases := []coreRuleCase{
		sh("setx", `setx OBSERVER_GUARD_MODE off`, "R-165", DecisionDeny),
		sh("setx lower case", `setx observer_guard_enabled false`, "R-165", DecisionDeny),
		ps("SetEnvironmentVariable", `[Environment]::SetEnvironmentVariable('OBSERVER_GUARD_MODE','off','User')`),
		ps("System.Environment SetEnvironmentVariable", `[System.Environment]::SetEnvironmentVariable("OBSERVER_GUARD_MODE", "off", "Machine")`),
		ps("Set-ItemProperty on the user environment", `Set-ItemProperty -Path HKCU:\Environment -Name OBSERVER_GUARD_MODE -Value off`),
		sh("reg add to the user environment", `reg add HKCU\\Environment /v OBSERVER_GUARD_MODE /d off /f`, "R-165", DecisionDeny),
		sh("launchctl setenv", `launchctl setenv OBSERVER_GUARD_MODE off`, "R-165", DecisionDeny),
		sh("systemctl --user set-environment", `systemctl --user set-environment OBSERVER_GUARD_MODE=off`, "R-165", DecisionDeny),
		ps("Add-Content to the PowerShell profile", `Add-Content -Path $PROFILE -Value '$env:OBSERVER_GUARD_MODE = "off"'`),
		sh("append to /etc/environment", `echo 'OBSERVER_GUARD_MODE=off' | sudo tee -a /etc/environment`, "R-165", DecisionDeny),
		edit("Edit tool on the PAM environment", "/home/u/.pam_environment", "OBSERVER_GUARD_MODE DEFAULT=off\n"),
		// Not persisted, or not the guard.
		sh("export for this shell only", `export OBSERVER_GUARD_MODE=off`, "", 0),
		sh("setx of another variable", `setx PATH "%PATH%;C:\tools"`, "", 0),
		sh("append another variable to .bashrc", `echo 'export EDITOR=vim' >> ~/.bashrc`, "", 0),
		sh("reading the variable", `echo $OBSERVER_GUARD_MODE`, "", 0),
		{
			name: "Edit tool on .bashrc without the variable", kind: KindFileAccess, actionType: "edit_file", target: "/home/u/.bashrc",
			edits: []ProposedEdit{{Kind: EditReplace, New: "export EDITOR=vim\n"}},
		},
	}
	runCoreRuleCases(t, cases, "R-165")

	// The shell profiles are R-154's too, which denies any agent write to
	// one in enforce mode and, as the earlier Critical row, names the
	// verdict. R-165's rows are the integrity floor under it: with R-154
	// disabled (a below-org layer may disable it, never R-165) they still
	// hold, in observe mode as a flag and in enforce mode as a deny.
	profiles := []coreRuleCase{
		sh("append to .bashrc", `echo 'export OBSERVER_GUARD_MODE=off' >> ~/.bashrc`, "R-165", DecisionDeny),
		sh("append to .zshrc through tee", `echo 'export OBSERVER_GUARD_MODE=off' | tee -a ~/.zshrc`, "R-165", DecisionDeny),
		sh("printf into .profile", `printf 'OBSERVER_GUARD_ENABLED=false\n' >> /home/u/.profile`, "R-165", DecisionDeny),
		edit("Edit tool on .bashrc", "/home/u/.bashrc", "export OBSERVER_GUARD_MODE=off\n"),
		edit("Edit tool on the PowerShell profile", "/home/u/Documents/PowerShell/Microsoft.PowerShell_profile.ps1", "$env:OBSERVER_GUARD_MODE = 'off'\n"),
	}
	for _, tc := range profiles {
		t.Run("profile/"+tc.name, func(t *testing.T) {
			t.Parallel()
			ev := Event{
				Kind: tc.kind, ActionType: tc.actionType, Target: tc.target, Edits: tc.edits,
				Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", SessionID: "s1",
			}
			for _, mode := range []Mode{ModeObserve, ModeEnforce} {
				withR154, err := New(Config{Mode: mode, Home: "/home/u"})
				if err != nil {
					t.Fatal(err)
				}
				if v := withR154.Evaluate(ev); mode == ModeEnforce && v.Decision != DecisionDeny {
					t.Fatalf("enforce with R-154: got %s/%s, want a deny", v.RuleID, v.Decision)
				}
				without, err := New(Config{Mode: mode, Home: "/home/u", Disabled: []string{"R-154"}})
				if err != nil {
					t.Fatal(err)
				}
				want := DecisionFlag
				if mode == ModeEnforce {
					want = DecisionDeny
				}
				if v := without.Evaluate(ev); v.RuleID != "R-165" || v.Decision != want {
					t.Fatalf("%s without R-154: got %s/%s, want R-165/%s (%q)", mode, v.RuleID, v.Decision, want, v.Reason)
				}
			}
		})
	}
}

// TestIntegrityRulesFollowEnforcedRows (sweep finding CFG-1): in observe
// mode a row that holds in every mode (a pack applied alone, a hand-written
// `enforce = true`) is worth nothing if the agent can lower the guard first,
// so the integrity rules hold with it. With no such row they stay at flag.
func TestIntegrityRulesFollowEnforcedRows(t *testing.T) {
	t.Parallel()
	deny := DecisionDeny
	ask := DecisionAsk
	flag := DecisionFlag
	cases := []struct {
		name      string
		overrides []Override
		line      string
		wantRule  string
		want      Decision
	}{
		{"no enforced row: recipe remove flags", nil, `observer guard recipe remove --yes`, "R-165", DecisionFlag},
		{"no enforced row: guard disable flags", nil, `observer guard disable`, "R-165", DecisionFlag},
		{"an enforced user deny: recipe remove denies", []Override{{RuleID: "R-101", Decision: &deny, Enforced: true, Source: "user"}}, `observer guard recipe remove --yes`, "R-165", DecisionDeny},
		{"an enforced user deny: apply level none denies", []Override{{RuleID: "R-101", Decision: &deny, Enforced: true, Source: "user"}}, `observer guard recipe apply --level none --yes`, "R-165", DecisionDeny},
		{"an enforced user deny: guard disable denies", []Override{{RuleID: "R-110", Decision: &deny, Enforced: true, Source: "user"}}, `observer guard disable`, "R-165", DecisionDeny},
		{"an enforced user ask: guard disable denies", []Override{{RuleID: "R-140", Decision: &ask, Enforced: true, Source: "trusted_project"}}, `observer guard disable`, "R-165", DecisionDeny},
		{"an enforced org deny: config set guard.mode denies", []Override{{RuleID: "R-170", Decision: &deny, Enforced: true, Source: SourceOrg}}, `observer config set guard.mode off`, "R-165", DecisionDeny},
		{"an enforced row: an agent write to the policy file denies", []Override{{RuleID: "R-101", Decision: &deny, Enforced: true, Source: "user"}}, `echo x > ~/.observer/guard-policy.toml`, "R-160", DecisionDeny},
		{"an enforced flag-only row does not count", []Override{{RuleID: "R-101", Decision: &flag, Enforced: true, Source: "user"}}, `observer guard disable`, "R-165", DecisionFlag},
		{"the request row stays a flag", []Override{{RuleID: "R-101", Decision: &deny, Enforced: true, Source: "user"}}, `observer request access --reason x`, "R-165", DecisionFlag},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, err := New(Config{Mode: ModeObserve, Home: "/home/u", Overrides: tc.overrides})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			v := e.Evaluate(Event{Kind: KindShellExec, Target: tc.line, Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", SessionID: "s1"})
			if v.RuleID != tc.wantRule || v.Decision != tc.want {
				t.Fatalf("got %s/%s, want %s/%s (%q)", v.RuleID, v.Decision, tc.wantRule, tc.want, v.Reason)
			}
		})
	}
}
