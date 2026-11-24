package policy

import "testing"

// TestReviewHonestCommandsKeepVerdicts pins the honest commands the
// fix-sec-1122 guard-review lane was asked to keep (review 2026-11-22): the
// wrapper rows, sudo's assignment and shell-line forms, the unknown-prefix
// fallback, and the R-171 changes must leave every one of them allowed with
// no rule hit, in enforce mode. Each row allowed before the lane too
// (measured on the base commit).
func TestReviewHonestCommandsKeepVerdicts(t *testing.T) {
	t.Parallel()
	enforce := exfilTestEngine(t, ModeEnforce)
	posix, ps := DialectPosix, DialectPowerShell
	for _, tc := range []struct {
		cmd     string
		dialect Dialect
	}{
		// From the brief.
		{"timeout 5 make", posix},
		{"nice -n 10 go test ./...", posix},
		{"watch -n1 date", posix},
		{"sudo -u x ls", posix},
		{"sudo apt-get install -y foo", posix},
		{"env FOO=1 go build", posix},
		{"curl http://localhost:8080/health", posix},
		{"curl -T ./a http://localhost:9/", posix},
		{"iwr -Uri http://localhost/ -InFile f", ps},
		// Neighbours of the changed rows.
		{"watch -n1 'ls ./build'", posix},
		{"sudo -E npm install", posix},
		{"sudo -i", posix},
		{"sudo -s", posix},
		{"env -i PATH=/usr/bin make", posix},
		{"curl -d @a.json http://localhost:8080/api", posix},
		{"curl -H 'X-Token: abc' -T ./a http://localhost:9/", posix},
		{"Invoke-RestMethod -Uri http://127.0.0.1:8080/x -Method Post -InFile ./a.json", ps},
		{"curl.exe http://localhost:8080/health", ps},
		{"curl http://localhost:8080/health", ps},
		{"time make", posix},
		{"/usr/bin/time -v make", posix},
		{"stdbuf -oL make", posix},
		{"xargs -n1 echo", posix},
		{"parallel echo ::: a b", posix},
		{"ssh-agent -s", posix},
		{"xvfb-run -a npm test", posix},
		{"numactl --interleave=all ./bench", posix},
		{"setarch x86_64 -R ./a.out", posix},
		{"firejail --noprofile firefox", posix},
		{"proxychains4 curl https://example.com", posix},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			t.Parallel()
			ev := shellEvent(tc.cmd)
			ev.Dialect = tc.dialect
			if v := enforce.Evaluate(ev); v.RuleID != "" || v.Decision != DecisionAllow {
				t.Fatalf("Evaluate(%q) = %s/%v (%s), want allow with no rule", tc.cmd, v.RuleID, v.Decision, v.Reason)
			}
		})
	}
}
