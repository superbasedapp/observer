package sshprofile

import (
	"errors"
	"strings"
	"testing"
)

// forwardBase is a minimal valid profile for the forward tests.
func forwardBase() Profile {
	return Profile{Name: "sb-devbox", Host: "devbox.internal"}
}

// argvIndex returns the position of tok in argv, or -1.
func argvIndex(argv []string, tok string) int {
	for i, a := range argv {
		if a == tok {
			return i
		}
	}
	return -1
}

// optionValue returns the value following the "-o" whose value has the given
// key prefix ("StrictHostKeyChecking="), or "" when absent.
func optionValue(argv []string, key string) string {
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == "-o" && strings.HasPrefix(argv[i+1], key) {
			return strings.TrimPrefix(argv[i+1], key)
		}
	}
	return ""
}

// TestForwardArgv_NeverWeakens pins the hardening set the forward variant must
// carry. This is the load-bearing test of the whole instance switcher: the
// forward runs UNATTENDED (there is no PTY and no operator to answer a prompt),
// so if any of these drifted, a silent MITM-accepting connection would be the
// result and nothing else in the system would notice.
//
// Each row is a property, not a byte-for-byte argv match, so adding an unrelated
// option later does not break the suite while a weakened one still does.
func TestForwardArgv_NeverWeakens(t *testing.T) {
	t.Parallel()

	p := forwardBase()
	p.KeyPath = "/home/dev/.ssh/id_ed25519"
	p.User = "dev"
	p.Port = 2222
	p.Jump = "bastion.internal"
	argv, err := ForwardArgv(p, Options{}, 41234)
	if err != nil {
		t.Fatalf("ForwardArgv: %v", err)
	}
	joined := strings.Join(argv, " ")

	t.Run("StrictHostKeyChecking stays ask", func(t *testing.T) {
		if got := optionValue(argv, "StrictHostKeyChecking="); got != "ask" {
			t.Fatalf("StrictHostKeyChecking=%q, want %q — a -N forward has no terminal to accept a new key on, so anything looser silently trusts an unverified host", got, "ask")
		}
	})
	t.Run("never accept-new or no", func(t *testing.T) {
		for _, weak := range []string{"StrictHostKeyChecking=accept-new", "StrictHostKeyChecking=no", "StrictHostKeyChecking=off"} {
			if strings.Contains(joined, weak) {
				t.Fatalf("argv contains %q — auto-accepting a host key from a daemon-driven forward defeats MITM protection", weak)
			}
		}
	})
	t.Run("never disables host-key checking by other means", func(t *testing.T) {
		for _, weak := range []string{"UserKnownHostsFile=/dev/null", "CheckHostIP=no", "NoHostAuthenticationForLocalhost=yes", "HostKeyAlias="} {
			if strings.Contains(joined, weak) {
				t.Fatalf("argv contains %q — a second route to skipping verification is the same defect as loosening StrictHostKeyChecking", weak)
			}
		}
	})
	t.Run("BatchMode is yes", func(t *testing.T) {
		// STRICTER than the interactive Argv, not looser: with no terminal
		// attached a prompt would hang forever instead of failing.
		if got := optionValue(argv, "BatchMode="); got != "yes" {
			t.Fatalf("BatchMode=%q, want yes", got)
		}
	})
	t.Run("ExitOnForwardFailure is yes", func(t *testing.T) {
		if got := optionValue(argv, "ExitOnForwardFailure="); got != "yes" {
			t.Fatalf("ExitOnForwardFailure=%q, want yes — a live connection carrying no forward would make the UI advertise a port that answers nothing", got)
		}
	})
	t.Run("-N present, no remote command", func(t *testing.T) {
		if argvIndex(argv, "-N") < 0 {
			t.Fatal("argv lacks -N — the child must carry the forward and nothing else")
		}
		if i := argvIndex(argv, p.Host); i != len(argv)-1 {
			t.Fatalf("host at index %d of %d; it must be LAST with no remote command after it", i, len(argv))
		}
		for _, pty := range []string{"-t", "-tt"} {
			if argvIndex(argv, pty) >= 0 {
				t.Fatalf("argv contains %q — a forward must never allocate a PTY", pty)
			}
		}
	})
	t.Run("no reverse, dynamic or tunnel forwarding by default", func(t *testing.T) {
		// p (the outer profile) leaves ReverseProxy unset, so -R must be absent
		// exactly like -D and -w always are, regardless of ReverseProxy.
		for _, banned := range []string{"-R", "-D", "-w", "-o", "-O"} {
			if banned == "-o" {
				continue // -o is the option carrier, checked by value above
			}
			if argvIndex(argv, banned) >= 0 {
				t.Fatalf("argv contains %q — a profile that does not opt into ReverseProxy composes exactly one local forward, never a reverse tunnel, SOCKS proxy or tun device", banned)
			}
		}
	})
	t.Run("IdentitiesOnly accompanies a key", func(t *testing.T) {
		if got := optionValue(argv, "IdentitiesOnly="); got != "yes" {
			t.Fatalf("IdentitiesOnly=%q, want yes when a key_path is configured", got)
		}
	})
	t.Run("key path is never read into the argv value", func(t *testing.T) {
		i := argvIndex(argv, "-i")
		if i < 0 || argv[i+1] != p.KeyPath {
			t.Fatalf("-i does not carry the configured key path verbatim: %v", argv)
		}
	})
}

// TestForwardArgv_ReverseProxyOptIn pins the C3 relaxation: -R is composed
// ONLY when a profile explicitly sets ReverseProxy, it is composed EXACTLY
// ONCE, and it is loopback-bound on both ends targeting the fixed
// DefaultObserverProxyPort — never a profile- or caller-chosen destination.
// -D and -w stay banned unconditionally; this test does not re-check them
// (see TestForwardArgv_NeverWeakens).
func TestForwardArgv_ReverseProxyOptIn(t *testing.T) {
	t.Parallel()

	t.Run("absent when ReverseProxy is unset", func(t *testing.T) {
		t.Parallel()
		p := forwardBase()
		argv, err := ForwardArgv(p, Options{}, 40000)
		if err != nil {
			t.Fatalf("ForwardArgv: %v", err)
		}
		if argvIndex(argv, "-R") >= 0 {
			t.Fatalf("argv contains -R with ReverseProxy unset: %v", argv)
		}
	})

	t.Run("present exactly once, loopback-bound, default port", func(t *testing.T) {
		t.Parallel()
		p := forwardBase()
		p.ReverseProxy = true
		argv, err := ForwardArgv(p, Options{}, 40000)
		if err != nil {
			t.Fatalf("ForwardArgv: %v", err)
		}
		i := argvIndex(argv, "-R")
		if i < 0 || i+1 >= len(argv) {
			t.Fatalf("argv lacks -R with ReverseProxy=true: %v", argv)
		}
		want := "127.0.0.1:8820:127.0.0.1:8820"
		if got := argv[i+1]; got != want {
			t.Fatalf("-R %q, want %q", got, want)
		}
		count := 0
		for _, a := range argv {
			if a == "-R" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("argv carries %d -R flags, want exactly 1", count)
		}
	})

	t.Run("present with explicit remote port", func(t *testing.T) {
		t.Parallel()
		p := forwardBase()
		p.ReverseProxy = true
		p.ReverseProxyPort = 19999
		argv, err := ForwardArgv(p, Options{}, 40000)
		if err != nil {
			t.Fatalf("ForwardArgv: %v", err)
		}
		i := argvIndex(argv, "-R")
		if i < 0 || i+1 >= len(argv) {
			t.Fatalf("argv lacks -R: %v", argv)
		}
		want := "127.0.0.1:19999:127.0.0.1:8820"
		if got := argv[i+1]; got != want {
			t.Fatalf("-R %q, want %q — remote bind must follow reverse_proxy_port, local destination must stay the fixed Observer proxy port", got, want)
		}
	})

	t.Run("out-of-range reverse_proxy_port is rejected", func(t *testing.T) {
		t.Parallel()
		p := forwardBase()
		p.ReverseProxy = true
		p.ReverseProxyPort = 65536
		if argv, err := ForwardArgv(p, Options{}, 40000); err == nil {
			t.Fatalf("ForwardArgv accepted reverse_proxy_port 65536: %v", argv)
		} else if !errors.Is(err, ErrInvalidProfile) {
			t.Fatalf("error %v does not wrap ErrInvalidProfile", err)
		}
	})

	t.Run("Argv (interactive login) never composes -R even when ReverseProxy is set", func(t *testing.T) {
		t.Parallel()
		p := forwardBase()
		p.ReverseProxy = true
		argv, err := Argv(p, Options{})
		if err != nil {
			t.Fatalf("Argv: %v", err)
		}
		if argvIndex(argv, "-R") >= 0 {
			t.Fatalf("Argv contains -R — the interactive login must never honor ReverseProxy: %v", argv)
		}
	})

	t.Run("TestArgv (diagnostic probe) never composes -R even when ReverseProxy is set", func(t *testing.T) {
		t.Parallel()
		p := forwardBase()
		p.ReverseProxy = true
		argv, err := TestArgv(p, Options{})
		if err != nil {
			t.Fatalf("TestArgv: %v", err)
		}
		if argvIndex(argv, "-R") >= 0 {
			t.Fatalf("TestArgv contains -R — the diagnostic probe must never honor ReverseProxy: %v", argv)
		}
	})
}

// TestForwardArgv_BindsLoopbackOnly pins the -L argument's shape. Both ends are
// constants: a non-loopback LOCAL bind would republish the remote dashboard to
// this machine's network, and a non-loopback REMOTE bind would turn the
// switcher into a pivot onto the remote's network.
func TestForwardArgv_BindsLoopbackOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		dashboardPort int
		localPort     int
		wantL         string
	}{
		{"default dashboard port", 0, 40001, "127.0.0.1:40001:127.0.0.1:8081"},
		{"explicit dashboard port", 9099, 40002, "127.0.0.1:40002:127.0.0.1:9099"},
		{"high ports", 65535, 65534, "127.0.0.1:65534:127.0.0.1:65535"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := forwardBase()
			p.DashboardPort = tt.dashboardPort
			argv, err := ForwardArgv(p, Options{}, tt.localPort)
			if err != nil {
				t.Fatalf("ForwardArgv: %v", err)
			}
			i := argvIndex(argv, "-L")
			if i < 0 || i+1 >= len(argv) {
				t.Fatalf("argv has no -L: %v", argv)
			}
			if argv[i+1] != tt.wantL {
				t.Fatalf("-L %q, want %q", argv[i+1], tt.wantL)
			}
			// Exactly one -L. Two would mean a second, unreviewed destination.
			count := 0
			for _, a := range argv {
				if a == "-L" {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("argv carries %d -L flags, want exactly 1", count)
			}
		})
	}
}

// TestForwardArgv_RemotePortComesFromConfigNotCaller is the wire property
// spelled as a unit test: ForwardArgv takes ONLY a local port from its caller.
// The remote port is read off the profile, so no request-shaped input can
// choose what is reached on the remote machine.
func TestForwardArgv_RemotePortComesFromConfigNotCaller(t *testing.T) {
	t.Parallel()

	p := forwardBase()
	p.DashboardPort = 8081
	// Try to smuggle a different remote port in through the ONE caller-supplied
	// number. It must land on the LOCAL side and nowhere else.
	argv, err := ForwardArgv(p, Options{}, 22)
	if err != nil {
		t.Fatalf("ForwardArgv: %v", err)
	}
	i := argvIndex(argv, "-L")
	if got, want := argv[i+1], "127.0.0.1:22:127.0.0.1:8081"; got != want {
		t.Fatalf("-L %q, want %q — the caller's number must only ever be the LOCAL bind", got, want)
	}
}

// TestForwardArgv_HostileInput refuses everything the interactive path refuses,
// plus the forward-specific port bounds.
func TestForwardArgv_HostileInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(*Profile)
		localPort int
		wantErr   string
	}{
		{"leading-dash host", func(p *Profile) { p.Host = "-oProxyCommand=id" }, 40000, "must not begin with '-'"},
		{"dashboard_port zero is fine", func(p *Profile) { p.DashboardPort = 0 }, 40000, ""},
		{"dashboard_port negative", func(p *Profile) { p.DashboardPort = -1 }, 40000, "dashboard_port"},
		{"dashboard_port above range", func(p *Profile) { p.DashboardPort = 65536 }, 40000, "dashboard_port"},
		{"dashboard_port far above range", func(p *Profile) { p.DashboardPort = 1 << 30 }, 40000, "dashboard_port"},
		{"local port zero", func(*Profile) {}, 0, "local forward port"},
		{"local port negative", func(*Profile) {}, -8080, "local forward port"},
		{"local port above range", func(*Profile) {}, 65536, "local forward port"},
		{"control char in host", func(p *Profile) { p.Host = "dev\nbox" }, 40000, "whitespace or a control character"},
		{"multi-hop jump", func(p *Profile) { p.Jump = "a.internal,b.internal" }, 40000, "single hop"},
		{"relative key path", func(p *Profile) { p.KeyPath = "id_rsa" }, 40000, "absolute path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := forwardBase()
			tt.mutate(&p)
			argv, err := ForwardArgv(p, Options{}, tt.localPort)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ForwardArgv: unexpected error %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ForwardArgv accepted hostile input and composed %v", argv)
			}
			if !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("error %v does not wrap ErrInvalidProfile", err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

// TestDashboardPortValidatedByProfileValidate pins that the new field is part of
// the SAME Validate() the config loader calls, so a bad dashboard_port is
// rejected loudly at load time rather than silently at the operator's click.
func TestDashboardPortValidatedByProfileValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		port    int
		wantErr bool
	}{
		{0, false},
		{1, false},
		{8081, false},
		{65535, false},
		{-1, true},
		{65536, true},
		{-65535, true},
	}
	for _, tt := range tests {
		p := forwardBase()
		p.DashboardPort = tt.port
		err := p.Validate()
		if tt.wantErr && err == nil {
			t.Fatalf("dashboard_port %d accepted by Validate", tt.port)
		}
		if !tt.wantErr && err != nil {
			t.Fatalf("dashboard_port %d rejected by Validate: %v", tt.port, err)
		}
	}
}

// TestResolvedDashboardPort pins the default substitution.
func TestResolvedDashboardPort(t *testing.T) {
	t.Parallel()

	if got := (Profile{}).ResolvedDashboardPort(); got != DefaultDashboardPort {
		t.Fatalf("unset dashboard port resolved to %d, want %d", got, DefaultDashboardPort)
	}
	if got := (Profile{DashboardPort: 9000}).ResolvedDashboardPort(); got != 9000 {
		t.Fatalf("explicit dashboard port resolved to %d, want 9000", got)
	}
}

// TestResolvedReverseProxyPort pins the default substitution for the C3
// opt-in -R forward's remote-side bind port.
func TestResolvedReverseProxyPort(t *testing.T) {
	t.Parallel()

	if got := (Profile{}).ResolvedReverseProxyPort(); got != DefaultReverseProxyPort {
		t.Fatalf("unset reverse proxy port resolved to %d, want %d", got, DefaultReverseProxyPort)
	}
	if got := (Profile{ReverseProxyPort: 19999}).ResolvedReverseProxyPort(); got != 19999 {
		t.Fatalf("explicit reverse proxy port resolved to %d, want 19999", got)
	}
}

// TestTestArgv_NeverWeakens pins the diagnostic probe's hardening (C2). It is
// deliberately STRICTER and NARROWER than the interactive Argv: no PTY, no
// forward, a fixed short ConnectTimeout, and a single literal remote command.
func TestTestArgv_NeverWeakens(t *testing.T) {
	t.Parallel()

	p := forwardBase()
	p.KeyPath = "/home/dev/.ssh/id_ed25519"
	p.User = "dev"
	p.Port = 2222
	p.Jump = "bastion.internal"
	argv, err := TestArgv(p, Options{})
	if err != nil {
		t.Fatalf("TestArgv: %v", err)
	}
	joined := strings.Join(argv, " ")

	t.Run("BatchMode is yes", func(t *testing.T) {
		if got := optionValue(argv, "BatchMode="); got != "yes" {
			t.Fatalf("BatchMode=%q, want yes — a probe has no terminal to prompt at", got)
		}
	})
	t.Run("StrictHostKeyChecking stays ask", func(t *testing.T) {
		if got := optionValue(argv, "StrictHostKeyChecking="); got != "ask" {
			t.Fatalf("StrictHostKeyChecking=%q, want ask", got)
		}
	})
	t.Run("ConnectTimeout is the fixed probe constant, not Options", func(t *testing.T) {
		if got := optionValue(argv, "ConnectTimeout="); got != "5" {
			t.Fatalf("ConnectTimeout=%q, want 5 (TestConnectTimeoutSeconds), even with default Options", got)
		}
		argv2, err := TestArgv(p, Options{ConnectTimeoutSeconds: 120})
		if err != nil {
			t.Fatalf("TestArgv: %v", err)
		}
		if got := optionValue(argv2, "ConnectTimeout="); got != "5" {
			t.Fatalf("ConnectTimeout=%q, want 5 — Options.ConnectTimeoutSeconds must be ignored by the probe", got)
		}
	})
	t.Run("never forwards, never allocates a PTY", func(t *testing.T) {
		for _, banned := range []string{"-L", "-R", "-D", "-w", "-N", "-t", "-tt"} {
			if argvIndex(argv, banned) >= 0 {
				t.Fatalf("argv contains %q — the probe must never forward or attach a terminal: %v", banned, argv)
			}
		}
	})
	t.Run("never weakens host-key checking", func(t *testing.T) {
		for _, weak := range []string{"StrictHostKeyChecking=accept-new", "StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null"} {
			if strings.Contains(joined, weak) {
				t.Fatalf("argv contains %q", weak)
			}
		}
	})
	t.Run("remote command is the single literal exit, host is second-to-last", func(t *testing.T) {
		if argv[len(argv)-1] != "exit" {
			t.Fatalf("last token = %q, want the literal \"exit\"", argv[len(argv)-1])
		}
		if argv[len(argv)-2] != p.Host {
			t.Fatalf("second-to-last token = %q, want the host %q", argv[len(argv)-2], p.Host)
		}
	})
}

// TestTestArgv_RejectsHostileProfile pins that the probe composer runs the
// same validation as every other composer in this package.
func TestTestArgv_RejectsHostileProfile(t *testing.T) {
	t.Parallel()

	p := forwardBase()
	p.Host = "-oProxyCommand=id"
	if argv, err := TestArgv(p, Options{}); err == nil {
		t.Fatalf("TestArgv accepted a leading-dash host: %v", argv)
	} else if !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("error %v does not wrap ErrInvalidProfile", err)
	}
}

// TestResolveArgv_ConnectsToNothing pins the known-hosts pre-flight command: it
// must carry -G (print the effective config and exit) and must never carry a
// remote command or a forward.
func TestResolveArgv_ConnectsToNothing(t *testing.T) {
	t.Parallel()

	p := forwardBase()
	p.User = "dev"
	p.Port = 2222
	argv, err := ResolveArgv(p)
	if err != nil {
		t.Fatalf("ResolveArgv: %v", err)
	}
	if argvIndex(argv, "-G") < 0 {
		t.Fatalf("argv lacks -G — without it the pre-flight would actually connect: %v", argv)
	}
	for _, banned := range []string{"-L", "-R", "-D", "-N", "-tt"} {
		if argvIndex(argv, banned) >= 0 {
			t.Fatalf("argv contains %q; the pre-flight parses config only: %v", banned, argv)
		}
	}
	if i := argvIndex(argv, p.Host); i != len(argv)-1 {
		t.Fatalf("host must be the last token: %v", argv)
	}
	if got := optionValue(argv, "BatchMode="); got != "yes" {
		t.Fatalf("BatchMode=%q, want yes — the pre-flight must never block on a prompt", got)
	}
}

// TestResolveArgv_RejectsHostileProfile pins that the pre-flight composer runs
// the same validation as every other composer (an unvalidated profile must not
// reach any argv builder in this package).
func TestResolveArgv_RejectsHostileProfile(t *testing.T) {
	t.Parallel()

	p := forwardBase()
	p.Host = "-oProxyCommand=id"
	if argv, err := ResolveArgv(p); err == nil {
		t.Fatalf("ResolveArgv accepted a leading-dash host: %v", argv)
	}
}
