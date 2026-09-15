package sshprofile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// valid is the baseline profile every hostile-input case mutates ONE field of,
// so a failure can only be attributable to that field.
func valid() Profile {
	return Profile{Name: "demo-box", Host: "demo.example.com", User: "ubuntu", Port: 22}
}

// TestValidate_Accepts pins the shapes an operator legitimately writes.
func TestValidate_Accepts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		p    Profile
	}{
		{"minimal", Profile{Name: "a", Host: "h"}},
		{"fqdn", Profile{Name: "demo-box", Host: "demo.internal.example.com"}},
		{"ipv4", Profile{Name: "gpu1", Host: "10.0.4.11", User: "root"}},
		{"ipv6 bare", Profile{Name: "v6", Host: "2001:db8::1"}},
		{"ipv6 bracketed", Profile{Name: "v6b", Host: "[2001:db8::1]"}},
		{"ipv6 loopback", Profile{Name: "v6l", Host: "::1"}},
		{"ssh_config alias", Profile{Name: "alias", Host: "my_bastion"}},
		{"nonstandard port", Profile{Name: "p", Host: "h.example.com", Port: 2222}},
		{"port 1", Profile{Name: "p1", Host: "h", Port: 1}},
		{"port 65535", Profile{Name: "pmax", Host: "h", Port: 65535}},
		{"user with dot and underscore", Profile{Name: "u", Host: "h", User: "first.last_2"}},
		{"label", Profile{Name: "l", Host: "h", Label: "Client demo (eu-west)"}},
		{"jump host only", Profile{Name: "j", Host: "h", Jump: "bastion.example.com"}},
		{"jump user@host", Profile{Name: "j2", Host: "h", Jump: "ops@bastion.example.com"}},
		{"jump host:port", Profile{Name: "j3", Host: "h", Jump: "bastion.example.com:2222"}},
		{"jump user@host:port", Profile{Name: "j4", Host: "h", Jump: "ops@bastion.example.com:2222"}},
		{"jump bare ipv6", Profile{Name: "j5", Host: "h", Jump: "2001:db8::9"}},
		{"jump bracketed ipv6 with port", Profile{Name: "j6", Host: "h", Jump: "[2001:db8::9]:2222"}},
		{"abs key path", Profile{Name: "k", Host: "h", KeyPath: "/home/dev/.ssh/id_demo"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.p.Validate(); err != nil {
				t.Fatalf("Validate() rejected a legitimate profile: %v", err)
			}
		})
	}
}

// TestValidate_RejectsHostileInput is the security surface of this package.
// Each row mutates exactly ONE field of the valid baseline, so a row that stops
// failing names precisely the validator that regressed (plan §9.1).
func TestValidate_RejectsHostileInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*Profile)
		// why documents the concrete attack the row defends against, so a
		// future reader cannot mistake a row for a stylistic preference.
		why string
	}{
		// --- host: the LAST argv token, and ssh has NO "--" separator ---------
		{
			"host leading dash", func(p *Profile) { p.Host = "-oProxyCommand=touch /tmp/pwn" },
			"ssh has no end-of-options separator, so a leading '-' host IS a flag",
		},
		{"host leading dash plain", func(p *Profile) { p.Host = "-h" }, "same class, minimal form"},
		{
			"host with space", func(p *Profile) { p.Host = "host -oProxyCommand=x" },
			"a space would let a single field become two tokens if ever shell-split",
		},
		{"host with semicolon", func(p *Profile) { p.Host = "host;touch /tmp/pwn" }, "shell metacharacter"},
		{"host with command substitution", func(p *Profile) { p.Host = "host$(id)" }, "shell metacharacter"},
		{"host with backtick", func(p *Profile) { p.Host = "host`id`" }, "shell metacharacter"},
		{"host with pipe", func(p *Profile) { p.Host = "host|id" }, "shell metacharacter"},
		{"host with newline", func(p *Profile) { p.Host = "host\nother" }, "control character"},
		{"host with NUL", func(p *Profile) { p.Host = "host\x00evil" }, "NUL truncation"},
		{"host with tab", func(p *Profile) { p.Host = "host\tevil" }, "control character"},
		{"host with slash", func(p *Profile) { p.Host = "host/../other" }, "outside the closed charset"},
		{
			"host with at sign", func(p *Profile) { p.Host = "user@other.example.com" },
			"an '@' in host would silently redirect the destination",
		},
		{
			"host with colon non-ipv6", func(p *Profile) { p.Host = "host:2222" },
			"a port must come through the typed Port field, not smuggled into host",
		},
		{"host invalid ipv6", func(p *Profile) { p.Host = "not:an:ipv6:addr:at:all:x" }, "colon shape that is not an address"},
		{"host empty", func(p *Profile) { p.Host = "" }, "no destination"},
		{"host too long", func(p *Profile) { p.Host = strings.Repeat("a", maxHost+1) }, "unbounded argv token"},

		// --- user: reaches the argv via -l -----------------------------------
		{"user leading dash", func(p *Profile) { p.User = "-oProxyCommand=x" }, "flag injection through -l's operand"},
		{
			"user with at sign", func(p *Profile) { p.User = "ubuntu@evil.example.com" },
			"'@' in user would express a second destination",
		},
		{"user with space", func(p *Profile) { p.User = "ubuntu -o Foo=bar" }, "two tokens from one field"},
		{"user with newline", func(p *Profile) { p.User = "ubuntu\nroot" }, "control character"},
		{"user with NUL", func(p *Profile) { p.User = "ubuntu\x00" }, "NUL truncation"},
		{"user with slash", func(p *Profile) { p.User = "../root" }, "outside the closed charset"},
		{"user too long", func(p *Profile) { p.User = strings.Repeat("u", maxUser+1) }, "unbounded argv token"},

		// --- port: typed, so only bounds matter ------------------------------
		{"port negative", func(p *Profile) { p.Port = -1 }, "out of range"},
		{"port too large", func(p *Profile) { p.Port = 65536 }, "out of range"},

		// --- reverse_proxy_port: typed, C3's -R remote bind port -------------
		{"reverse_proxy_port negative", func(p *Profile) { p.ReverseProxyPort = -1 }, "out of range"},
		{"reverse_proxy_port too large", func(p *Profile) { p.ReverseProxyPort = 65536 }, "out of range"},

		// --- key_path: reaches the argv via -i -------------------------------
		{"key leading dash", func(p *Profile) { p.KeyPath = "-oProxyCommand=x" }, "flag injection through -i's operand"},
		{"key relative", func(p *Profile) { p.KeyPath = "relative/id_rsa" }, "must be absolute on this host"},
		{"key with NUL", func(p *Profile) { p.KeyPath = "/home/dev/id\x00" }, "NUL truncation"},
		{"key with newline", func(p *Profile) { p.KeyPath = "/home/dev/id\nx" }, "control character"},
		{"key UNC backslash", func(p *Profile) { p.KeyPath = `\\server\share\id_rsa` }, "UNC/network path"},
		{"key UNC slash", func(p *Profile) { p.KeyPath = "//server/share/id_rsa" }, "UNC/network path"},
		{"key device namespace", func(p *Profile) { p.KeyPath = `C:\\.\NUL` }, "device-namespace path"},

		// --- jump: reaches the argv via -J -----------------------------------
		{"jump leading dash", func(p *Profile) { p.Jump = "-oProxyCommand=x" }, "flag injection through -J's operand"},
		{"jump multi-hop", func(p *Profile) { p.Jump = "a.example.com,b.example.com" }, "v1 rejects chains (plan D3)"},
		{"jump with space", func(p *Profile) { p.Jump = "bastion -o Foo=bar" }, "two tokens from one field"},
		{"jump bad port", func(p *Profile) { p.Jump = "bastion.example.com:notaport" }, "non-numeric port"},
		{"jump port zero", func(p *Profile) { p.Jump = "bastion.example.com:0" }, "explicitly malformed port"},
		{"jump port out of range", func(p *Profile) { p.Jump = "bastion.example.com:70000" }, "out of range"},
		{"jump empty user", func(p *Profile) { p.Jump = "@bastion.example.com" }, "malformed spec"},
		{"jump user leading dash", func(p *Profile) { p.Jump = "-x@bastion.example.com" }, "flag injection via the user half"},
		{"jump unclosed bracket", func(p *Profile) { p.Jump = "[2001:db8::9" }, "malformed IPv6 literal"},
		{"jump trailing garbage after bracket", func(p *Profile) { p.Jump = "[2001:db8::9]x" }, "malformed spec"},
		{"jump with NUL", func(p *Profile) { p.Jump = "bastion\x00" }, "NUL truncation"},

		// --- name: travels in a request body ---------------------------------
		{"name empty", func(p *Profile) { p.Name = "" }, "unaddressable profile"},
		{"name uppercase", func(p *Profile) { p.Name = "Demo" }, "outside the narrow API-key charset"},
		{"name leading dash", func(p *Profile) { p.Name = "-demo" }, "leading separator"},
		{"name with slash", func(p *Profile) { p.Name = "a/b" }, "path-shaped identifier"},
		{"name with space", func(p *Profile) { p.Name = "a b" }, "outside the charset"},
		{"name too long", func(p *Profile) { p.Name = strings.Repeat("a", maxName+1) }, "unbounded identifier"},

		// --- label: display-only, but must not garble the terminal ------------
		{"label with escape", func(p *Profile) { p.Label = "demo\x1b[2J" }, "ANSI escape in dashboard copy"},
		{"label with NUL", func(p *Profile) { p.Label = "demo\x00" }, "control character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := valid()
			tc.mutate(&p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("Validate() ACCEPTED hostile input (%s): %+v", tc.why, p)
			}
			if !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("error does not wrap ErrInvalidProfile: %v", err)
			}
			// A rejected profile must never be able to produce an argv.
			if argv, aerr := Argv(p, Options{}); aerr == nil {
				t.Fatalf("Argv() composed an argv for a rejected profile: %q", argv)
			}
		})
	}
}

// TestArgv_Composition pins the exact argv for representative profiles (plan
// §4.1). A change here is a deliberate change to what we execute.
func TestArgv_Composition(t *testing.T) {
	t.Parallel()
	base := []string{
		"ssh", "-tt",
		"-o", "BatchMode=no",
		"-o", "StrictHostKeyChecking=ask",
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
	}
	cases := []struct {
		name string
		p    Profile
		o    Options
		want []string
	}{
		{
			name: "minimal — no flags beyond the fixed options",
			p:    Profile{Name: "m", Host: "h.example.com"},
			want: append(append([]string{}, base...), "h.example.com"),
		},
		{
			name: "default port 22 omits -p",
			p:    Profile{Name: "m", Host: "h.example.com", Port: 22},
			want: append(append([]string{}, base...), "h.example.com"),
		},
		{
			name: "user rides -l, never user@host",
			p:    Profile{Name: "m", Host: "h.example.com", User: "ubuntu"},
			want: append(append([]string{}, base...), "-l", "ubuntu", "h.example.com"),
		},
		{
			name: "key adds IdentitiesOnly + -i",
			p:    Profile{Name: "m", Host: "h.example.com", KeyPath: "/k/id"},
			want: append(append([]string{}, base...), "-o", "IdentitiesOnly=yes", "-i", "/k/id", "h.example.com"),
		},
		{
			name: "everything, in the documented order",
			p: Profile{
				Name: "m", Host: "h.example.com", User: "ubuntu", Port: 2222,
				KeyPath: "/k/id", Jump: "ops@bastion.example.com:2022",
			},
			want: append(append([]string{}, base...),
				"-o", "IdentitiesOnly=yes", "-i", "/k/id",
				"-p", "2222",
				"-J", "ops@bastion.example.com:2022",
				"-l", "ubuntu",
				"h.example.com"),
		},
		{
			name: "options override the timeouts",
			p:    Profile{Name: "m", Host: "h.example.com"},
			o:    Options{ConnectTimeoutSeconds: 5, KeepaliveSeconds: 15},
			want: []string{
				"ssh", "-tt",
				"-o", "BatchMode=no",
				"-o", "StrictHostKeyChecking=ask",
				"-o", "ConnectTimeout=5",
				"-o", "ServerAliveInterval=15",
				"-o", "ServerAliveCountMax=3",
				"h.example.com",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Argv(tc.p, tc.o)
			if err != nil {
				t.Fatalf("Argv: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("argv length = %d, want %d\n got: %q\nwant: %q", len(got), len(tc.want), got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("argv[%d] = %q, want %q\n got: %q\nwant: %q", i, got[i], tc.want[i], got, tc.want)
				}
			}
		})
	}
}

// TestArgv_HostIsLastAndCarriesNoCommand pins the two structural properties the
// design depends on: the host is the FINAL token (so nothing can append a
// remote command), and no argv element is ever a shell invocation.
func TestArgv_HostIsLastAndCarriesNoCommand(t *testing.T) {
	t.Parallel()
	p := Profile{Name: "m", Host: "h.example.com", User: "ubuntu", Port: 2222, KeyPath: "/k/id", Jump: "b.example.com"}
	argv, err := Argv(p, Options{})
	if err != nil {
		t.Fatalf("Argv: %v", err)
	}
	if argv[len(argv)-1] != p.Host {
		t.Fatalf("host is not the final argv token: %q", argv)
	}
	if argv[0] != "ssh" {
		t.Fatalf("argv[0] = %q, want ssh", argv[0])
	}
	for _, tok := range argv {
		if tok == "-c" || strings.HasSuffix(tok, "/sh") || strings.HasSuffix(tok, "/bash") {
			t.Fatalf("argv contains a shell invocation token %q: %q", tok, argv)
		}
	}
}

// TestArgv_NeverEmitsStrictHostKeyWeakening is the host-key policy pin: the
// composed argv must ALWAYS carry StrictHostKeyChecking=ask, and must never
// carry a weakening value or override UserKnownHostsFile (plan §4.2).
func TestArgv_NeverEmitsStrictHostKeyWeakening(t *testing.T) {
	t.Parallel()
	for _, p := range []Profile{
		{Name: "a", Host: "h"},
		{Name: "b", Host: "h", User: "root", Port: 2222, KeyPath: "/k/id", Jump: "j.example.com"},
	} {
		argv, err := Argv(p, Options{})
		if err != nil {
			t.Fatalf("Argv: %v", err)
		}
		joined := strings.Join(argv, " ")
		if !strings.Contains(joined, "StrictHostKeyChecking=ask") {
			t.Fatalf("argv lost StrictHostKeyChecking=ask: %q", argv)
		}
		for _, bad := range []string{"StrictHostKeyChecking=no", "StrictHostKeyChecking=accept-new", "UserKnownHostsFile", "BatchMode=yes"} {
			if strings.Contains(joined, bad) {
				t.Fatalf("argv contains forbidden option %q: %q", bad, argv)
			}
		}
	}
}

// TestValidateWithFS covers the key-path filesystem check: an existing regular
// file passes, a missing path and a directory both fail.
func TestValidateWithFS(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "id_test")
	if err := os.WriteFile(keyFile, []byte("not-a-real-key"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Run("existing regular file passes", func(t *testing.T) {
		t.Parallel()
		p := Profile{Name: "k", Host: "h", KeyPath: keyFile}
		if err := p.ValidateWithFS(); err != nil {
			t.Fatalf("ValidateWithFS: %v", err)
		}
	})
	t.Run("no key configured passes", func(t *testing.T) {
		t.Parallel()
		if err := (Profile{Name: "k", Host: "h"}).ValidateWithFS(); err != nil {
			t.Fatalf("ValidateWithFS: %v", err)
		}
	})
	t.Run("missing key fails", func(t *testing.T) {
		t.Parallel()
		p := Profile{Name: "k", Host: "h", KeyPath: filepath.Join(dir, "absent")}
		if err := p.ValidateWithFS(); err == nil {
			t.Fatal("ValidateWithFS accepted a missing key path")
		} else if !errors.Is(err, ErrInvalidProfile) {
			t.Fatalf("error does not wrap ErrInvalidProfile: %v", err)
		}
	})
	t.Run("directory fails", func(t *testing.T) {
		t.Parallel()
		p := Profile{Name: "k", Host: "h", KeyPath: dir}
		if err := p.ValidateWithFS(); err == nil {
			t.Fatal("ValidateWithFS accepted a directory as a key path")
		}
	})
	t.Run("syntax failure still fails with FS check", func(t *testing.T) {
		t.Parallel()
		p := Profile{Name: "k", Host: "-evil", KeyPath: keyFile}
		if err := p.ValidateWithFS(); err == nil {
			t.Fatal("ValidateWithFS skipped the syntax validation")
		}
	})
}

// TestFind pins the ONLY path from a client string to a Profile.
func TestFind(t *testing.T) {
	t.Parallel()
	ps := []Profile{{Name: "a", Host: "ha"}, {Name: "b", Host: "hb"}}
	if got, ok := Find(ps, "b"); !ok || got.Host != "hb" {
		t.Fatalf("Find(b) = %+v, %v", got, ok)
	}
	for _, miss := range []string{"", "c", "A", "a ", " a"} {
		if _, ok := Find(ps, miss); ok {
			t.Fatalf("Find(%q) matched — lookup must be exact", miss)
		}
	}
}

// TestDisplayTargetKeyHint pins the picker-facing helpers, in particular that
// KeyHint discloses only a BASENAME (plan §6.2 — the dashboard must not leak
// the operator's filesystem layout).
func TestDisplayTargetKeyHint(t *testing.T) {
	t.Parallel()
	p := Profile{Name: "demo-box", Label: "Client demo", Host: "h.example.com", User: "ubuntu", Port: 2222, KeyPath: "/home/dev/.ssh/id_demo"}
	if got := p.Display(); got != "Client demo" {
		t.Fatalf("Display = %q", got)
	}
	if got := (Profile{Name: "n", Host: "h"}).Display(); got != "n" {
		t.Fatalf("Display without label = %q, want the name", got)
	}
	if got := p.Target(); got != "ubuntu@h.example.com:2222" {
		t.Fatalf("Target = %q", got)
	}
	if got := (Profile{Host: "h", Port: 22}).Target(); got != "h" {
		t.Fatalf("Target with default port = %q, want bare host", got)
	}
	if got := p.KeyHint(); got != "id_demo" {
		t.Fatalf("KeyHint = %q, want the basename only", got)
	}
	if strings.Contains(p.KeyHint(), "/") {
		t.Fatalf("KeyHint leaked a directory component: %q", p.KeyHint())
	}
	if got := (Profile{Host: "h"}).KeyHint(); got != "" {
		t.Fatalf("KeyHint without a key = %q, want empty", got)
	}
}
