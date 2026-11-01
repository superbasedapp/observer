package sandboxnet

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestHostRules_Check(t *testing.T) {
	t.Parallel()
	h, err := ParseHostRules([]string{"registry.npmjs.org", "*.npmjs.org", "github.com"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host, want string
	}{
		{"registry.npmjs.org", ""},
		{"REGISTRY.NPMJS.ORG", ""},
		{"Registry.Npmjs.Org", ""},
		{"cdn.registry.npmjs.org", ""},
		{"a.npmjs.org", ""},
		{"github.com", ""},
		{"npmjs.org", RuleHostNotListed},
		{"evilnpmjs.org", RuleHostNotListed},
		{"npmjs.org.evil.com", RuleHostNotListed},
		{"api.github.com", RuleHostNotListed},
		{"registry.npmjs.org.", RuleHostNameInvalid},
		{"regístry.npmjs.org", RuleHostNameInvalid},
		{"xn--regstry-9ya.npmjs.org", ""},
		{"xn--regstry-9ya.example.org", RuleHostNotListed},
		{"reg_istry.npmjs.org", RuleHostNameInvalid},
		{"-a.npmjs.org", RuleHostNameInvalid},
		{"a..npmjs.org", RuleHostNameInvalid},
		{"", RuleHostNameInvalid},
		{"203.0.113.7", RuleLiteralIP},
		{"2001:db8::1", RuleLiteralIP},
		{"[2001:db8::1]", RuleLiteralIP},
		{strings.Repeat("a", 64) + ".npmjs.org", RuleHostNameInvalid},
	}
	for _, c := range cases {
		if got := h.Check(c.host); got != c.want {
			t.Errorf("Check(%q) = %q, want %q", c.host, got, c.want)
		}
	}
	var none *HostRules
	if got := none.Check("anything.example"); got != "" {
		t.Errorf("a nil list refused %q", got)
	}
}

func TestParseHostRules_Refuses(t *testing.T) {
	t.Parallel()
	bad := [][]string{
		nil,
		{""},
		{" registry.npmjs.org"},
		{"Registry.npmjs.org"},
		{"203.0.113.7"},
		{"[2001:db8::1]"},
		{"registry.npmjs.org."},
		{"*"},
		{"*.org"},
		{"a.*.npmjs.org"},
		{"*npmjs.org"},
		{"localhost"},
		{"xn--80ak6aa92e.com"},
		{"regístry.npmjs.org"},
	}
	for _, b := range bad {
		if _, err := ParseHostRules(b); err == nil {
			t.Errorf("ParseHostRules(%q) accepted", b)
		}
	}
	h, err := ParseHostRules([]string{"b.example.com", "*.a.example.com", "b.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.Entries(), ","); got != "*.a.example.com,b.example.com" {
		t.Errorf("Entries = %q", got)
	}
}

// listedNet is a fake network whose one listed name resolves public and one
// listed name resolves private.
func listedNet(t *testing.T) (*fakeNet, *Gateway) {
	t.Helper()
	echo := startTCPServer(t, echoHandler)
	f := &fakeNet{
		resolve: map[string][]net.IP{
			"registry.npmjs.org":   {testPublicIP},
			"evilnpmjs.org":        {testPublicIP},
			"private.npmjs.org":    {net.ParseIP("10.9.8.7")},
			"other.example.com":    {testPublicIP},
			"registry.npmjs.org.":  {testPublicIP},
			"intranet.example.com": {net.ParseIP("192.168.0.4")},
		},
		routes: map[string]string{"203.0.113.7:443": echo, "203.0.113.7:80": echo},
	}
	g := f.gateway()
	h, err := ParseHostRules([]string{"registry.npmjs.org", "*.npmjs.org"})
	if err != nil {
		t.Fatal(err)
	}
	g.Hosts = h
	return f, g
}

func TestGateway_HostListConnect(t *testing.T) {
	t.Parallel()
	cases := []struct {
		target   string
		status   int
		rule     string
		resolved bool
	}{
		{"registry.npmjs.org:443", http.StatusOK, "", true},
		{"REGISTRY.npmjs.org:443", http.StatusOK, "", true},
		{"evilnpmjs.org:443", http.StatusForbidden, RuleHostNotListed, false},
		{"other.example.com:443", http.StatusForbidden, RuleHostNotListed, false},
		{"registry.npmjs.org.:443", http.StatusForbidden, RuleHostNameInvalid, false},
		{"203.0.113.7:443", http.StatusForbidden, RuleLiteralIP, false},
		{"private.npmjs.org:443", http.StatusForbidden, RulePrivate, true},
	}
	for _, c := range cases {
		t.Run(c.target, func(t *testing.T) {
			t.Parallel()
			f, g := listedNet(t)
			path := startGateway(t, g)
			resp, conn, _ := rawRequest(t, path, http.MethodConnect, connectHead(c.target), "")
			defer func() { _ = conn.Close() }()
			if resp.StatusCode != c.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, c.status)
			}
			if c.rule != "" {
				body, _ := io.ReadAll(resp.Body)
				if !strings.Contains(string(body), "rule "+c.rule) {
					t.Errorf("body %q does not name rule %s", body, c.rule)
				}
			}
			if got := len(f.resolves()) > 0; got != c.resolved {
				t.Errorf("resolved = %v, want %v (the list is checked before resolution)", got, c.resolved)
			}
			if c.status != http.StatusOK && len(f.dials()) > 0 {
				t.Errorf("a refused target was dialled: %v", f.dials())
			}
		})
	}
}

func TestGateway_HostListAbsoluteForm(t *testing.T) {
	t.Parallel()
	cases := []struct {
		url  string
		rule string
	}{
		{"http://evilnpmjs.org/x", RuleHostNotListed},
		{"http://203.0.113.7/x", RuleLiteralIP},
		{"http://private.npmjs.org/x", RulePrivate},
	}
	for _, c := range cases {
		f, g := listedNet(t)
		path := startGateway(t, g)
		host, _, _ := strings.Cut(strings.TrimPrefix(c.url, "http://"), "/")
		resp, conn, _ := rawRequest(t, path, http.MethodGet, "GET "+c.url+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n", "")
		body, _ := io.ReadAll(resp.Body)
		_ = conn.Close()
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "rule "+c.rule) {
			t.Errorf("%s: %d %q, want 403 naming %s", c.url, resp.StatusCode, body, c.rule)
		}
		if len(f.dials()) > 0 {
			t.Errorf("%s: dialled %v", c.url, f.dials())
		}
	}
}

func TestRefusalLogger_OneUserLinePerHost(t *testing.T) {
	t.Parallel()
	var runLog []string
	var user bytes.Buffer
	_, g := listedNet(t)
	g.Logger = RefusalLogger(func(s string) { runLog = append(runLog, s) }, &user)
	path := startGateway(t, g)
	for i := 0; i < 3; i++ {
		resp, conn, _ := rawRequest(t, path, http.MethodConnect, connectHead("evilnpmjs.org:443"), "")
		_ = resp.Body.Close()
		_ = conn.Close()
	}
	resp, conn, _ := rawRequest(t, path, http.MethodConnect, connectHead("203.0.113.7:443"), "")
	_ = resp.Body.Close()
	_ = conn.Close()
	want := "\r\nobserver sandbox: blocked evilnpmjs.org (host-not-listed)\r\n\r\nobserver sandbox: blocked 203.0.113.7 (literal-ip)\r\n"
	if user.String() != want {
		t.Errorf("user lines %q, want %q", user.String(), want)
	}
	if len(runLog) != 4 {
		t.Fatalf("run log has %d lines, want 4: %q", len(runLog), runLog)
	}
	for _, l := range runLog {
		if !strings.Contains(l, LogEgressRefused) || strings.Contains(l, "\n") {
			t.Errorf("run log line %q", l)
		}
	}
	if strings.Contains(user.String(), "WARN") || strings.Contains(user.String(), "level=") {
		t.Errorf("the user saw a log-formatted line: %q", user.String())
	}
}

func TestRefusalLogger_ControlCharactersNeverReachTheTerminal(t *testing.T) {
	t.Parallel()
	var user bytes.Buffer
	l := RefusalLogger(nil, &user)
	l.Warn(LogEgressRefused, "host", "a\x1b[2Jb", "rules", RuleHostNameInvalid)
	if strings.ContainsRune(user.String(), 0x1b) {
		t.Errorf("an escape reached the terminal: %q", user.String())
	}
}
