package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/proxyauth"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

func clientAuthTestConfig(t *testing.T, routes, require bool) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Proxy.ClientAuthRoutes, cfg.Proxy.RequireClientAuth = routes, require
	cfg.Proxy.ClientTokenFile = filepath.Join(t.TempDir(), "proxy-client-token")
	return cfg
}

// TestProxyClientTokenOffTouchesNothing: with both switches off (the
// default) no token exists and no file is created.
func TestProxyClientTokenOffTouchesNothing(t *testing.T) {
	cfg := clientAuthTestConfig(t, false, false)
	tok, err := proxyClientToken(cfg, true)
	if err != nil || tok != "" {
		t.Fatalf("token %q err %v", tok, err)
	}
	if _, err := os.Stat(cfg.Proxy.ClientTokenFile); !os.IsNotExist(err) {
		t.Fatalf("a token file was created with client auth off: %v", err)
	}
	if got, enf := wireProxyClientAuth(cfg, 8820, newLogger("error")); got != "" || enf.Enforce {
		t.Fatalf("wire with client auth off: %q %+v", got, enf)
	}
}

// TestWireProxyClientAuthHonoursAnExistingToken: with both switches off a
// token file left from an earlier opt-in is still loaded read-only (audit
// F2), never enforced, and an absent file is never created.
func TestWireProxyClientAuthHonoursAnExistingToken(t *testing.T) {
	on := clientAuthTestConfig(t, true, false)
	tok, err := proxyClientToken(on, true)
	if err != nil || tok == "" {
		t.Fatalf("seed token: %q %v", tok, err)
	}
	off := on
	off.Proxy.ClientAuthRoutes = false
	got, enf := wireProxyClientAuth(off, 8820, newLogger("error"))
	if got != tok || enf.Enforce {
		t.Fatalf("switches off with a token file: %q %+v", got, enf)
	}
	if routes := launchProxyURL(off, "claude-code", "http://127.0.0.1:8820", false); routes != "http://127.0.0.1:8820" {
		t.Fatalf("a launcher wrote the token form with the switches off: %q", routes)
	}
}

// TestProxyClientTokenCreatedOwnerOnly: a switch on creates one owner-only
// token; a read-only caller (a launcher) sees the same token and never
// creates one.
func TestProxyClientTokenCreatedOwnerOnly(t *testing.T) {
	cfg := clientAuthTestConfig(t, true, false)
	if tok, _ := proxyClientToken(cfg, false); tok != "" {
		t.Fatalf("a read-only caller created or found a token: %q", tok)
	}
	tok, err := proxyClientToken(cfg, true)
	if err != nil || !proxyauth.ValidToken(tok) {
		t.Fatalf("token %q err %v", tok, err)
	}
	if again, _ := proxyClientToken(cfg, false); again != tok {
		t.Fatalf("read-only read %q, want the created token", again)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(cfg.Proxy.ClientTokenFile)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("token file mode: %v %v", fi, err)
		}
	}
}

// TestLaunchProxyURL: only a covered launcher of a carrier row gets the
// token form, never an explicit --proxy override, never with client auth off.
func TestLaunchProxyURL(t *testing.T) {
	cfg := clientAuthTestConfig(t, true, false)
	tok, err := proxyClientToken(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	const plain = "http://127.0.0.1:8820"
	if got := launchProxyURL(cfg, "claude-code", plain, false); got != plain+"/t/"+tok {
		t.Errorf("claude-code: %q", got)
	}
	for _, c := range []struct {
		name     string
		cfg      config.Config
		tool     string
		override bool
	}{
		{"codex launcher (argv) stays plain", cfg, "codex", false},
		{"non-carrier stays plain", cfg, "gemini-cli", false},
		{"explicit --proxy is the operator's", cfg, "claude-code", true},
		{"client auth off", clientAuthTestConfig(t, false, false), "claude-code", false},
	} {
		if got := launchProxyURL(c.cfg, c.tool, plain, c.override); got != plain {
			t.Errorf("%s: %q, want the plain form", c.name, got)
		}
	}
}

// TestProxyClientAuthFacts: every fact that would break a live route holds
// enforcement off, and with none of them it is enforced.
func TestProxyClientAuthFacts(t *testing.T) {
	cfg := clientAuthTestConfig(t, false, true)
	const tok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	none := func(integration.Capability) bool { return false }
	tokened := []proxyroute.RouteStatus{{Tool: "claude-code", State: proxyroute.RouteOurs, Port: 8820, ClientAuth: true}}
	for _, c := range []struct {
		name      string
		routes    []proxyroute.RouteStatus
		installed func(integration.Capability) bool
		sandbox   bool
		enforce   bool
		blocking  string
	}{
		{"every route carries the token", tokened, none, false, true, ""},
		{"a plain config route at this port", append(tokened, proxyroute.RouteStatus{Tool: "codex", State: proxyroute.RouteOurs, Port: 8820}), none, false, false, "codex (config route)"},
		{"a plain route at another port is not this proxy's", append(tokened, proxyroute.RouteStatus{Tool: "codex", State: proxyroute.RouteOurs, Port: 9999}), none, false, true, ""},
		{"an installed launcher tool with the plain form", tokened, func(c integration.Capability) bool { return c.Tool == "opencode" }, false, false, "opencode (launcher route)"},
		{"the claude launcher carries the token", tokened, func(c integration.Capability) bool { return c.Tool == "claude-code" }, false, true, ""},
		{"sandboxed terminals", tokened, none, true, false, "sandboxed terminals"},
	} {
		enf := proxyauth.Enforce(proxyClientAuthFacts(cfg, tok, 8820, c.routes, c.installed, c.sandbox))
		if enf.Enforce != c.enforce || (c.blocking != "" && !strings.Contains(strings.Join(enf.Blocking, ","), c.blocking)) {
			t.Errorf("%s: %+v", c.name, enf)
		}
	}
	if enf := proxyauth.Enforce(proxyClientAuthFacts(cfg, "", 8820, tokened, none, false)); enf.Enforce {
		t.Error("enforced without a token")
	}
}

// TestURLRoutesToProxyTokenForm: the route proof accepts the client token
// form of the proxy's own route, and nothing more.
func TestURLRoutesToProxyTokenForm(t *testing.T) {
	const tok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const proxy = "http://127.0.0.1:8820"
	for _, c := range []struct {
		got  string
		want bool
	}{
		{"http://127.0.0.1:8820/t/" + tok, true},
		{"http://127.0.0.1:8820/t/" + tok + "/v1", true},
		{"http://127.0.0.1:8820/t/nottoken/v1", false},
		{"http://127.0.0.1:8821/t/" + tok + "/v1", false},
		{"http://127.0.0.1:8820/t/" + tok + "/up/x/v1", false},
	} {
		if got := urlRoutesToProxy(c.got, proxy); got != c.want {
			t.Errorf("urlRoutesToProxy(%q) = %v, want %v", c.got, got, c.want)
		}
	}
}

// TestProxyClientTokenRefusesAReadableFile: a token file other accounts can
// read is never used (audit F6). POSIX only here: readLocalTokenFile repairs
// group and other bits of a file of ours, so the case is a file whose
// repair is undone by the test right before the owner-only check; on Windows
// the same check reads the DACL (fsatomic.IsOwnerOnly).
func TestProxyClientTokenRefusesAReadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the POSIX mode case; Windows is the DACL check")
	}
	cfg := clientAuthTestConfig(t, true, false)
	if _, err := proxyClientToken(cfg, true); err != nil {
		t.Fatal(err)
	}
	if err := proxyTokenFileOwnerOnly(cfg.Proxy.ClientTokenFile); err != nil {
		t.Fatalf("a freshly created token file: %v", err)
	}
	if err := os.Chmod(cfg.Proxy.ClientTokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := proxyTokenFileOwnerOnly(cfg.Proxy.ClientTokenFile); err == nil {
		t.Fatal("a world-readable token file passed the owner-only check")
	}
	// The read path repairs the bits first, then the check passes.
	if tok, err := proxyClientToken(cfg, false); err != nil || tok == "" {
		t.Fatalf("read after repair: %q %v", tok, err)
	}
	if fi, _ := os.Stat(filepath.Dir(cfg.Proxy.ClientTokenFile)); fi == nil {
		t.Fatal("token dir missing")
	}
}

// TestProxyClientTokenDirIsOwnerOnly: a directory the token writer creates
// is 0700.
func TestProxyClientTokenDirIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits")
	}
	cfg := clientAuthTestConfig(t, true, false)
	cfg.Proxy.ClientTokenFile = filepath.Join(t.TempDir(), "fresh", "proxy-client-token")
	if _, err := proxyClientToken(cfg, true); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Dir(cfg.Proxy.ClientTokenFile))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("token dir mode: %v %v", fi, err)
	}
}
