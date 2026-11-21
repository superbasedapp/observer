package config

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// sandbox_openshell.go is the [terminal.sandbox.openshell] block of the
// OpenShell sandbox row (OpenShell plan doc 04 R2.6 O1, build plan 05
// section 2, lane O1A). It is read only while the terminals.sandbox.openshell
// component is selected AND "openshell" is in [terminal.sandbox].backends.
// Every zero value is the default, so no Default() entry is needed: with no
// block the row is still off (not listed, component inactive), and once it
// is listed an empty gateway_mode resolves to the managed private gateway
// (EffectiveGatewayMode, decision D2).

// TerminalSandboxOpenShellConfig is [terminal.sandbox.openshell].
type TerminalSandboxOpenShellConfig struct {
	// GatewayMode is "managed" (the default, decision D2 OB-039, lane
	// O2): Observer starts and stops a private OpenShell gateway of its
	// own (its own loopback port, config and state, certificates in the
	// OS keychain, telemetry off); or "external" (the opt-in): you install,
	// start and sign in to your own gateway, and Observer never holds its
	// certificates. "" resolves through EffectiveGatewayMode: managed,
	// unless an endpoint is set (an endpoint names your own gateway).
	GatewayMode string `toml:"gateway_mode"`
	// Endpoint is your own gateway's https endpoint in external mode (""
	// uses the openshell CLI's active gateway). It must be on this
	// machine's loopback: the box's mounts are same-path binds of this
	// machine's files, which only a gateway whose runtime runs here can
	// make. Managed mode picks its own port, so an endpoint with
	// gateway_mode = "managed" is refused.
	Endpoint string `toml:"endpoint"`
	// Version pins the OpenShell version (MAJOR.MINOR.PATCH, "" for none):
	// a CLI or gateway at another version is refused. A version outside the
	// tested table is refused either way.
	Version string `toml:"version"`
	// StateDir is where Observer keeps the row's per-run files ("" is
	// ~/.observer/sandbox-openshell); an absolute path.
	StateDir string `toml:"state_dir"`
}

// The gateway_mode values.
const (
	OpenShellGatewayExternal = "external"
	OpenShellGatewayManaged  = "managed"
)

// openShellModeRows is the gateway_mode resolution table (decision D2,
// OB-039), walked top-down: an explicit mode is kept; with none, an
// endpoint means the user's own gateway (external), and otherwise the
// default is the managed private gateway.
var openShellModeRows = []struct {
	mode     string
	endpoint bool
	out      string
}{
	{OpenShellGatewayExternal, false, OpenShellGatewayExternal},
	{OpenShellGatewayExternal, true, OpenShellGatewayExternal},
	{OpenShellGatewayManaged, false, OpenShellGatewayManaged},
	{OpenShellGatewayManaged, true, OpenShellGatewayManaged},
	{"", true, OpenShellGatewayExternal},
	{"", false, OpenShellGatewayManaged},
}

// EffectiveGatewayMode resolves gateway_mode to "managed" or "external"
// ("" for a value validation refuses).
func (c TerminalSandboxOpenShellConfig) EffectiveGatewayMode() string {
	for _, r := range openShellModeRows {
		if r.mode == c.GatewayMode && r.endpoint == (c.Endpoint != "") {
			return r.out
		}
	}
	return ""
}

// openShellVersionRE is the shape of a version pin.
var openShellVersionRE = regexp.MustCompile(`^v?\d{1,4}\.\d{1,4}\.\d{1,4}$`)

// validateTerminalSandboxOpenShell checks [terminal.sandbox.openshell].
func validateTerminalSandboxOpenShell(c TerminalSandboxOpenShellConfig) error {
	switch c.GatewayMode {
	case "", OpenShellGatewayExternal, OpenShellGatewayManaged:
	default:
		return fmt.Errorf("config: terminal.sandbox.openshell.gateway_mode %q not in {external, managed}", c.GatewayMode)
	}
	if c.GatewayMode == OpenShellGatewayManaged && c.Endpoint != "" {
		return fmt.Errorf("config: terminal.sandbox.openshell.endpoint is set but gateway_mode is \"managed\": the managed gateway picks its own loopback port; set gateway_mode = \"external\" to use the gateway at %s", c.Endpoint)
	}
	if c.Endpoint != "" {
		if err := validateOpenShellEndpoint(c.Endpoint); err != nil {
			return err
		}
	}
	if c.Version != "" && !openShellVersionRE.MatchString(c.Version) {
		return fmt.Errorf("config: terminal.sandbox.openshell.version %q is not MAJOR.MINOR.PATCH", c.Version)
	}
	// The row is Linux only, so the state dir is a Linux path: path, not
	// filepath, so the check reads the same on every build host (audit
	// finding O1A-A12: filepath.IsAbs refused /var/lib/... on Windows).
	if c.StateDir != "" && (!path.IsAbs(c.StateDir) || path.Clean(c.StateDir) != c.StateDir) {
		return fmt.Errorf("config: terminal.sandbox.openshell.state_dir %q must be an absolute, clean path", c.StateDir)
	}
	return nil
}

// validateOpenShellEndpoint requires an https URL on the loopback with no
// credentials, path, query or fragment.
func validateOpenShellEndpoint(raw string) error {
	bad := func(why string) error {
		return fmt.Errorf("config: terminal.sandbox.openshell.endpoint %q %s", raw, why)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return bad("is not a URL")
	}
	if u.Scheme != "https" {
		return bad("must be an https URL (OpenShell gateways authenticate over TLS)")
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, " \t\n") {
		return bad("must be scheme, host and port only")
	}
	host := u.Hostname()
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return bad("must be on this machine's loopback (the box's binds are this machine's paths)")
		}
	}
	return nil
}
