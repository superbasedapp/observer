package sandbox

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// Egress is the closed vocabulary of network tiers a sandboxed launch can run
// under (security ledger SR27-SBX-1). The v1 sandbox shared the host network
// namespace, so a sandboxed agent could call the daemon's loopback dashboard
// (launch an unsandboxed terminal, write config) exactly like a local CLI.
// Every tier except EgressHost gives the sandbox its OWN network namespace
// (`bwrap --unshare-net`, loopback only), which removes the host's 127.0.0.1
// from the agent's reach outright; what is then let back in is decided by the
// row in egressProfiles, never by a branch on a tool name.
type Egress string

const (
	// EgressHost shares the host network namespace (the v1 behaviour). The
	// daemon's loopback control plane stays reachable from inside the
	// sandbox; kept as an explicit escape hatch for hosts where the other
	// tiers cannot work.
	EgressHost Egress = "host"
	// EgressInternet is an isolated namespace in which the observer model
	// proxy port is forwarded in and general traffic leaves through the
	// host-side egress gateway (HTTP(S)_PROXY), which refuses every
	// host-local destination. The default tier.
	EgressInternet Egress = "internet"
	// EgressProxyOnly is an isolated namespace in which ONLY the observer
	// model proxy port is reachable. No other egress at all.
	EgressProxyOnly Egress = "proxy_only"
	// EgressNone is an isolated namespace with loopback only: nothing is
	// forwarded in, not even the model proxy.
	EgressNone Egress = "none"
)

// DefaultEgress is the tier an empty [terminal.sandbox].egress resolves to.
const DefaultEgress = EgressInternet

// EgressProfile is one row of the tier table: what a tier builds. The planner
// and the cmd seam read the capability columns, never the Mode string.
type EgressProfile struct {
	// Mode is the tier's config spelling.
	Mode Egress
	// UnshareNet gives the sandbox its own network namespace.
	UnshareNet bool
	// ForwardProxy forwards the observer model proxy port into the
	// namespace through a unix socket.
	ForwardProxy bool
	// Gateway exposes the host-side egress gateway (HTTP forward proxy that
	// refuses host-local destinations) and points HTTP(S)_PROXY at it.
	Gateway bool
	// ControlPlaneReachable reports whether the daemon's loopback control
	// plane (dashboard) is reachable from inside the sandbox. True only for
	// the shared-namespace tier.
	ControlPlaneReachable bool
	// Summary is the one-line operator-facing description (no em-dashes).
	Summary string
}

// egressProfiles is the tier table, walked by ResolveEgress. One row per tier;
// adding a tier is adding a row.
var egressProfiles = []EgressProfile{
	{
		Mode:                  EgressHost,
		ControlPlaneReachable: true,
		Summary:               "shares the host network; the daemon's loopback dashboard stays reachable from inside the sandbox",
	},
	{
		Mode:         EgressInternet,
		UnshareNet:   true,
		ForwardProxy: true,
		Gateway:      true,
		Summary:      "own network namespace; model API through the observer proxy, internet through the egress gateway (host-local addresses refused)",
	},
	{
		Mode:         EgressProxyOnly,
		UnshareNet:   true,
		ForwardProxy: true,
		Summary:      "own network namespace; only the observer model proxy is reachable",
	},
	{
		Mode:       EgressNone,
		UnshareNet: true,
		Summary:    "own network namespace with loopback only; nothing is reachable, not even the model proxy",
	},
}

// EgressProfiles returns a copy of the tier table in its canonical order.
func EgressProfiles() []EgressProfile {
	return append([]EgressProfile(nil), egressProfiles...)
}

// EgressModes returns the tier spellings in canonical order (config
// validation and the dashboard selector read this, so the list has one
// owner).
func EgressModes() []string {
	out := make([]string, 0, len(egressProfiles))
	for _, p := range egressProfiles {
		out = append(out, string(p.Mode))
	}
	return out
}

// ResolveEgress maps a config value to its tier row. Empty resolves to
// DefaultEgress; an unknown value is an error (fail closed, never a silent
// shared-namespace fallback).
func ResolveEgress(s string) (EgressProfile, error) {
	mode := Egress(strings.TrimSpace(s))
	if mode == "" {
		mode = DefaultEgress
	}
	for _, p := range egressProfiles {
		if p.Mode == mode {
			return p, nil
		}
	}
	return EgressProfile{}, fmt.Errorf("sandbox.ResolveEgress: egress %q not in {%s}", s, strings.Join(EgressModes(), ", "))
}

// Network-tier wire vocabulary. The helper verbs are argv[1] of the observer
// binary itself: HostVerb runs OUTSIDE the sandbox (it owns the unix sockets
// and spawns bwrap), GuestVerb runs INSIDE it (it listens on the in-namespace
// loopback ports and spawns the real launcher). One owner for every spelling
// so the planner, the cmd dispatcher and the parsers can never drift.
const (
	// HostVerb is the host-side network helper subcommand.
	HostVerb = "sandbox-host"
	// GuestVerb is the in-sandbox network helper subcommand.
	GuestVerb = "sandbox-guest"
	// GuestSocketDir is where the per-run host socket dir is bound
	// (read-only) inside the sandbox. It sits in the sandbox's private /tmp
	// tmpfs, so no other run's sockets are visible.
	GuestSocketDir = "/tmp/.observer-sandbox-net"
	// ProxySocketName is the model-proxy socket file in a socket dir.
	ProxySocketName = "proxy.sock"
	// GatewaySocketName is the egress-gateway socket file in a socket dir.
	GatewaySocketName = "gateway.sock"

	flagSockDir     = "--sock-dir"
	flagProxyAddr   = "--proxy-addr"
	flagGateway     = "--gateway"
	flagAllowCIDR   = "--egress-allow-cidr"
	flagPlaceFile   = "--placeholder-file"
	flagPlaceDir    = "--placeholder-dir"
	flagProxyPort   = "--proxy-port"
	flagProxySock   = "--proxy-sock"
	flagGatewayPort = "--gateway-port"
	flagGatewaySock = "--gateway-sock"

	// defaultGatewayPort is the in-namespace port the egress gateway is
	// forwarded on. The namespace is private, so any port is free; this one
	// is only moved when it collides with the proxy port.
	defaultGatewayPort = 3128
	// maxUnixSocketPath is the conservative sun_path budget (108 on Linux,
	// minus the terminating NUL).
	maxUnixSocketPath = 107
)

// NetRequest is the network-tier input to BuildPlan.
//
//   - Egress        the resolved tier (use ResolveEgress); empty is rejected so
//     a caller can never silently fall back to the shared namespace.
//   - HostSocketDir absolute per-run dir the host helper creates (0700, must
//     not pre-exist) and bind-mounts read-only at GuestSocketDir. Required
//     when the tier forwards anything.
//   - ProxyPort     the host observer proxy TCP port, forwarded in under the
//     same port number so the in-sandbox launcher's proxy URL is unchanged.
//   - EgressAllowCIDRs the operator's private-destination allow-list for the
//     egress gateway ([terminal.sandbox].egress_allow_cidrs). Passed to the
//     host helper verbatim (one flag per entry) for a tier with a gateway and
//     ignored otherwise; the helper parses them with the gateway's own
//     validator and refuses to start on a bad entry.
type NetRequest struct {
	Egress           Egress
	HostSocketDir    string
	ProxyPort        int
	EgressAllowCIDRs []string
}

// GatewayPort is the in-namespace port the egress gateway listens on for a
// given proxy port.
func GatewayPort(proxyPort int) int {
	if proxyPort == defaultGatewayPort {
		return defaultGatewayPort + 1
	}
	return defaultGatewayPort
}

// resolveNet validates a NetRequest against its tier row.
func resolveNet(n NetRequest) (EgressProfile, error) {
	if n.Egress == "" {
		return EgressProfile{}, fmt.Errorf("network egress tier is empty (resolve the configured value with ResolveEgress)")
	}
	prof, err := ResolveEgress(string(n.Egress))
	if err != nil {
		return EgressProfile{}, err
	}
	if prof.ForwardProxy || prof.Gateway {
		if err := validateAbs(n.HostSocketDir, true); err != nil {
			return EgressProfile{}, fmt.Errorf("host socket dir: %w", err)
		}
		if filepath.Clean(n.HostSocketDir) != n.HostSocketDir {
			return EgressProfile{}, fmt.Errorf("host socket dir %q must be clean", n.HostSocketDir)
		}
		longest := filepath.Join(n.HostSocketDir, GatewaySocketName)
		if len(longest) > maxUnixSocketPath {
			return EgressProfile{}, fmt.Errorf("host socket dir %q is too long for a unix socket path (%d > %d bytes)", n.HostSocketDir, len(longest), maxUnixSocketPath)
		}
	}
	if prof.ForwardProxy && (n.ProxyPort <= 0 || n.ProxyPort > 65535) {
		return EgressProfile{}, fmt.Errorf("proxy port %d out of range", n.ProxyPort)
	}
	if prof.Gateway {
		for _, c := range n.EgressAllowCIDRs {
			if err := validateToken(c); err != nil {
				return EgressProfile{}, fmt.Errorf("egress allow cidr: %w", err)
			}
		}
	}
	return prof, nil
}

// validateToken guards a free-form helper argument (a CIDR): non-empty, not
// flag-shaped, no NUL / whitespace / control character.
func validateToken(v string) error {
	if v == "" {
		return fmt.Errorf("empty value")
	}
	if strings.HasPrefix(v, "-") {
		return fmt.Errorf("%q must not begin with '-'", v)
	}
	if badCharIndex(v) >= 0 {
		return fmt.Errorf("%q contains a NUL, whitespace, or control character", v)
	}
	return nil
}

// HostArgv returns the host-side helper prefix for a network request with no
// protected-path placeholders (see Plan.HostArgv, which the launch path
// uses): [observerBin, HostVerb, --sock-dir D, --proxy-addr 127.0.0.1:P,
// (--gateway (--egress-allow-cidr C)...), "--"]. The cmd seam appends the
// resolved bwrap path and the plan's argv after it. It returns nil when the
// helper has nothing to do, where bwrap is exec'd directly.
func HostArgv(observerBin string, n NetRequest) ([]string, error) {
	return hostArgv(observerBin, n, nil)
}

// HostArgv is the host-side helper prefix for this plan: its network tier's
// forwarding plus the protected-path placeholders the helper must create on
// the host before bwrap runs (so a sandboxed process cannot create them
// first) and remove again afterwards. It returns nil when the helper has
// nothing to do.
func (p Plan) HostArgv(observerBin string) ([]string, error) {
	return hostArgv(observerBin, p.net, p.placeholders)
}

// hostArgv composes the helper prefix. --sock-dir is emitted only for a tier
// that forwards something; placeholders ride as --placeholder-file /
// --placeholder-dir, one flag per path.
func hostArgv(observerBin string, n NetRequest, placeholders []Overlay) ([]string, error) {
	prof, err := resolveNet(n)
	if err != nil {
		return nil, fmt.Errorf("sandbox.HostArgv: %w", err)
	}
	forwards := prof.ForwardProxy || prof.Gateway
	if !forwards && len(placeholders) == 0 {
		return nil, nil
	}
	if err := validateAbs(observerBin, false); err != nil {
		return nil, fmt.Errorf("sandbox.HostArgv: observer bin: %w", err)
	}
	out := []string{observerBin, HostVerb}
	if forwards {
		out = append(out, flagSockDir, n.HostSocketDir)
	}
	if prof.ForwardProxy {
		out = append(out, flagProxyAddr, "127.0.0.1:"+strconv.Itoa(n.ProxyPort))
	}
	if prof.Gateway {
		out = append(out, flagGateway)
		for _, c := range n.EgressAllowCIDRs {
			out = append(out, flagAllowCIDR, c)
		}
	}
	for _, o := range placeholders {
		if err := validateAbs(o.Path, true); err != nil {
			return nil, fmt.Errorf("sandbox.HostArgv: placeholder: %w", err)
		}
		switch o.Placeholder {
		case PlaceholderFile:
			out = append(out, flagPlaceFile, o.Path)
		case PlaceholderDir:
			out = append(out, flagPlaceDir, o.Path)
		default:
			return nil, fmt.Errorf("sandbox.HostArgv: placeholder %q has no kind", o.Path)
		}
	}
	return append(out, argSep), nil
}

// guestArgv returns the in-sandbox helper prefix inserted between bwrap's
// "--" and the real inner argv, or nil for a tier with nothing to forward.
func guestArgv(observerBin string, prof EgressProfile, n NetRequest) []string {
	if !prof.ForwardProxy && !prof.Gateway {
		return nil
	}
	out := []string{observerBin, GuestVerb}
	if prof.ForwardProxy {
		out = append(out,
			flagProxyPort, strconv.Itoa(n.ProxyPort),
			flagProxySock, filepath.Join(GuestSocketDir, ProxySocketName))
	}
	if prof.Gateway {
		out = append(out,
			flagGatewayPort, strconv.Itoa(GatewayPort(n.ProxyPort)),
			flagGatewaySock, filepath.Join(GuestSocketDir, GatewaySocketName))
	}
	return append(out, argSep)
}

// HostArgs is the parsed host-helper command line (HostVerb's own flags plus
// the command it must run after "--").
type HostArgs struct {
	SockDir   string
	ProxyAddr string
	Gateway   bool
	// AllowCIDRs are the raw --egress-allow-cidr values; the helper parses
	// them with the gateway's validator (sandboxnet.ParseAllowCIDRs).
	AllowCIDRs []string
	// PlaceholderFiles / PlaceholderDirs are the absolute protected paths
	// the helper creates before bwrap and removes afterwards if untouched.
	PlaceholderFiles []string
	PlaceholderDirs  []string
	Command          []string
}

// GuestArgs is the parsed guest-helper command line.
type GuestArgs struct {
	ProxyPort   int
	ProxySock   string
	GatewayPort int
	GatewaySock string
	Command     []string
}

// ParseHostArgs parses the arguments AFTER HostVerb. The command after "--"
// is required and must not be flag-shaped. --sock-dir is required whenever
// the helper forwards anything (--proxy-addr or --gateway).
func ParseHostArgs(args []string) (HostArgs, error) {
	var h HostArgs
	rest, err := walkHelperFlags(args, map[string]func(string) error{
		flagSockDir:   func(v string) error { h.SockDir = v; return validateAbs(v, true) },
		flagProxyAddr: func(v string) error { h.ProxyAddr = v; return nil },
		flagAllowCIDR: func(v string) error { h.AllowCIDRs = append(h.AllowCIDRs, v); return validateToken(v) },
		flagPlaceFile: func(v string) error { h.PlaceholderFiles = append(h.PlaceholderFiles, v); return validateAbs(v, true) },
		flagPlaceDir:  func(v string) error { h.PlaceholderDirs = append(h.PlaceholderDirs, v); return validateAbs(v, true) },
	}, map[string]func(){
		flagGateway: func() { h.Gateway = true },
	})
	if err != nil {
		return HostArgs{}, fmt.Errorf("sandbox.ParseHostArgs: %w", err)
	}
	if (h.ProxyAddr != "" || h.Gateway) && h.SockDir == "" {
		return HostArgs{}, fmt.Errorf("sandbox.ParseHostArgs: %s is required", flagSockDir)
	}
	if len(h.AllowCIDRs) > 0 && !h.Gateway {
		return HostArgs{}, fmt.Errorf("sandbox.ParseHostArgs: %s needs %s", flagAllowCIDR, flagGateway)
	}
	h.Command = rest
	return h, nil
}

// ParseGuestArgs parses the arguments AFTER GuestVerb.
func ParseGuestArgs(args []string) (GuestArgs, error) {
	var g GuestArgs
	port := func(dst *int) func(string) error {
		return func(v string) error {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 || n > 65535 {
				return fmt.Errorf("port %q out of range", v)
			}
			*dst = n
			return nil
		}
	}
	rest, err := walkHelperFlags(args, map[string]func(string) error{
		flagProxyPort:   port(&g.ProxyPort),
		flagProxySock:   func(v string) error { g.ProxySock = v; return validateAbs(v, false) },
		flagGatewayPort: port(&g.GatewayPort),
		flagGatewaySock: func(v string) error { g.GatewaySock = v; return validateAbs(v, false) },
	}, nil)
	if err != nil {
		return GuestArgs{}, fmt.Errorf("sandbox.ParseGuestArgs: %w", err)
	}
	if (g.ProxyPort == 0) != (g.ProxySock == "") {
		return GuestArgs{}, fmt.Errorf("sandbox.ParseGuestArgs: %s and %s go together", flagProxyPort, flagProxySock)
	}
	if (g.GatewayPort == 0) != (g.GatewaySock == "") {
		return GuestArgs{}, fmt.Errorf("sandbox.ParseGuestArgs: %s and %s go together", flagGatewayPort, flagGatewaySock)
	}
	g.Command = rest
	return g, nil
}

// walkHelperFlags walks "--flag value" / "--switch" tokens up to the "--"
// separator and returns the command after it. Unknown flags, a missing "--",
// an empty command, and a flag-shaped command[0] are errors.
func walkHelperFlags(args []string, valued map[string]func(string) error, switches map[string]func()) ([]string, error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == argSep {
			rest := args[i+1:]
			if len(rest) == 0 || rest[0] == "" || strings.HasPrefix(rest[0], "-") {
				return nil, fmt.Errorf("a non-flag command is required after %q", argSep)
			}
			return rest, nil
		}
		if set, ok := valued[a]; ok {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s needs a value", a)
			}
			if err := set(args[i+1]); err != nil {
				return nil, fmt.Errorf("%s: %w", a, err)
			}
			i++
			continue
		}
		if on, ok := switches[a]; ok {
			on()
			continue
		}
		return nil, fmt.Errorf("unknown helper flag %q", a)
	}
	return nil, fmt.Errorf("missing %q before the command", argSep)
}

// GuestProxyEnv returns the environment the guest adds for the inner command
// when the egress gateway is in use: every common spelling of the HTTP(S)
// proxy variables pointed at the in-namespace gateway port, and NO_PROXY
// covering loopback so the model proxy (also on 127.0.0.1) is reached
// directly. Values it sets REPLACE any inherited ones (an inherited
// corporate proxy is unreachable from the private namespace anyway).
func GuestProxyEnv(gatewayPort int) []string {
	u := "http://127.0.0.1:" + strconv.Itoa(gatewayPort)
	const noProxy = "127.0.0.1,localhost,::1"
	return []string{
		"HTTP_PROXY=" + u,
		"HTTPS_PROXY=" + u,
		"http_proxy=" + u,
		"https_proxy=" + u,
		"NO_PROXY=" + noProxy,
		"no_proxy=" + noProxy,
	}
}
