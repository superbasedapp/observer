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

// EnvEgress names the egress tier a sandboxed launch runs under. A launcher
// that knows the tier sets it beside EnvMarker, so the in-sandbox launcher
// can say the tier's real model route when its proxy check fails (live run
// 2, finding N2). It changes only what is said, never a route.
const EnvEgress = "OBSERVER_SANDBOX_EGRESS"

// ModelRouteNotice is what a launcher inside a sandbox of tier p says when
// it finds no model proxy, read from the tier's columns: "" when the tier
// leaves a direct route (the shared host network, or the egress gateway),
// so the caller's own notice stands; for a tier whose only route is the
// forwarded proxy, that the model is unreachable this run; for a tier with
// nothing forwarded, that the sandbox has no route to the model at all.
func ModelRouteNotice(p EgressProfile, tool, proxyURL string) string {
	switch {
	case !p.UnshareNet || p.Gateway:
		return ""
	case p.ForwardProxy:
		return fmt.Sprintf("observer %s: this sandbox's network tier is %s (%s): the observer proxy at %s is its only route to the model API and it is not reachable, so %s cannot reach the model in this run (nothing goes straight to the provider; turns are NOT captured).", tool, p.Mode, p.Summary, proxyURL, tool)
	default:
		return fmt.Sprintf("observer %s: this sandbox's network tier is %s (%s): %s is launched without proxy routing and has no route to the model API in this run (nothing is sent to the provider from here; the transcript is still captured).", tool, p.Mode, p.Summary, tool)
	}
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
	// flagProviderBlock turns the gateway's model-provider host block on
	// (sandbox plan v2 section 7.3); flagProviderHost adds one host to the
	// closed provider list (the proxy's own configured upstreams).
	flagProviderBlock = "--provider-block"
	flagProviderHost  = "--provider-host"
	// flagPrivateNet tells the host helper the plan unshares the network, so
	// its post-launch re-check (sandboxselect.RecheckBwrap) requires the
	// sandbox's network namespace to differ from the host's.
	flagPrivateNet = "--private-net"
	// flagRelayRun and flagObserverDir turn the capture relay on in the
	// host helper (lane sbx-p2): the run record's id, and the host
	// observer directory that holds it and the daemon's link endpoint.
	flagRelayRun    = "--relay-run"
	flagObserverDir = "--observer-dir"

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
//   - ProviderBlock turns on the gateway's model-provider host block for this
//     run (section 7.3): set by the cmd seam when the run's computed capture
//     is full only through the gateway (rule C6). Ignored without a gateway.
//   - ProviderHosts are hosts added to the gateway's closed provider list
//     (the proxy's own configured upstream hosts).
type NetRequest struct {
	Egress           Egress
	HostSocketDir    string
	ProxyPort        int
	EgressAllowCIDRs []string
	ProviderBlock    bool
	ProviderHosts    []string
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
		if err := validateSockDir(n.HostSocketDir); err != nil {
			return EgressProfile{}, err
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
		for _, h := range n.ProviderHosts {
			if err := validateToken(h); err != nil {
				return EgressProfile{}, fmt.Errorf("provider host: %w", err)
			}
		}
	}
	return prof, nil
}

// validateSockDir checks a per-run host socket dir: absolute, clean, and
// short enough for every socket it will hold.
func validateSockDir(dir string) error {
	if err := validateAbs(dir, true); err != nil {
		return fmt.Errorf("host socket dir: %w", err)
	}
	if filepath.Clean(dir) != dir {
		return fmt.Errorf("host socket dir %q must be clean", dir)
	}
	longest := filepath.Join(dir, GatewaySocketName)
	if len(longest) > maxUnixSocketPath {
		return fmt.Errorf("host socket dir %q is too long for a unix socket path (%d > %d bytes)", dir, len(longest), maxUnixSocketPath)
	}
	return nil
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
// uses): [observerBin, HostVerb, --sock-dir D, (--private-net),
// --proxy-addr 127.0.0.1:P, (--gateway (--egress-allow-cidr C)...), "--"]. The cmd seam appends the
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
	return hostArgvRelay(observerBin, p.net, p.placeholders, p.relay)
}

// hostArgv composes the helper prefix. --sock-dir is emitted only for a tier
// that forwards something; placeholders ride as --placeholder-file /
// --placeholder-dir, one flag per path.
func hostArgv(observerBin string, n NetRequest, placeholders []Overlay) ([]string, error) {
	return hostArgvRelay(observerBin, n, placeholders, RelayRequest{})
}

// hostArgvRelay is hostArgv with the relay: a relayed run always runs the
// helper (it serves the relay socket), with the socket dir and the relay
// flags.
func hostArgvRelay(observerBin string, n NetRequest, placeholders []Overlay, relay RelayRequest) ([]string, error) {
	prof, err := resolveNet(n)
	if err != nil {
		return nil, fmt.Errorf("sandbox.HostArgv: %w", err)
	}
	forwards := prof.ForwardProxy || prof.Gateway
	if !forwards && len(placeholders) == 0 && !relay.Enabled() {
		return nil, nil
	}
	if err := validateAbs(observerBin, false); err != nil {
		return nil, fmt.Errorf("sandbox.HostArgv: observer bin: %w", err)
	}
	out := []string{observerBin, HostVerb}
	if forwards || relay.Enabled() {
		out = append(out, flagSockDir, n.HostSocketDir)
	}
	if relay.Enabled() {
		if !validRunToken(relay.RunID) {
			return nil, fmt.Errorf("sandbox.HostArgv: relay run id %q", relay.RunID)
		}
		if err := validateAbs(relay.HostObserverDir, false); err != nil {
			return nil, fmt.Errorf("sandbox.HostArgv: relay observer dir: %w", err)
		}
		out = append(out, flagRelayRun, relay.RunID, flagObserverDir, relay.HostObserverDir)
	}
	if prof.UnshareNet {
		out = append(out, flagPrivateNet)
	}
	if prof.ForwardProxy {
		out = append(out, flagProxyAddr, "127.0.0.1:"+strconv.Itoa(n.ProxyPort))
	}
	if prof.Gateway {
		out = append(out, flagGateway)
		for _, c := range n.EgressAllowCIDRs {
			out = append(out, flagAllowCIDR, c)
		}
		if n.ProviderBlock {
			out = append(out, flagProviderBlock)
			for _, h := range n.ProviderHosts {
				out = append(out, flagProviderHost, h)
			}
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
	// ProviderBlock turns the gateway's model-provider host block on;
	// ProviderHosts are the extra hosts for its list.
	ProviderBlock bool
	ProviderHosts []string
	// PrivateNet: the plan unshares the network (every tier but host); the
	// helper's post-launch re-check holds the built sandbox to it.
	PrivateNet bool
	// RelayRun and ObserverDir turn the capture relay on: the helper reads
	// the run record under ObserverDir, writes the box record into SockDir
	// and serves the relay socket there.
	RelayRun    string
	ObserverDir string
	Command     []string
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
		flagProviderHost: func(v string) error {
			h.ProviderHosts = append(h.ProviderHosts, v)
			return validateToken(v)
		},
		flagRelayRun: func(v string) error {
			h.RelayRun = v
			if !validRunToken(v) {
				return fmt.Errorf("relay run id %q", v)
			}
			return nil
		},
		flagObserverDir: func(v string) error { h.ObserverDir = v; return validateAbs(v, false) },
	}, map[string]func(){
		flagGateway:       func() { h.Gateway = true },
		flagProviderBlock: func() { h.ProviderBlock = true },
		flagPrivateNet:    func() { h.PrivateNet = true },
	})
	if err != nil {
		return HostArgs{}, fmt.Errorf("sandbox.ParseHostArgs: %w", err)
	}
	if (h.RelayRun == "") != (h.ObserverDir == "") {
		return HostArgs{}, fmt.Errorf("sandbox.ParseHostArgs: %s and %s go together", flagRelayRun, flagObserverDir)
	}
	if (h.ProxyAddr != "" || h.Gateway || h.RelayRun != "") && h.SockDir == "" {
		return HostArgs{}, fmt.Errorf("sandbox.ParseHostArgs: %s is required", flagSockDir)
	}
	if len(h.AllowCIDRs) > 0 && !h.Gateway {
		return HostArgs{}, fmt.Errorf("sandbox.ParseHostArgs: %s needs %s", flagAllowCIDR, flagGateway)
	}
	if (h.ProviderBlock || len(h.ProviderHosts) > 0) && !h.Gateway {
		return HostArgs{}, fmt.Errorf("sandbox.ParseHostArgs: %s and %s need %s", flagProviderBlock, flagProviderHost, flagGateway)
	}
	if len(h.ProviderHosts) > 0 && !h.ProviderBlock {
		return HostArgs{}, fmt.Errorf("sandbox.ParseHostArgs: %s needs %s", flagProviderHost, flagProviderBlock)
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

// RelayOfWrap returns the capture relay's run id and host observer directory
// from a wrap argv HostArgv composed (the host helper's own flags), so the
// launcher can name the run record that belongs to the run it spawns.
// ok=false: the argv carries no host helper or no relay.
func RelayOfWrap(argv []string) (runID, observerDir string, ok bool) {
	for i := 1; i < len(argv); i++ {
		if argv[i] != HostVerb {
			continue
		}
		h, err := ParseHostArgs(argv[i+1:])
		if err != nil || h.RelayRun == "" {
			return "", "", false
		}
		return h.RelayRun, h.ObserverDir, true
	}
	return "", "", false
}
