package winrelay

import (
	"fmt"
	"strings"
)

// DefaultPort is the relay's loopback port on the Windows host. It is not the
// proxy's default port (8820) nor any other port Observer binds by default
// (8821 browser ingest, 8823 process bridge, 8082 dashboard), so a relay and a
// proxy on one host (WSL2 mirrored networking shares the loopback) never
// collide; ValidatePorts refuses a configured clash.
const DefaultPort = 8829

// DefaultProxyPort is the proxy port the relay forwards to when none is
// given ([proxy].port's default).
const DefaultProxyPort = 8820

// RoutePrefix starts every relay path. The segment after it names the tool
// whose lane serves the request, so a recorded bypass names the tool without
// reading anything the client sent beyond the path.
const RoutePrefix = "/r/"

// Lane is one tool the relay serves.
type Lane struct {
	// Tool is the registry tool id, the path segment after RoutePrefix.
	Tool string
	// Direct is the provider base URL a fail-open forward goes to: the
	// upstream the tool itself uses when no route is set.
	Direct string
}

// lanes is the closed lane table (CLAUDE.md #5). Only tools whose direct
// upstream follows from the path alone have a row: Claude Code's Messages API
// is always api.anthropic.com when ANTHROPIC_BASE_URL is the route. Codex is
// deliberately absent: its direct upstream depends on the credential kind
// (an API key goes to api.openai.com, a ChatGPT sign-in to chatgpt.com's
// codex backend, the split the proxy makes in isChatGPTAuthRequest), and the
// relay never inspects a credential, so it cannot choose; the codex-windows
// route keeps its WSL proxy target (follow-up in the lane report).
var lanes = []Lane{
	{Tool: "claude-code", Direct: "https://api.anthropic.com"},
}

// Lanes returns a copy of the lane table.
func Lanes() []Lane { return append([]Lane(nil), lanes...) }

// LaneFor returns the lane serving tool.
func LaneFor(tool string) (Lane, bool) {
	for _, l := range lanes {
		if l.Tool == tool {
			return l, true
		}
	}
	return Lane{}, false
}

// RouteURL is the base URL a Windows-side route writer points tool at when
// the relay serves it: http://127.0.0.1:<port>/r/<tool>. The address is the
// IPv4 loopback literal, never "localhost": the relay binds only 127.0.0.1,
// and a client that resolves localhost to ::1 first would be refused. ok is
// false for a tool with no lane or an out-of-range port.
func RouteURL(port int, tool string) (string, bool) {
	if _, ok := LaneFor(tool); !ok || !validPort(port) {
		return "", false
	}
	return fmt.Sprintf("http://127.0.0.1:%d%s%s", port, RoutePrefix, tool), true
}

// ParseRoutePath splits a relay request path into the lane tool and the path
// the upstream receives ("/r/claude-code/v1/messages" -> "claude-code",
// "/v1/messages"). ok is false for a path outside RoutePrefix, an empty or
// unknown tool, or a rest that is not empty or rooted.
func ParseRoutePath(path string) (tool, rest string, ok bool) {
	after, found := strings.CutPrefix(path, RoutePrefix)
	if !found {
		return "", "", false
	}
	tool, rest, _ = strings.Cut(after, "/")
	if _, known := LaneFor(tool); !known {
		return "", "", false
	}
	if rest == "" {
		return tool, "/", true
	}
	return tool, "/" + rest, true
}

// ValidatePorts checks the relay's listen port against the proxy port it
// forwards to: both in range, and never the same port (a relay on the proxy's
// port would forward to itself, and on a host whose loopback WSL2 shares the
// two listeners would fight over one port). The proxy's default port is
// refused as a listen port even when the proxy runs elsewhere.
func ValidatePorts(listen, proxy int) error {
	switch {
	case !validPort(listen):
		return fmt.Errorf("winrelay: listen port %d is out of range", listen)
	case !validPort(proxy):
		return fmt.Errorf("winrelay: proxy port %d is out of range", proxy)
	case listen == proxy:
		return fmt.Errorf("winrelay: listen port %d is the proxy's port; the relay must use its own port", listen)
	case listen == DefaultProxyPort:
		return fmt.Errorf("winrelay: listen port %d is the proxy's default port; the relay must use its own port", listen)
	}
	return nil
}

func validPort(p int) bool { return p > 0 && p <= 65535 }
