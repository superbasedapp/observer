package secassess

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// MaxLaunchJSON is the most bytes of a .claude/launch.json read for
// candidates.
const MaxLaunchJSON = 256 << 10

// MaxLaunchTargetBytes is the longest target address (as Target.String() writes
// it) a launch accepts. ParseTarget takes up to 2048 bytes, as secdast's does,
// but the address stands in the prompt twice (the target line and the result
// example), and a prompt with every optional section at its cap and a longer
// address would pass the argument cap (MaxPromptBytes); TestPromptBudget holds
// the longest address to it.
const MaxLaunchTargetBytes = 512

// ErrNotLoopback is the refusal of a target whose host is not a loopback
// literal or "localhost".
var ErrNotLoopback = errors.New("secassess: the target must be localhost, 127.0.0.0/8 or ::1")

// Target is the one loopback address a pen test or red team exercise is
// scoped to.
//
// ParseTarget and LaunchCandidates are small standard-library copies of
// internal/secdast's rules of the same names. They are copies, not imports,
// because secdast belongs to the optional security.dast component and an
// import from a package that stays in the omit build breaks the component
// fence; secassesssvc's test pins the two against one shared case table.
type Target struct {
	// Scheme is "http" or "https".
	Scheme string
	// Host is "localhost", an IPv4 address in 127.0.0.0/8 or an IPv6
	// loopback address, lower case, without brackets.
	Host string
	// Port is the explicit port, decimal.
	Port string
	// Path is the page path, "/" when none was typed; RawQuery is kept and
	// the fragment dropped.
	Path     string
	RawQuery string
}

// isLoopbackHost reports whether host is "localhost" or a loopback IP
// literal. A name that merely resolves to 127.0.0.1 does not count.
func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsValid() && a.Zone() == "" && a.IsLoopback()
}

// ParseTarget validates a typed URL: http or https, a loopback host, an
// explicit port, no user information.
func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, errors.New("secassess: no target URL")
	}
	if len(raw) > 2048 {
		return Target{}, errors.New("secassess: the URL is over 2048 bytes")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, fmt.Errorf("secassess: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return Target{}, fmt.Errorf("secassess: %q is not an http or https URL (type it as http://localhost:<port>/)", raw)
	}
	if u.Opaque != "" || u.Host == "" {
		return Target{}, fmt.Errorf("secassess: %q has no host", raw)
	}
	if u.User != nil {
		return Target{}, errors.New("secassess: a URL with user information is refused (no credential is ever sent)")
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, "%") || !isLoopbackHost(host) {
		return Target{}, fmt.Errorf("%w (got %q)", ErrNotLoopback, u.Hostname())
	}
	port := u.Port()
	if port == "" {
		return Target{}, fmt.Errorf("secassess: %q has no port: name the development server's port (for example http://localhost:3000/)", raw)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return Target{}, fmt.Errorf("secassess: %q is not a port", port)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		return Target{}, fmt.Errorf("secassess: %q is not an absolute path", path)
	}
	return Target{Scheme: scheme, Host: host, Port: port, Path: path, RawQuery: u.RawQuery}, nil
}

// PortNumber is the port as an int (ParseTarget guarantees it parses).
func (t Target) PortNumber() int {
	n, _ := strconv.Atoi(t.Port)
	return n
}

// Origin is scheme://host:port.
func (t Target) Origin() string {
	h := t.Host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return t.Scheme + "://" + h + ":" + t.Port
}

// String is the page URL.
func (t Target) String() string {
	if t.RawQuery != "" {
		return t.Origin() + t.Path + "?" + t.RawQuery
	}
	return t.Origin() + t.Path
}

// Candidate is one dev server URL the developer may pick (from a project's
// dev-server files, never a remote host).
type Candidate struct {
	URL  string `json:"url"`
	Name string `json:"name,omitempty"`
	// Source names the file kind the candidate came from (the StartSource*
	// values); LaunchCandidates leaves it empty.
	Source string `json:"source,omitempty"`
}

type launchFile struct {
	Configurations []struct {
		Name string          `json:"name"`
		Port json.RawMessage `json:"port"`
		URL  string          `json:"url"`
	} `json:"configurations"`
}

// LaunchCandidates reads .claude/launch.json bytes: a configuration's url when
// it is a loopback URL with a port, else http://localhost:<port>/. Anything
// malformed is skipped; nothing is resolved or dialed here.
func LaunchCandidates(data []byte) []Candidate {
	if len(data) == 0 || len(data) > MaxLaunchJSON {
		return nil
	}
	var lf launchFile
	if json.Unmarshal(data, &lf) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []Candidate
	add := func(u, name string) {
		t, err := ParseTarget(u)
		if err != nil || seen[t.String()] {
			return
		}
		seen[t.String()] = true
		out = append(out, Candidate{URL: t.String(), Name: clean(name, 80)})
	}
	for _, c := range lf.Configurations {
		if c.URL != "" {
			add(c.URL, c.Name)
			continue
		}
		if p, ok := launchPort(c.Port); ok {
			add("http://localhost:"+strconv.Itoa(p)+"/", c.Name)
		}
	}
	return out
}

// launchPort accepts a JSON number or a numeric string.
func launchPort(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var n int
	if json.Unmarshal(raw, &n) != nil {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return 0, false
		}
		v, err := strconv.Atoi(s)
		if err != nil {
			return 0, false
		}
		n = v
	}
	return n, n >= 1 && n <= 65535
}
