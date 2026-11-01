package sandboxnet

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// goldenCases are the list-less gateway's refusals before the host
// allow-list existed (captured at a4acb0d73): a gateway with no Hosts must
// answer each exactly so.
var goldenCases = []struct {
	name, method, target string
	providers            bool
}{
	{"connect loopback literal", http.MethodConnect, "127.0.0.1:443", false},
	{"connect private literal", http.MethodConnect, "10.1.2.3:443", false},
	{"connect metadata literal", http.MethodConnect, "169.254.169.254:80", false},
	{"connect private name", http.MethodConnect, "intranet.example.com:443", false},
	{"connect unresolvable", http.MethodConnect, "nowhere.example.com:443", false},
	{"connect bad port", http.MethodConnect, "registry.npmjs.org:0", false},
	{"connect provider host", http.MethodConnect, "api.anthropic.com:443", true},
	{"connect literal under provider block", http.MethodConnect, "203.0.113.7:443", true},
	{"absolute private name", http.MethodGet, "http://intranet.example.com/x", false},
	{"absolute https", http.MethodGet, "https://registry.npmjs.org/x", false},
	{"origin form", http.MethodGet, "/x", false},
}

func goldenGateway(providers bool) *Gateway {
	g := &Gateway{
		Resolve: func(_ context.Context, host string) ([]net.IP, error) {
			switch host {
			case "intranet.example.com":
				return []net.IP{net.ParseIP("192.168.4.5")}, nil
			case "registry.npmjs.org":
				return []net.IP{testPublicIP}, nil
			}
			return nil, fmt.Errorf("no such host %s", host)
		},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, fmt.Errorf("no dial in the golden test")
		},
		LocalAddrs: func() ([]net.IP, error) { return nil, nil },
		Logger:     discardLogger(),
	}
	if providers {
		g.Providers = NewProviderBlock(nil)
		g.Providers.addrHosts = nil
	}
	return g
}

func goldenAnswer(g *Gateway, method, target string) string {
	var r *http.Request
	if method == http.MethodConnect {
		r = &http.Request{Method: method, Host: target, URL: &url.URL{Host: target}, Header: http.Header{}}
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return fmt.Sprintf("%d %s", w.Code, strings.TrimSpace(w.Body.String()))
}

// TestGateway_ListLessGolden pins a list-less gateway's refusals byte for
// byte (lane SBX-P3C: the host allow-list changes nothing for agent runs).
func TestGateway_ListLessGolden(t *testing.T) {
	var got []string
	for _, c := range goldenCases {
		got = append(got, c.name+": "+goldenAnswer(goldenGateway(c.providers), c.method, c.target))
	}
	if os.Getenv("SBO_PRINT_GOLDEN") != "" {
		fmt.Println(strings.Join(got, "\n"))
	}
	if len(got) != len(listLessGolden) {
		t.Fatalf("%d cases, %d golden lines", len(got), len(listLessGolden))
	}
	for i := range got {
		if got[i] != listLessGolden[i] {
			t.Errorf("case %d\n got %q\nwant %q", i, got[i], listLessGolden[i])
		}
	}
}

var listLessGolden = []string{
	"connect loopback literal: 403 sandbox egress gateway: destination refused by rule loopback",
	"connect private literal: 403 sandbox egress gateway: destination refused by rule private-rfc1918 (to allow a private destination, add its CIDR to [terminal.sandbox].egress_allow_cidrs)",
	"connect metadata literal: 403 sandbox egress gateway: destination refused by rule link-local-unicast",
	"connect private name: 403 sandbox egress gateway: destination refused by rule private-rfc1918 (to allow a private destination, add its CIDR to [terminal.sandbox].egress_allow_cidrs)",
	"connect unresolvable: 502 sandbox egress gateway: cannot resolve host",
	"connect bad port: 400 sandbox egress gateway: target \"registry.npmjs.org:0\" has an invalid port",
	"connect provider host: 403 sandbox egress gateway: destination refused by rule model-provider-host (this run claims full capture, so model API calls must go through the Observer proxy the tool is configured with)",
	"connect literal under provider block: 403 sandbox egress gateway: destination refused by rule literal-ip (this run claims full capture, so model API calls must go through the Observer proxy the tool is configured with)",
	"absolute private name: 403 sandbox egress gateway: destination refused by rule private-rfc1918 (to allow a private destination, add its CIDR to [terminal.sandbox].egress_allow_cidrs)",
	"absolute https: 400 sandbox egress gateway: https requests must use CONNECT",
	"origin form: 400 sandbox egress gateway: this is a forward proxy; send CONNECT or an absolute-form http request",
}
