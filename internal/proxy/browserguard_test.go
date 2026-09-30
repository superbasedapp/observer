package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBrowserProvenanceRefusal walks the provenance table one case per row
// (plus the pass-through shapes every real client uses).
func TestBrowserProvenanceRefusal(t *testing.T) {
	cases := []struct {
		name      string
		host      string
		headers   map[string]string
		hostCheck bool
		want      string
	}{
		{name: "cli client, loopback host", host: "127.0.0.1:8820", hostCheck: true, want: ""},
		{name: "cli client, localhost name", host: "localhost:8820", hostCheck: true, want: ""},
		{name: "cli client, ipv6 loopback", host: "[::1]:8820", hostCheck: true, want: ""},
		{name: "rebound host on loopback bind", host: "rebind.evil.example:8820", hostCheck: true, want: "non_loopback_host"},
		{name: "any host on exposed bind", host: "devbox.lan:8820", hostCheck: false, want: ""},
		{name: "opaque origin", host: "127.0.0.1:8820", headers: map[string]string{"Origin": "null"}, want: "opaque_origin"},
		{name: "cross-origin web page", host: "127.0.0.1:8820", headers: map[string]string{"Origin": "https://evil.example"}, want: "cross_origin_web_page"},
		{name: "http web page", host: "127.0.0.1:8820", headers: map[string]string{"Origin": "http://evil.example:8080"}, want: "cross_origin_web_page"},
		{name: "unparseable origin", host: "127.0.0.1:8820", headers: map[string]string{"Origin": "http://[::1"}, want: "cross_origin_web_page"},
		{name: "loopback web app", host: "127.0.0.1:8820", headers: map[string]string{"Origin": "http://localhost:3000"}, want: ""},
		{name: "desktop renderer scheme", host: "127.0.0.1:8820", headers: map[string]string{"Origin": "vscode-file://vscode-app", "Sec-Fetch-Site": "cross-site"}, want: ""},
		{name: "no-cors cross-site fetch", host: "127.0.0.1:8820", headers: map[string]string{"Sec-Fetch-Site": "cross-site"}, want: "cross_site_fetch"},
		{name: "same-site fetch", host: "127.0.0.1:8820", headers: map[string]string{"Sec-Fetch-Site": "same-site"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
			r.Host = tc.host
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := browserProvenanceRefusal(r, tc.hostCheck); got != tc.want {
				t.Errorf("refusal = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestProxyRefusesBrowserProvenanceOnGatewayRoute is the SR27-B1 regression
// (security review 2026-09-27). In AI-Gateway mode the proxy attaches the org
// virtual key to every gateway-bound request, so before the fix any website
// could POST text/plain to 127.0.0.1:8820 (no preflight) and spend the org's
// provider credential, and a DNS-rebound page could read the answer. Both
// browser shapes must now be refused before the gateway is dialed, while a
// plain CLI request still reaches the gateway carrying the virtual key.
func TestProxyRefusesBrowserProvenanceOnGatewayRoute(t *testing.T) {
	gateway := newRecordingUpstream(t, http.StatusOK)
	p := mustGatewayProxy(t, Options{
		Sink:             &fakeSink{},
		VirtualKeySource: &fakeVirtualKeySource{key: "sbo-vk-org", gen: 1},
	}, gateway.srv.URL, nil, terminalHold, false)
	// What ListenAndServe records for the default 127.0.0.1 bind.
	p.requireLoopbackHost.Store(true)
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	const body = `{"model":"claude-sonnet-4-5","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`

	// (a) A cross-site page's no-cors text/plain POST.
	resp := doPost(t, ts.URL+"/v1/messages", body, func(r *http.Request) {
		r.Header.Set("Content-Type", "text/plain;charset=UTF-8")
		r.Header.Set("Origin", "https://evil.example")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	})
	_ = readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin POST status = %d, want 403", resp.StatusCode)
	}
	if n := gateway.count(); n != 0 {
		t.Fatalf("gateway dialed %d times for a cross-origin page, want 0", n)
	}

	// (b) A DNS-rebound page: no Origin (same-origin from the page's view), but
	// its own name in Host.
	resp = doPost(t, ts.URL+"/v1/messages", body, func(r *http.Request) {
		r.Host = "rebind.evil.example:8820"
	})
	_ = readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("rebound-host POST status = %d, want 403", resp.StatusCode)
	}
	if n := gateway.count(); n != 0 {
		t.Fatalf("gateway dialed %d times for a rebound host, want 0", n)
	}

	// (c) Control: a CLI client on loopback still gets the gateway + virtual key.
	resp = doPost(t, ts.URL+"/v1/messages", body, nil)
	_ = readBody(t, resp)
	if gateway.count() != 1 {
		t.Fatalf("gateway hits = %d after a CLI request, want 1", gateway.count())
	}
	if got := gateway.header("X-Api-Key"); got != "sbo-vk-org" {
		t.Errorf("gateway X-Api-Key = %q, want the virtual key", got)
	}
}
