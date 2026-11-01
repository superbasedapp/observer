package sandbox

import (
	"strings"
	"testing"
)

// TestModelRouteNoticeFromTheTierTable (live run 2, finding N2: on the none
// tier the in-box launcher said traffic goes straight to Anthropic, though
// the box has no network): the notice is read from the tier's columns; a
// tier with a direct route leaves the caller's notice, the proxy-only tier
// says the proxy is its only route, the none tier says there is no route.
func TestModelRouteNoticeFromTheTierTable(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode    Egress
		want    []string
		wantNot []string
	}{
		{EgressHost, nil, nil},
		{EgressInternet, nil, nil},
		{EgressProxyOnly, []string{"tier is proxy_only", "only route to the model API", "http://127.0.0.1:8820"}, []string{"straight to Anthropic"}},
		{EgressNone, []string{"tier is none", "no route to the model API", "not even the model proxy"}, []string{"straight to Anthropic"}},
	} {
		p, err := ResolveEgress(string(tc.mode))
		if err != nil {
			t.Fatal(err)
		}
		got := ModelRouteNotice(p, "claude", "http://127.0.0.1:8820")
		if tc.want == nil {
			if got != "" {
				t.Errorf("%s: a direct-route tier said %q", tc.mode, got)
			}
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q lacks %q", tc.mode, got, w)
			}
		}
		for _, w := range tc.wantNot {
			if strings.Contains(got, w) {
				t.Errorf("%s: %q says %q", tc.mode, got, w)
			}
		}
		if strings.ContainsAny(got, "–—") {
			t.Errorf("%s: a dash in %q", tc.mode, got)
		}
	}
}
