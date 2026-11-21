//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// init stubs the route-lane read for every test in the package (fix round
// 1, FU8-A11): a test that reaches providerHostList never reads the real
// home's route-provenance file.
func init() { sandboxRouteLaneRoots = func(int) []string { return nil } }

// fu8LaneTable is a live lane table with an org route.
type fu8LaneTable struct {
	lanes   map[string]string
	primary string
	fall    []string
}

func (f fu8LaneTable) LaneTable() (map[string]string, string) { return f.lanes, "" }
func (f fu8LaneTable) OrgRoute() (string, string, []string, uint64) {
	return "gateway", f.primary, f.fall, 1
}

// TestSandboxProviderHostSources pins lane FU8 (ledger OSH-43, sweep E4):
// the extra provider hosts come from every source, one case per source.
func TestSandboxProviderHostSources(t *testing.T) {
	oldRoots := sandboxRouteLaneRoots
	t.Cleanup(func() {
		sandboxRouteLaneRoots = oldRoots
		sandboxLiveProviderHosts.Store(nil)
	})
	cases := []struct {
		name  string
		cfg   config.ProxyConfig
		roots []string
		live  *fu8LaneTable
		want  string
	}{
		{name: "static upstreams", cfg: config.ProxyConfig{Upstreams: map[string]string{"or": "https://openrouter.ai/api"}}, want: "openrouter.ai"},
		{name: "static org route", cfg: config.ProxyConfig{OrgRoute: config.ProxyOrgRouteConfig{Mode: "gateway", Primary: "https://gw.corp.example/v1", Fallbacks: []string{"https://gw2.corp.example"}}}, want: "gw.corp.example,gw2.corp.example"},
		{name: "recorded route lane", roots: []string{"https://api.siliconflow.cn", "http://127.0.0.1:9"}, want: "api.siliconflow.cn"},
		{name: "live gateway.providers lane", live: &fu8LaneTable{lanes: map[string]string{"corp": "https://llm.corp.example/api"}}, want: "llm.corp.example"},
		{name: "live org route", live: &fu8LaneTable{primary: "https://aigw.corp.example", fall: []string{"https://aigw-b.corp.example"}}, want: "aigw-b.corp.example,aigw.corp.example"},
		{name: "union deduplicated", cfg: config.ProxyConfig{Upstreams: map[string]string{"or": "https://openrouter.ai/api"}}, roots: []string{"https://OpenRouter.ai"}, live: &fu8LaneTable{lanes: map[string]string{"x": "https://openrouter.ai/v1"}}, want: "openrouter.ai"},
		{name: "none", want: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			roots := c.roots
			sandboxRouteLaneRoots = func(int) []string { return roots }
			if c.live != nil {
				bindSandboxLiveProviderHosts(*c.live)
			} else {
				bindSandboxLiveProviderHosts(nil)
			}
			if got := strings.Join(sandboxProviderHosts(c.cfg), ","); got != c.want {
				t.Fatalf("sandboxProviderHosts = %q, want %q", got, c.want)
			}
		})
	}
}

// TestProviderHostListReadsAtLaunch pins that a lane installed after the
// runtime was built is in the next launch's list.
func TestProviderHostListReadsAtLaunch(t *testing.T) {
	oldRoots := sandboxRouteLaneRoots
	t.Cleanup(func() {
		sandboxRouteLaneRoots = oldRoots
		sandboxLiveProviderHosts.Store(nil)
	})
	sandboxRouteLaneRoots = func(int) []string { return nil }
	bindSandboxLiveProviderHosts(nil)
	r := &sandboxRuntime{providerHosts: []string{"openrouter.ai"}, proxyPort: 8820}
	if got := strings.Join(r.providerHostList(), ","); got != "openrouter.ai" {
		t.Fatalf("before = %q", got)
	}
	bindSandboxLiveProviderHosts(fu8LaneTable{lanes: map[string]string{"corp": "https://llm.corp.example"}})
	if got := strings.Join(r.providerHostList(), ","); got != "llm.corp.example,openrouter.ai" {
		t.Fatalf("after = %q", got)
	}
}

// TestSandboxProviderHostSeamFamilies pins that the refusal advisor reads the
// family rows too (one matcher with the gateway).
func TestSandboxProviderHostSeamFamilies(t *testing.T) {
	oldRoots := sandboxRouteLaneRoots
	t.Cleanup(func() { sandboxRouteLaneRoots = oldRoots })
	sandboxRouteLaneRoots = func(int) []string { return nil }
	seam := sandboxProviderHostSeam()
	for host, want := range map[string]bool{
		"bedrock-runtime.us-east-1.amazonaws.com": true,
		"us-central1-aiplatform.googleapis.com":   true,
		"s3.us-east-1.amazonaws.com":              false,
	} {
		if got := seam(config.Config{}, host); got != want {
			t.Errorf("seam(%q) = %v, want %v", host, got, want)
		}
	}
}
