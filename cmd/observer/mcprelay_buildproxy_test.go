package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// writeMCPRelayProxyConfig writes a daemon config.toml under a temp dir with
// [mcp_relay].enabled set as asked, the org-bundle cache (and so the relay's
// sibling node-table cache) pinned inside the temp dir, and the Anthropic
// upstream pointed at anthURL. HOME is redirected so nothing in the build
// touches the operator's real ~/.observer.
func writeMCPRelayProxyConfig(t *testing.T, enabled bool, anthURL string) (configPath, dbPath, bundlePath string) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	dbPath = filepath.Join(tmp, "observer.db")
	bundlePath = filepath.Join(tmp, "org-policy-bundle.json")
	configPath = filepath.Join(tmp, "config.toml")
	body := fmt.Sprintf(`
[observer]
db_path = %q
log_level = "error"

[proxy]
enabled = true
port = 8820
anthropic_upstream = %q
openai_upstream = "http://127.0.0.1:1"
chatgpt_upstream = "http://127.0.0.1:2"
prewarm_targets = []

[guard.rules]
org_bundle = %q

[mcp_relay]
enabled = %t
mode = "stdio_wrapper"
audit_mode = "async"
`, dbPath, anthURL, bundlePath, enabled)
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath, dbPath, bundlePath
}

// isolateProcessMCPRelay snapshots the process-wide relay handle, clears it
// for the test and restores it afterwards (buildProxy mutates a global).
func isolateProcessMCPRelay(t *testing.T) {
	t.Helper()
	prev := processMCPRelay.Load()
	t.Cleanup(func() { processMCPRelay.Store(prev) })
	processMCPRelay.Store(nil)
}

// TestBuildProxy_BindsProcessMCPRelay pins the production wiring defect
// closed: buildProxy (the `observer start` / `observer proxy start`
// assembly) is the ONE binder of processMCPRelay. With [mcp_relay].enabled
// the handle must be bound (so the tools.mcp_access publisher, the relay
// runtime goroutine and the policy-state point reader see it); with it off
// nothing is bound.
func TestBuildProxy_BindsProcessMCPRelay(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			isolateProcessMCPRelay(t)
			configPath, dbPath, bundlePath := writeMCPRelayProxyConfig(t, enabled, "http://127.0.0.1:3")
			_, cleanup, _, _, _, _, _, err := buildProxy(context.Background(), configPath, "", 0, "127.0.0.1", nil)
			if err != nil {
				t.Fatalf("buildProxy: %v", err)
			}
			t.Cleanup(cleanup)
			h := processMCPRelay.Load()
			if !enabled {
				if h != nil {
					t.Fatal("[mcp_relay].enabled=false bound a process relay handle")
				}
				return
			}
			if h == nil {
				t.Fatal("[mcp_relay].enabled=true: buildProxy never bound processMCPRelay (relay runtime, publisher and point reader all see nil)")
			}
			want := localpdp.SiblingPath(bundlePath, dbPath)
			if h.cache.Path != want {
				t.Errorf("relay cache path = %s, want %s (beside the org-bundle cache)", h.cache.Path, want)
			}
			// The governance attach start.go performs after buildProxy must
			// land on THIS handle.
			ngov := newNodeGovernanceHandle(nil, nil)
			processMCPRelay.Load().SetGovernance(ngov)
			h.mu.Lock()
			bound := h.orgAuthoritative != nil
			h.mu.Unlock()
			if !bound {
				t.Error("SetGovernance on the bound handle did not attach the governance rule")
			}
		})
	}
}

// TestBuildProxy_MCPAccessPublishReachesRelay drives a verified
// tools.mcp_access result through the SAME dispatch the policy-resource
// publisher uses (mcpRelayPublish, called from publishPolicyResourceResult
// for policyfam.FamilyMCPAccess) against a daemon-assembled proxy, and
// proves the three effects: the compiled table is applied and cached to disk
// (what a hook process and `observer mcp doctor` read), and the proxy's
// tools[] seam strips the org-denied declaration on the wire.
func TestBuildProxy_MCPAccessPublishReachesRelay(t *testing.T) {
	isolateProcessMCPRelay(t)

	var (
		mu   sync.Mutex
		seen [][]string
	)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		}
		_ = json.Unmarshal(raw, &req)
		names := make([]string, 0, len(req.Tools))
		for _, tl := range req.Tools {
			names = append(names, tl.Name)
		}
		sort.Strings(names)
		mu.Lock()
		seen = append(seen, names)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_relay","type":"message","role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	t.Cleanup(up.Close)

	configPath, dbPath, bundlePath := writeMCPRelayProxyConfig(t, true, up.URL)
	p, cleanup, _, _, _, _, _, err := buildProxy(context.Background(), configPath, "", 0, "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("buildProxy: %v", err)
	}
	t.Cleanup(cleanup)
	if processMCPRelay.Load() == nil {
		t.Fatal("buildProxy did not bind processMCPRelay")
	}
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)

	send := func() []string {
		t.Helper()
		body := `{"model":"claude-opus-4-8","max_tokens":8,
			"tools":[
				{"name":"Read","input_schema":{"type":"object"}},
				{"name":"mcp__github__create_issue","input_schema":{"type":"object"}},
				{"name":"mcp__github__delete_repo","input_schema":{"type":"object"}}
			],
			"messages":[{"role":"user","content":"hi"}]}`
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/messages", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Session-Id", "sRelayWire")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("proxy request: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("proxy status = %d", resp.StatusCode)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(seen) == 0 {
			t.Fatal("upstream never saw the request")
		}
		return seen[len(seen)-1]
	}

	// No table yet: the seam keeps everything.
	if got := strings.Join(send(), ","); got != "Read,mcp__github__create_issue,mcp__github__delete_repo" {
		t.Fatalf("pre-publish forwarded tools = %s", got)
	}

	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cachePath := localpdp.SiblingPath(bundlePath, dbPath)
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatalf("node table cache present before publish: %v", err)
	}

	// The exact dispatch publishPolicyResourceResult performs for
	// policyfam.FamilyMCPAccess once its identity gate passes.
	mcpRelayPublish(orgclient.PolicyResourceResult{
		Status: orgclient.PRApplied, Version: 7, BodyHash: strings.Repeat("c", 64),
		OrgKey: "org", Generation: 1, EnforceAllowed: true, Spec: mcpRelayTestSpec(t, "enforce"),
	})

	h := processMCPRelay.Load()
	if tbl := h.Table(); tbl == nil || tbl.Meta.Version != 7 {
		t.Fatalf("published table not applied: state=%+v", h.State())
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("node table cache not written at %s: %v", cachePath, err)
	}
	lookup := hookMCPAccessLookup(cfg)
	if lookup == nil {
		t.Fatal("hook-process lookup found no cached table after the daemon publish")
	}
	if v := lookup("github", "delete_repo"); !v.Known || !v.OrgDenied {
		t.Errorf("hook lookup delete_repo = %+v, want org-denied", v)
	}

	// The proxy tools[] seam now strips the org-denied declaration.
	if got := strings.Join(send(), ","); got != "Read,mcp__github__create_issue" {
		t.Errorf("post-publish forwarded tools = %s, want Read,mcp__github__create_issue", got)
	}
}
