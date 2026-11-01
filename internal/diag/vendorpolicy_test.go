package diag

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestVendorPolicyRules: one case per row of the two rule tables (S-15,
// D17), each proving the row fires on its member and stays quiet on the
// neighbouring reading.
func TestVendorPolicyRules(t *testing.T) {
	rule := func(rules []vendorPolicyRule, id string) vendorPolicyRule {
		for _, r := range rules {
			if r.id == id {
				return r
			}
		}
		t.Fatalf("no rule %s", id)
		return vendorPolicyRule{}
	}
	for _, tc := range []struct {
		rules []vendorPolicyRule
		id    string
		doc   string
		holds bool
	}{
		{clineRemoteConfigRules, "cline.remote.mcp_marketplace_off", `{"mcpMarketplaceEnabled":false}`, true},
		{clineRemoteConfigRules, "cline.remote.mcp_marketplace_off", `{"mcpMarketplaceEnabled":true}`, false},
		{clineRemoteConfigRules, "cline.remote.mcp_marketplace_off", `{}`, false},
		{clineRemoteConfigRules, "cline.remote.mcp_not_allowlisted", `{"allowedMCPServers":[{"id":"github"}]}`, true},
		{clineRemoteConfigRules, "cline.remote.mcp_not_allowlisted", `{"allowedMCPServers":[{"id":"github"},{"id":"observer"}]}`, false},
		{clineRemoteConfigRules, "cline.remote.mcp_not_allowlisted", `{"allowedMCPServers":[]}`, false},
		{clineRemoteConfigRules, "cline.remote.route_pinned", `{"providerSettings":{"OpenAiCompatible":{"openAiBaseUrl":"https://llm.corp.example/v1"}}}`, true},
		{clineRemoteConfigRules, "cline.remote.route_pinned", `{"providerSettings":{"Anthropic":{"baseUrl":"https://gw.example"}}}`, true},
		{clineRemoteConfigRules, "cline.remote.route_pinned", `{"providerSettings":{"LiteLLM":{"baseUrl":"http://127.0.0.1:8820"}}}`, false},
		{clineRemoteConfigRules, "cline.remote.route_pinned", `{"providerSettings":{"OpenAiCompatible":{"openAiBaseUrl":""}}}`, false},
		{factoryOrgCacheRules, "factory.orgcache.mcp_policy_blocks_all", `{"managedSettings":{"mcpPolicy":{"enabled":true,"allowlist":[]}}}`, true},
		{factoryOrgCacheRules, "factory.orgcache.mcp_policy_blocks_all", `{"managedSettings":{"mcpPolicy":{"enabled":true}}}`, true},
		{factoryOrgCacheRules, "factory.orgcache.mcp_policy_blocks_all", `{"managedSettings":{"mcpPolicy":{"enabled":false,"allowlist":[]}}}`, false},
		{factoryOrgCacheRules, "factory.orgcache.mcp_not_allowlisted", `{"managedSettings":{"mcpPolicy":{"enabled":true,"allowlist":["github.com"]}}}`, true},
		{factoryOrgCacheRules, "factory.orgcache.mcp_not_allowlisted", `{"managedSettings":{"mcpPolicy":{"enabled":true,"allowlist":["observer"]}}}`, false},
		{factoryOrgCacheRules, "factory.orgcache.mcp_not_allowlisted", `{"managedSettings":{"mcpPolicy":{"enabled":true,"allowlist":["observer-helper","not-observer"]}}}`, true},
		{factoryOrgCacheRules, "factory.orgcache.mcp_not_allowlisted", `{"managedSettings":{"mcpPolicy":{"enabled":true,"allowlist":[{"name":"Observer"}]}}}`, false},
		{factoryOrgCacheRules, "factory.orgcache.mcp_not_allowlisted", `{"managedSettings":{"mcpPolicy":{"enabled":true,"allowlist":[{"command":"observer mcp"}]}}}`, true},
		{factoryOrgCacheRules, "factory.orgcache.custom_models_off", `{"managedSettings":{"modelPolicy":{"allowCustomModels":false}}}`, true},
		{factoryOrgCacheRules, "factory.orgcache.custom_models_off", `{"managedSettings":{"modelPolicy":{"allowCustomModels":true}}}`, false},
		{factoryOrgCacheRules, "factory.orgcache.base_urls_exclude_loopback", `{"managedSettings":{"modelPolicy":{"allowedBaseUrls":["https://api.example"]}}}`, true},
		{factoryOrgCacheRules, "factory.orgcache.base_urls_exclude_loopback", `{"managedSettings":{"modelPolicy":{"allowedBaseUrls":["https://api.example","http://localhost:8820"]}}}`, false},
	} {
		r := rule(tc.rules, tc.id)
		if got := r.holds(vendorPolicyDoc{raw: []byte(tc.doc)}); got != tc.holds {
			t.Errorf("%s over %s = %v, want %v", tc.id, tc.doc, got, tc.holds)
		}
	}
}

// TestVendorPolicyFindingsReadsOnlyNamedMembers: the caches are found under
// a throwaway home, a finding never carries a value read from the file (a
// header secret or the pinned URL), and the doctor row warns.
func TestVendorPolicyFindingsReadsOnlyNamedMembers(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exercises the Linux VS Code layout")
	}
	home := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const secret = "sk-SECRET-VALUE-NEVER-SURFACED"
	write(".config/Code/User/globalStorage/saoudrizwan.claude-dev/cache/remote_config_org123.json",
		`{"mcpMarketplaceEnabled":false,"providerSettings":{"OpenAiCompatible":{"openAiBaseUrl":"https://llm.corp.example/v1","openAiHeaders":{"Authorization":"Bearer `+secret+`"}}},"remoteMCPServers":[{"name":"x","url":"https://x","headers":{"k":"`+secret+`"}}]}`)
	write(".factory/org-managed-settings.cache.json", `{"managedSettings":{"modelPolicy":{"allowCustomModels":false}},"orgId":"o","revision":3}`)

	findings := VendorPolicyFindings(home, func(string) string { return "" })
	got := map[string]VendorPolicyFinding{}
	for _, f := range findings {
		got[f.Rule] = f
		for _, s := range []string{f.Message, f.Grounding, f.Tool, f.Rule} {
			if strings.Contains(s, secret) || strings.Contains(s, "llm.corp.example") {
				t.Fatalf("a finding surfaced a value read from the cache: %+v", f)
			}
		}
	}
	for _, want := range []string{"cline.remote.mcp_marketplace_off", "cline.remote.route_pinned", "factory.orgcache.custom_models_off"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing finding %s (got %v)", want, findings)
		}
	}
	if f := got["cline.remote.route_pinned"]; f.Kind != VendorPolicyPinsRoute || !f.Warn || !strings.HasSuffix(f.Dir, filepath.Join("saoudrizwan.claude-dev", "cache")) {
		t.Errorf("cline route finding = %+v", f)
	}
	if f := got["factory.orgcache.custom_models_off"]; f.Warn || f.Grounding != VendorPolicyLiveGrounded {
		t.Errorf("a route veto where Observer writes no route must be informational: %+v", f)
	}
	c := checkVendorPolicyCaches(home, nil)
	if c.Status != StatusWarn || len(c.Details) != len(findings) {
		t.Fatalf("doctor row = %+v", c)
	}
	for _, d := range c.Details {
		if strings.Contains(d, secret) {
			t.Fatalf("the doctor row surfaced a value read from the cache: %q", d)
		}
	}
	if c := checkVendorPolicyCaches(t.TempDir(), nil); c.Status != StatusOK {
		t.Fatalf("an empty home reads %+v", c)
	}
}

// TestVendorPolicyCacheTooLargeIsSkipped: a cache over the read bound is not
// judged.
func TestVendorPolicyCacheTooLargeIsSkipped(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".factory", "org-managed-settings.cache.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	big := `{"managedSettings":{"modelPolicy":{"allowCustomModels":false}},"pad":"` + strings.Repeat("x", vendorPolicyMaxBytes) + `"}`
	if err := os.WriteFile(p, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := VendorPolicyFindings(home, nil); len(got) != 0 {
		t.Fatalf("an oversized cache was judged: %+v", got)
	}
}

// writeCache writes body at rel under home, creating directories.
func writeCache(t *testing.T, home, rel, body string) string {
	t.Helper()
	p := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestVendorPolicySymlinks: a cache symlink is followed only inside the
// cache's own directory; a link that leaves it is refused.
func TestVendorPolicySymlinks(t *testing.T) {
	home := t.TempDir()
	const body = `{"managedSettings":{"modelPolicy":{"allowCustomModels":false}}}`
	cache := filepath.Join(home, ".factory", "org-managed-settings.cache.json")
	outside := writeCache(t, t.TempDir(), "elsewhere.json", body)
	if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, cache); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if got := VendorPolicyFindings(home, nil); len(got) != 0 {
		t.Fatalf("a symlink leaving the cache dir was followed: %+v", got)
	}
	if err := os.Remove(cache); err != nil {
		t.Fatal(err)
	}
	inside := writeCache(t, home, ".factory/real-cache.json", body)
	if err := os.Symlink(inside, cache); err != nil {
		t.Fatal(err)
	}
	if got := VendorPolicyFindings(home, nil); len(got) != 1 {
		t.Fatalf("a symlink inside the cache dir was not followed: %+v", got)
	}
}

// TestClineCacheListingIgnoresGlobMetacharacters: a home path holding "["
// (a legal Windows user folder character) still finds the cache, which a
// filepath.Glob over the joined path would miss.
func TestClineCacheListingIgnoresGlobMetacharacters(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exercises the Linux VS Code layout")
	}
	home := filepath.Join(t.TempDir(), "user[1]")
	want := writeCache(t, home, ".config/Code/User/globalStorage/saoudrizwan.claude-dev/cache/remote_config_o.json", `{"mcpMarketplaceEnabled":false}`)
	writeCache(t, home, ".config/Code/User/globalStorage/saoudrizwan.claude-dev/cache/other.json", `{}`)
	got := clineRemoteConfigFiles(home, nil)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("files = %v, want [%s]", got, want)
	}
}
