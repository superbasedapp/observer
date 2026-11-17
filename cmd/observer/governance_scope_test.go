package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// TestGovernedScopeOptions pins CG-13's push-side composition: an individual
// node pushes under its own lists; a managed node's guard verdicts ignore
// them; and only a managed node holding extract.scope applies the org's
// scope raise (govern.RaiseScope*), never an individual node handed the same
// directive.
func TestGovernedScopeOptions(t *testing.T) {
	local := config.OrgClientScopeConfig{
		ProjectRootAllowlist: []string{"/w/a", "/w/b"},
		ProjectRootDenylist:  []string{"/w/secret", "/w/vendor"},
	}
	directives := map[string]any{
		govern.ScopeUnrestrictedShareKey:   true,
		govern.ScopeDenylistRemoveShareKey: []string{"/w/vendor"},
	}
	cases := []struct {
		name         string
		eff          govern.Effective
		wantAllow    []string
		wantDeny     []string
		wantUnscoped bool
	}{
		{"individual node", govern.Effective{}, local.ProjectRootAllowlist, local.ProjectRootDenylist, false},
		{"individual node handed the directives", govern.Effective{Share: directives, Authority: []string{govern.AuthorityExtractScope}}, local.ProjectRootAllowlist, local.ProjectRootDenylist, false},
		{"managed node, no extract.scope", govern.Effective{Managed: true, Share: directives}, local.ProjectRootAllowlist, local.ProjectRootDenylist, true},
		{"managed node with extract.scope, no directive", govern.Effective{Managed: true, Authority: []string{govern.AuthorityExtractScope}}, local.ProjectRootAllowlist, local.ProjectRootDenylist, true},
		{"managed node with extract.scope and directives", govern.Effective{Managed: true, Share: directives, Authority: []string{govern.AuthorityExtractScope}}, nil, []string{"/w/secret"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := governedScopeOptions(local, tc.eff)
			if !reflect.DeepEqual(got.ProjectRootAllowlist, tc.wantAllow) {
				t.Errorf("allowlist = %v, want %v", got.ProjectRootAllowlist, tc.wantAllow)
			}
			if !reflect.DeepEqual(got.ProjectRootDenylist, tc.wantDeny) {
				t.Errorf("denylist = %v, want %v", got.ProjectRootDenylist, tc.wantDeny)
			}
			if got.GuardEventsUnscoped != tc.wantUnscoped {
				t.Errorf("GuardEventsUnscoped = %v, want %v", got.GuardEventsUnscoped, tc.wantUnscoped)
			}
		})
	}
	if p := governanceScopeProvider(config.OrgClientConfig{Scope: local}, nil); p().GuardEventsUnscoped {
		t.Error("no governance handle: guard events must stay scoped")
	}
}

// TestGovernedScopeRaiseFromAPublishedBody is R3-85's end-to-end proof: a real
// node.governance body publishing the two scope raise directives, run through
// the daemon chain (nodegov.CompileBody, govern.Resolve, governedScopeOptions),
// lifts the allowlist and takes the named entry off the denylist on a managed
// node holding extract.scope, and changes nothing without that authority or
// on an individually enrolled node handed the same body.
func TestGovernedScopeRaiseFromAPublishedBody(t *testing.T) {
	const body = `{"schema":2,"share":{"scope.unrestricted":true,"scope.denylist_remove":["/w/vendor"]}}`
	local := config.OrgClientScopeConfig{
		ProjectRootAllowlist: []string{"/w/a", "/w/b"},
		ProjectRootDenylist:  []string{"/w/secret", "/w/vendor"},
	}
	spec, _, err := nodegov.CompileBody([]byte(body), 1<<20)
	if err != nil {
		t.Fatalf("CompileBody: %v", err)
	}
	now := time.Now().UTC()
	grant := func(tenancy string, authority ...string) *govern.Grant {
		return &govern.Grant{
			OrgKey: "ok", Generation: 2, OrgName: "Acme", KeyPinSHA256: "pin",
			ConsentMode: tenancy,
			Authority:   append([]string{govern.AuthorityCapturePin}, authority...),
			GrantedAt:   now.Add(-time.Hour), ExpiresAt: now.Add(30 * 24 * time.Hour),
		}
	}
	cases := []struct {
		name      string
		grant     *govern.Grant
		wantAllow []string
		wantDeny  []string
	}{
		{"managed with extract.scope", grant(govern.ConsentManaged, govern.AuthorityExtractScope), nil, []string{"/w/secret"}},
		{"managed without extract.scope", grant(govern.ConsentManaged), local.ProjectRootAllowlist, local.ProjectRootDenylist},
		{"managed with only the umbrella", grant(govern.ConsentManaged, govern.AuthorityExtractManaged), local.ProjectRootAllowlist, local.ProjectRootDenylist},
		{"individual with extract.scope", grant(govern.ConsentInteractive, govern.AuthorityExtractScope), local.ProjectRootAllowlist, local.ProjectRootDenylist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eff := govern.Resolve(
				govern.Delivered{Present: true, Version: 3, BodyHash: "bh", Spec: spec},
				tc.grant,
				govern.LiveIdentity{Enrolled: true, OrgKey: "ok", Generation: 2, KeyPinSHA256: "pin"},
				now,
			)
			if _, ok := eff.Share[govern.ScopeUnrestrictedShareKey]; !ok {
				t.Fatalf("the resolved posture lost the scope directive: share=%v dropped=%v", eff.Share, eff.Dropped)
			}
			got := governedScopeOptions(local, eff)
			if !reflect.DeepEqual(got.ProjectRootAllowlist, tc.wantAllow) {
				t.Errorf("allowlist = %v, want %v", got.ProjectRootAllowlist, tc.wantAllow)
			}
			if !reflect.DeepEqual(got.ProjectRootDenylist, tc.wantDeny) {
				t.Errorf("denylist = %v, want %v", got.ProjectRootDenylist, tc.wantDeny)
			}
		})
	}
}
