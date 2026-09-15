package nodegov_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// This file is an EXTERNAL test package (nodegov_test) so it may import
// internal/config, which the package itself must never import
// (imports_test.go pins that). The dependency is one-way and test-only.

// resolveDotted walks a dotted TOML path against a reflect-walked struct,
// mirroring internal/config's own applyEnvToStruct traversal (toml tag,
// first comma-separated segment, "-" skipped).
func resolveDotted(v reflect.Value, dotted string) (reflect.Value, bool) {
	cur := v
	for _, seg := range strings.Split(dotted, ".") {
		if cur.Kind() != reflect.Struct {
			return reflect.Value{}, false
		}
		t := cur.Type()
		found := false
		for i := 0; i < cur.NumField(); i++ {
			tag := t.Field(i).Tag.Get("toml")
			if tag == "" {
				tag = t.Field(i).Name
			}
			tag = strings.SplitN(tag, ",", 2)[0]
			if tag == "-" {
				continue
			}
			if tag == seg {
				cur = cur.Field(i)
				found = true
				break
			}
		}
		if !found {
			return reflect.Value{}, false
		}
	}
	return cur, true
}

func kindFor(k reflect.Kind, typ reflect.Type) string {
	switch k {
	case reflect.Bool:
		return "bool"
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int32, reflect.Int64:
		return "int"
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.String {
			return "string_list"
		}
	}
	return ""
}

// TestEveryPinnableKeyResolvesInConfig is the anti-recurrence gate the
// 2026-08-15 adversarial review's finding B1 demands: four of the spec
// draft's thirteen pinnable rows named config paths that did not exist,
// inside a table whose own prose claimed every path had been checked.
//
// After this test, that finding class is impossible: every dotted key in
// PinnableKeys must resolve against a reflect-walked config.Default(), and
// its Go kind must agree with the row's declared Kind.
func TestEveryPinnableKeyResolvesInConfig(t *testing.T) {
	def := config.Default()
	root := reflect.ValueOf(&def).Elem()
	for _, row := range nodegov.PinnableKeys {
		fv, ok := resolveDotted(root, row.Key)
		if !ok {
			t.Errorf("PinnableKeys names %q, which does NOT resolve in config.Default() — an org could pin a key no process reads", row.Key)
			continue
		}
		if got := kindFor(fv.Kind(), fv.Type()); got != row.Kind {
			t.Errorf("PinnableKeys row %q declares Kind %q but the config field is %q", row.Key, row.Kind, got)
		}
	}
}

// TestEveryShareKeyResolvesInConfig is the same gate for the share block:
// every share key must resolve under [org_client.share].
func TestEveryShareKeyResolvesInConfig(t *testing.T) {
	def := config.Default()
	root := reflect.ValueOf(&def).Elem()
	for _, row := range nodegov.ShareKeys {
		path := nodegov.ShareKeyConfigPath(row.Key)
		fv, ok := resolveDotted(root, path)
		if !ok {
			t.Errorf("ShareKeys names %q, which does NOT resolve in config.Default()", path)
			continue
		}
		if got := kindFor(fv.Kind(), fv.Type()); got != row.Kind {
			t.Errorf("ShareKeys row %q declares Kind %q but the config field is %q", path, row.Kind, got)
		}
	}
}

// TestEveryFeatureExpandsToAPinnableKey: features are a compile-time alias
// over pinned keys, so there is no second list to keep in sync.
func TestEveryFeatureExpandsToAPinnableKey(t *testing.T) {
	for _, f := range nodegov.Features {
		if !nodegov.IsPinnableKey(f.Key) {
			t.Errorf("feature %q expands to %q, which is not a pinnable key", f.ID, f.Key)
		}
	}
}

// TestShareKeysNotPinnable is §1.9's one-owner rule: the share block is the
// ONLY way to express a share directive, because it carries its own
// direction algebra (§2). A share key in PinnableKeys would be two owners of
// one piece of state.
func TestShareKeysNotPinnable(t *testing.T) {
	for _, row := range nodegov.PinnableKeys {
		if strings.HasPrefix(row.Key, "org_client.share.") {
			t.Errorf("PinnableKeys names the share key %q — share directives have exactly one owner (the `share` block)", row.Key)
		}
	}
	for _, row := range nodegov.ShareKeys {
		if nodegov.IsPinnableKey(nodegov.ShareKeyConfigPath(row.Key)) {
			t.Errorf("share key %q is also pinnable", row.Key)
		}
	}
}

// TestBootstrapEnvelopeKeysNotPinnable walks §1.9's structural exclusion
// list, one row per key.
func TestBootstrapEnvelopeKeysNotPinnable(t *testing.T) {
	for _, key := range nodegov.BootstrapEnvelopeKeys {
		if nodegov.IsPinnableKey(key) {
			t.Errorf("bootstrap-envelope key %q is pinnable — a remotely-set value could sever or brick the node", key)
		}
	}
}

// TestAdminManagedNotRemotelySettable: admin_managed flips content-sharing
// defaults raw. It is excluded from EVERY remote vocabulary, and a body
// naming it fails Compile on both the publish and the accept path.
//
// This is a TEAMS-posture-and-common statement about the nodegov governance
// vocabulary (the same signed-directive compiler both postures share): under
// EITHER posture, admin_managed itself is never a governance-body key,
// because it is not how enterprise posture authorizes raw content either.
// The Plane B dual-mode gateway / RBAC-IA design's enterprise posture
// (2026-08-29 §5.3 item 2) makes admin_managed IRRELEVANT rather than
// remotely-settable — a managed node's own enrolment grant satisfying
// govern.Effective.GrantsEnterpriseContent() sets store.ShareOptions
// .EnterpriseGranted through a structurally distinct, non-governance-body
// channel (see TestOrgPushUnchangedByGovernance in
// tests/invariant/governance_phase1b_test.go and the "enterprise_granted"
// subtest of TestPushPayloadCarriesContentWhenOptedIn in
// tests/invariant/privacy_test.go). So this test's assertions hold
// byte-identically under both postures for the reason stated here, not
// because enterprise posture was overlooked.
func TestAdminManagedNotRemotelySettable(t *testing.T) {
	if nodegov.IsPinnableKey("org_client.share.admin_managed") {
		t.Fatal("admin_managed is pinnable")
	}
	if nodegov.IsShareKey("admin_managed") {
		t.Fatal("admin_managed is an org-directable share key")
	}
	for _, body := range []string{
		`{"schema":2,"pinned":{"org_client.share.admin_managed":true}}`,
		`{"schema":2,"share":{"admin_managed":true}}`,
	} {
		if _, _, err := nodegov.CompileBody([]byte(body), 1<<20); err == nil {
			t.Fatalf("the compiler accepted %s — the org could command raw content sharing", body)
		}
	}
}
