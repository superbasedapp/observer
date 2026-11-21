package orgcontract

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// TestSecurityPackageLookupFields pins the package lookup vocabulary of the
// security managed pull (lane RM-3): the closed enums decode, anything else
// is refused, absent reads off.
func TestSecurityPackageLookupFields(t *testing.T) {
	cases := []struct {
		name, body string
		on         bool
		err        bool
	}{
		{"absent is off", `{"version":1}`, false, false},
		{"off", `{"version":1,"package_lookup":"off"}`, false, false},
		{"org mirror", `{"version":1,"package_lookup":"org_mirror","package_lookup_private":"withhold","package_lookup_kinds":["language","actions"]}`, true, false},
		{"send private", `{"version":1,"package_lookup":"org_mirror","package_lookup_private":"send"}`, true, false},
		{"public host refused", `{"version":1,"package_lookup":"shards"}`, false, true},
		{"unknown private", `{"version":1,"package_lookup":"org_mirror","package_lookup_private":"maybe"}`, false, true},
		{"os kind not in this build", `{"version":1,"package_lookup":"org_mirror","package_lookup_kinds":["os"]}`, false, true},
		{"empty kinds", `{"version":1,"package_lookup":"org_mirror","package_lookup_kinds":[]}`, false, true},
	}
	for _, c := range cases {
		p, ok, err := DecodeSecurityManagedPolicy([]byte(c.body))
		if (err != nil) != c.err {
			t.Errorf("%s: err %v", c.name, err)
			continue
		}
		if err != nil {
			if !errors.Is(err, ErrSecurityManagedPolicy) {
				t.Errorf("%s: %v is not a policy refusal", c.name, err)
			}
			continue
		}
		if !ok || SecurityPackageLookupOn(&p) != c.on {
			t.Errorf("%s: on %v, want %v", c.name, SecurityPackageLookupOn(&p), c.on)
		}
	}
	if SecurityPackageLookupOn(nil) {
		t.Error("no body must read off")
	}
}

// TestSecurityPackageLookupNeedsSuperAdmin: turning the lookup on, and
// sending private names, are switches only the org's super admin writes.
func TestSecurityPackageLookupNeedsSuperAdmin(t *testing.T) {
	why := SecurityManagedPolicyEnables(SecurityManagedPolicyV1{Version: 1, PackageLookup: "org_mirror", PackageLookupPrivate: "send"})
	if !slices.Contains(why, "switches on the package lookup through the org mirror") || !slices.Contains(why, "looks private package names up too") {
		t.Fatalf("enables: %v", why)
	}
	if why := SecurityManagedPolicyEnables(SecurityManagedPolicyV1{Version: 1, PackageLookup: "off", PackageLookupPrivate: "send"}); len(why) != 0 {
		t.Fatalf("off enables nothing: %v", why)
	}
}

// TestComposeSecurityServedStripsPackageLookup: a caller that does not name
// the capability token (an older node, whose closed decoder would refuse
// the whole body) is served the body without the package lookup fields;
// one that names it gets them; a body without them stays byte for byte.
func TestComposeSecurityServedStripsPackageLookup(t *testing.T) {
	body, err := CanonicalSecurityManagedPolicy(SecurityManagedPolicyV1{
		Version: 1, Components: []string{"security.deps"}, PackageLookup: "org_mirror", PackageLookupKinds: []string{"language"},
	})
	if err != nil {
		t.Fatal(err)
	}
	old, err := ComposeSecurityServed(body, nil, SecurityServedInput{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(old), "package_lookup") {
		t.Fatalf("an older node is served the lookup fields: %s", old)
	}
	p, ok, err := DecodeSecurityManagedPolicy(old)
	if err != nil || !ok || !slices.Contains(p.Components, "security.deps") {
		t.Fatalf("the stripped body lost the rest: %s %v", old, err)
	}
	cur, err := ComposeSecurityServed(body, []string{SecurityCapabilityPackageLookup}, SecurityServedInput{})
	if err != nil || string(cur) != string(body) {
		t.Fatalf("a capable node gets the authored body: %s %v", cur, err)
	}
	plain, _ := CanonicalSecurityManagedPolicy(SecurityManagedPolicyV1{Version: 1, Components: []string{"security.deps"}})
	if same, _ := ComposeSecurityServed(plain, nil, SecurityServedInput{}); string(same) != string(plain) {
		t.Fatalf("a body without the fields changed: %s", same)
	}
}
