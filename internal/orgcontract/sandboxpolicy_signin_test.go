package orgcontract

import "testing"

// TestSandboxSignInSeedForbidField (lane BOXSIGNIN): the org's sign-in
// seeding forbid rides the closed body as one optional boolean, is served
// only to a caller that advertised the capability (an older node, whose
// closed decoder would refuse the whole body for it, is served no field),
// and an older body without it decodes as before.
func TestSandboxSignInSeedForbidField(t *testing.T) {
	t.Parallel()
	p, err := DecodeSandboxManagedPolicy([]byte(`{"schema":"sbo-sandbox-managed-v1","sign_in_seed_forbidden":true}`))
	if err != nil || p.SignInSeedForbidden == nil || !*p.SignInSeedForbidden {
		t.Fatalf("decode = %+v %v", p, err)
	}
	if _, err := DecodeSandboxManagedPolicy([]byte(`{"schema":"sbo-sandbox-managed-v1","sign_in_seed_forbidden":"yes"}`)); err == nil {
		t.Error("accepted a non-boolean forbid")
	}
	if got := SandboxSignInSeedForCaller(p, []string{SandboxCapabilityE2BEndpoint}); got.SignInSeedForbidden != nil {
		t.Fatal("served sign_in_seed_forbidden to a caller that did not advertise it")
	}
	if got := SandboxSignInSeedForCaller(p, []string{SandboxCapabilitySignInSeedForbid}); got.SignInSeedForbidden == nil {
		t.Fatal("withheld sign_in_seed_forbidden from a caller that advertised it")
	}
	if q, err := DecodeSandboxManagedPolicy([]byte(`{"schema":"sbo-sandbox-managed-v1","enabled":true}`)); err != nil || q.SignInSeedForbidden != nil {
		t.Fatalf("an older body: %+v %v", q, err)
	}
}
