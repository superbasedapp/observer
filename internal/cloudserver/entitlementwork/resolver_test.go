package entitlementwork_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// fakeOwnerStore is the OwnerStore fake (the real one is the 0093 lookups,
// tested on PostgreSQL in internal/cloudserver/store).
type fakeOwnerStore struct {
	sub, hint       string
	subErr, hintErr error
}

func (f fakeOwnerStore) OrgCreateOwnerSub(context.Context, string) (string, error) {
	if f.subErr != nil {
		return "", f.subErr
	}
	return f.sub, nil
}

func (f fakeOwnerStore) OrgCreateOwnerEmailHint(context.Context, string) (string, error) {
	if f.hintErr != nil {
		return "", f.hintErr
	}
	return f.hint, nil
}

func reasonOf(err error) string {
	var re *hostclient.ResolveError
	if errors.As(err, &re) {
		return re.Reason
	}
	return ""
}

// TestStoreOwners: the subject binds the owner; with a store that offers only
// the 0093 hint, the address is a hint marked unverified; each missing piece
// is a typed refusal; any other failure is an untyped error (retried as
// "not_sent:resolve").
func TestStoreOwners(t *testing.T) {
	t.Parallel()
	notFound := fmt.Errorf("wrapped: %w", store.ErrNotFound)
	cases := []struct {
		name   string
		st     fakeOwnerStore
		want   entitlementwork.Owner
		reason string
		err    bool
	}{
		{name: "both", st: fakeOwnerStore{sub: "user_01", hint: "o@example.test"}, want: entitlementwork.Owner{Sub: "user_01", Email: "o@example.test"}},
		{name: "no subject", st: fakeOwnerStore{subErr: notFound, hint: "o@example.test"}, reason: entitlementwork.ReasonOwnerIdentityUnavailable, err: true},
		{name: "no address", st: fakeOwnerStore{sub: "user_01", hintErr: notFound}, reason: entitlementwork.ReasonOwnerEmailHintUnavailable, err: true},
		{name: "subject read fails", st: fakeOwnerStore{subErr: errors.New("conn reset")}, err: true},
		{name: "address read fails", st: fakeOwnerStore{sub: "user_01", hintErr: errors.New("conn reset")}, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := entitlementwork.StoreOwners{Store: tc.st}.Owner(context.Background(), orgA)
			if tc.err != (err != nil) || reasonOf(err) != tc.reason || got != tc.want {
				t.Fatalf("Owner = %+v, %v (reason %q); want %+v reason %q err %v", got, err, reasonOf(err), tc.want, tc.reason, tc.err)
			}
			if got.EmailVerified {
				t.Fatal("a hint-only store vouched for an address")
			}
		})
	}
	if _, err := (entitlementwork.StoreOwners{}).Owner(context.Background(), orgA); err == nil {
		t.Fatal("a source with no store answered")
	}
}

// fakeAddressStore also offers the one-statement address read (cloud 0096).
type fakeAddressStore struct {
	fakeOwnerStore
	addr    store.OrgCreateOwnerAddress
	addrErr error
}

func (f fakeAddressStore) OrgCreateOwnerAddress(context.Context, string) (store.OrgCreateOwnerAddress, error) {
	return f.addr, f.addrErr
}

// TestStoreOwnersVerifiedAddress (C2.tenant-cloud-2): the address is sent as
// verified exactly when WorkOS verified it; the subject still binds; a
// missing address is still the typed refusal; the hint read is not used.
func TestStoreOwnersVerifiedAddress(t *testing.T) {
	t.Parallel()
	notFound := fmt.Errorf("wrapped: %w", store.ErrNotFound)
	base := fakeOwnerStore{sub: "user_01", hintErr: errors.New("the hint read must not be used")}
	cases := []struct {
		name   string
		st     fakeAddressStore
		want   entitlementwork.Owner
		reason string
		err    bool
	}{
		{
			name: "verified", st: fakeAddressStore{fakeOwnerStore: base, addr: store.OrgCreateOwnerAddress{Hint: "o@example.test", Verified: true}},
			want: entitlementwork.Owner{Sub: "user_01", Email: "o@example.test", EmailVerified: true},
		},
		{
			name: "not verified", st: fakeAddressStore{fakeOwnerStore: base, addr: store.OrgCreateOwnerAddress{Hint: "o@example.test"}},
			want: entitlementwork.Owner{Sub: "user_01", Email: "o@example.test"},
		},
		{name: "no address", st: fakeAddressStore{fakeOwnerStore: base, addrErr: notFound}, reason: entitlementwork.ReasonOwnerEmailHintUnavailable, err: true},
		{name: "address read fails", st: fakeAddressStore{fakeOwnerStore: base, addrErr: errors.New("conn reset")}, err: true},
		{
			name: "no subject wins first", st: fakeAddressStore{fakeOwnerStore: fakeOwnerStore{subErr: notFound}, addr: store.OrgCreateOwnerAddress{Hint: "o@example.test", Verified: true}},
			reason: entitlementwork.ReasonOwnerIdentityUnavailable, err: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := entitlementwork.StoreOwners{Store: tc.st}.Owner(context.Background(), orgA)
			if tc.err != (err != nil) || reasonOf(err) != tc.reason || got != tc.want {
				t.Fatalf("Owner = %+v, %v (reason %q); want %+v reason %q err %v", got, err, reasonOf(err), tc.want, tc.reason, tc.err)
			}
		})
	}
}

type fakeFacts struct {
	f   store.OrgCreateFacts
	err error
}

func (f fakeFacts) OrgCreateFacts(context.Context, string) (store.OrgCreateFacts, error) {
	return f.f, f.err
}

// TestCreateResolverCarriesSlugKindAndHint: the create extras carry the
// org's current slug and its kind on the wire, the owner's subject and the
// unverified hint; a missing org row is a typed refusal.
func TestCreateResolverCarriesSlugKindAndHint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := testNow
	st := newStore(team(orgA, "provisioning"))
	if _, err := newIssuer(t, st, newMemSigner(entKey), keySet(entKey), nil, &now).IssueOnce(ctx); err != nil {
		t.Fatal(err)
	}
	owners := entitlementwork.StoreOwners{Store: fakeOwnerStore{sub: "user_01", hint: "o@example.test"}}
	cases := []struct {
		name     string
		facts    fakeFacts
		slug     string
		kind     pc.OrgKind
		reason   string
		wantFail bool
	}{
		{name: "team", facts: fakeFacts{f: store.OrgCreateFacts{Slug: "acme", Kind: store.OrgTeam}}, slug: "acme", kind: pc.OrgKindTeam},
		{name: "personal", facts: fakeFacts{f: store.OrgCreateFacts{Slug: "u-abcdefgh", Kind: store.OrgPersonal}}, slug: "u-abcdefgh", kind: pc.OrgKindPersonal},
		{name: "org gone", facts: fakeFacts{err: fmt.Errorf("x: %w", store.ErrNotFound)}, reason: entitlementwork.ReasonOrgUnavailable, wantFail: true},
		{name: "unknown kind", facts: fakeFacts{f: store.OrgCreateFacts{Slug: "acme", Kind: "dedicated"}}, reason: entitlementwork.ReasonOrgUnavailable, wantFail: true},
		{name: "read fails", facts: fakeFacts{err: errors.New("conn reset")}, wantFail: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := entitlementwork.CreateResolver{Docs: st, Owners: owners, Facts: tc.facts}
			x, err := r.ResolveCreate(ctx, orgA)
			if tc.wantFail {
				if err == nil || reasonOf(err) != tc.reason {
					t.Fatalf("err = %v (reason %q), want reason %q", err, reasonOf(err), tc.reason)
				}
				return
			}
			if err != nil || x.Slug != tc.slug || x.Kind != tc.kind || x.OwnerSub != "user_01" ||
				x.OwnerEmail != "o@example.test" || x.OwnerEmailVerified || x.Entitlements.Version != now.Unix() {
				t.Fatalf("extras = %+v, %v", x, err)
			}
		})
	}
}
