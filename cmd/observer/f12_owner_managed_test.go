package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestF12GrantFromStoreCarriesOwnerManaged: the cmd boundary fills
// govern.Grant.OwnerManaged from the stored enrolment.
func TestF12GrantFromStoreCarriesOwnerManaged(t *testing.T) {
	for _, tc := range []struct {
		name string
		enr  *store.Enrolment
		want bool
	}{
		{"no enrolment", nil, false},
		{"team enrolment", &store.Enrolment{OrgID: "o", Tenancy: "managed"}, false},
		{"owner-managed enrolment", &store.Enrolment{OrgID: "o", Tenancy: "managed", OwnerManaged: true}, true},
	} {
		if got := grantFromStore(store.EnrolmentGrant{OrgID: "o"}, tc.enr).OwnerManaged; got != tc.want {
			t.Errorf("%s: OwnerManaged = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestF12PrintGrantOfferListsManagedDefaults: the CLI consent screen prints
// the managed-default summary and lines on a managed offer only.
func TestF12PrintGrantOfferListsManagedDefaults(t *testing.T) {
	var buf bytes.Buffer
	managed := testGrantOffer(t, true, []string{govern.AuthorityDashboardVisibility})
	printGrantOffer(&buf, managed)
	if !strings.Contains(buf.String(), "Accepting makes ") || !strings.Contains(buf.String(), "Hidden pages: ") || !strings.Contains(buf.String(), "App Traces") {
		t.Fatalf("managed offer: no managed-default lines:\n%s", buf.String())
	}
	buf.Reset()
	owner := testGrantOffer(t, true, []string{govern.AuthorityDashboardVisibility})
	owner.OwnerManaged = true
	printGrantOffer(&buf, owner)
	if !strings.Contains(buf.String(), "Hidden pages: Security") || strings.Contains(buf.String(), "App Traces") ||
		!strings.Contains(buf.String(), "both the admin and the developer") {
		t.Fatalf("owner-managed offer: wrong managed-default lines:\n%s", buf.String())
	}
	buf.Reset()
	printGrantOffer(&buf, testGrantOffer(t, false, []string{govern.AuthorityDashboardVisibility}))
	if strings.Contains(buf.String(), "Hidden pages: ") {
		t.Fatalf("individual offer lists managed defaults:\n%s", buf.String())
	}
}
