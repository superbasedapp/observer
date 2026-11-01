package govern_test

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestTenancyNamesMirrorOrgcontract keeps govern's hand copy of the tenancy
// class names equal to the contract's, which the store and the wire use.
func TestTenancyNamesMirrorOrgcontract(t *testing.T) {
	if govern.TenancyIndividual != orgcontract.TenancyIndividual || govern.TenancyManaged != orgcontract.TenancyManaged {
		t.Fatalf("govern tenancy names %q/%q drifted from orgcontract %q/%q",
			govern.TenancyIndividual, govern.TenancyManaged, orgcontract.TenancyIndividual, orgcontract.TenancyManaged)
	}
}
