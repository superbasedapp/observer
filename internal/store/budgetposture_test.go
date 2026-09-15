package store

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestComposeBudgetPostureIsSeamOnly pins the three states of the seam: no
// provider (a build without the feature), a provider reporting nothing, and a
// provider reporting a row.
func TestComposeBudgetPostureIsSeamOnly(t *testing.T) {
	t.Parallel()

	s := &Store{}
	if got := s.composeBudgetPosture(); got != nil {
		t.Errorf("with no provider: got %+v, want nil — a pre-feature node's envelope must stay byte-identical", got)
	}

	s.SetBudgetPostureProvider(func() (orgcontract.BudgetPostureRow, bool) {
		return orgcontract.BudgetPostureRow{}, false
	})
	if got := s.composeBudgetPosture(); got != nil {
		t.Errorf("with a provider reporting nothing: got %+v, want nil", got)
	}

	want := orgcontract.BudgetPostureRow{
		EnforcementPoint: orgcontract.BudgetPointGuard,
		Mode:             "enforce",
		Source:           orgcontract.BudgetSourceOrgLowered,
		FetchState:       orgcontract.BudgetFetchOK,
		FromOrg:          true, LastFetchOK: true, Hard: true, Capped: true,
		Coverage: orgcontract.BudgetCoverageProxyOnly,
	}
	s.SetBudgetPostureProvider(func() (orgcontract.BudgetPostureRow, bool) { return want, true })
	got := s.composeBudgetPosture()
	if got == nil || !reflect.DeepEqual(*got, want) {
		t.Errorf("composeBudgetPosture() = %+v, want %+v", got, want)
	}
}
