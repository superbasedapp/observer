package dashapi

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// RequestService is the subset of *orgclient.Client the Requests endpoints
// need. Nil on a solo node: the page then explains that requests go to an
// organization and shows the enrolment link.
type RequestService interface {
	Status(ctx context.Context) (orgclient.EnrolmentState, error)
	ListMyOrgRequests(ctx context.Context) ([]orgclient.OrgRequest, error)
	PrepareAccessRequest(ctx context.Context, in orgcontract.AccessRequestCreate, optInExcerpt bool) (orgcontract.AccessRequestCreate, error)
	SendOrQueueAccessRequest(ctx context.Context, prepared orgcontract.AccessRequestCreate) (orgclient.OrgRequest, int64, error)
	WithdrawOrgRequest(ctx context.Context, id int64) error
	AccessGrantsView(ctx context.Context) (store.AccessGrantsView, bool, error)
	QueuedAccessRequests(ctx context.Context) ([]store.OutboxRequest, error)
	CancelQueuedAccessRequest(ctx context.Context, id int64) (bool, error)
	RequestContextShipsRaw(ctx context.Context) bool
	// AlreadyGranted reports the grant in force on this machine that
	// already gives everything the validated request asks for, so the form
	// says "G-11 already covers this" instead of sending a request that
	// would change nothing.
	AlreadyGranted(ctx context.Context, n accessgrant.Normalized) (accessgrant.Held, bool)
	// RequestableBudgets lists the budgets the node's verified budget rail
	// names, for the budget picker on a budget-increase request (T-523).
	RequestableBudgets() []orgclient.RequestableBudget
}
