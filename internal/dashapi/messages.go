package dashapi

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// MessageService is the subset of *orgclient.Client the Messages endpoints
// (/api/messages*, admin and developer messaging, T-854) need for the acts
// that reach the org: sending, retrying, read and acknowledge marks (which
// queue receipts) and discarding an unsent post. The reads (threads,
// summary, rail status) come straight from the node-local store. Nil on a
// solo node: the page then says messages come from an organization.
type MessageService interface {
	Status(ctx context.Context) (orgclient.EnrolmentState, error)
	SendOrgMessage(ctx context.Context, d orgclient.OrgMessageDraft) (store.OrgMessageOutboxItem, error)
	RetryOrgMessage(ctx context.Context, id string) (store.OrgMessageOutboxItem, error)
	DiscardOrgMessage(ctx context.Context, id string) (bool, error)
	MarkOrgMessageThreadRead(ctx context.Context, threadID string) (int, error)
	AckOrgMessage(ctx context.Context, id int64) (store.OrgInboxMessage, error)
	// OrgMessageReadReceiptsOn reports whether the org sees when the
	// developer reads a message (always on a managed enrolment).
	OrgMessageReadReceiptsOn(ctx context.Context) bool
	// NoteActivity tells the org client someone is waiting on the org: its
	// policy-version probe then runs soon, and an answer retries a stalled
	// message rail at once (orgclient retryStalledOrgMessages). Non-blocking.
	NoteActivity()
}
